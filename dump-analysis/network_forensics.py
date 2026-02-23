"""
network_forensics.py
====================
Анализ сетевого дампа (.pcapng или JSON-экспорт из Wireshark).

Использование:
    python network_forensics.py --pcap dhcp.pcapng   # требует tshark
    python network_forensics.py --json dump.json      # JSON-экспорт из Wireshark
"""

import argparse
import json
import os
import subprocess
import sys
from collections import Counter
from datetime import datetime

import matplotlib.pyplot as plt
import pandas as pd

# Типы DHCP-сообщений
DHCP_MSG_TYPES = {
    "1": "DISCOVER", "2": "OFFER", "3": "REQUEST",
    "4": "DECLINE",  "5": "ACK",   "6": "NAK",
    "7": "RELEASE",  "8": "INFORM",
}

# ── загрузка данных ──

def find_tshark():
    """Ищет tshark в PATH и стандартных путях Windows."""
    import shutil
    # сначала пробуем PATH
    if shutil.which("tshark"):
        return "tshark"
    # стандартные пути Windows
    windows_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ]
    for path in windows_paths:
        if os.path.isfile(path):
            return path
    return None

def load_via_tshark(pcap_path):
    """Конвертирует .pcapng в JSON через tshark и возвращает список пакетов."""
    tshark = find_tshark()
    if not tshark:
        print("[!] tshark не найден. Установите Wireshark или используйте --json.")
        return []
    print(f"[*] Запуск tshark: {pcap_path}  (бинарник: {tshark})")
    cmd = [tshark, "-r", pcap_path, "-T", "json", "--no-duplicate-keys"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            print(f"[!] Ошибка tshark:\n{result.stderr[:300]}")
            return []
        return json.loads(result.stdout)
    except Exception as e:
        print(f"[!] Ошибка запуска tshark: {e}")
        return []

def load_json(json_path):
    """Загружает JSON-экспорт из Wireshark (File -> Export Packet Dissections -> JSON).
    Автоматически определяет кодировку: UTF-8 или UTF-16 (Windows Wireshark)."""
    print(f"[*] Загрузка JSON: {json_path}")
    # определяем кодировку по BOM-байтам
    with open(json_path, "rb") as f:
        bom = f.read(2)
    encoding = "utf-16" if bom in (b"\xff\xfe", b"\xfe\xff") else "utf-8"
    print(f"[*] Кодировка файла: {encoding}")
    with open(json_path, encoding=encoding) as f:
        return json.load(f)

# ── разбор пакетов ──

def parse_packets(raw_packets):
    """
    Извлекает из сырых пакетов:
      - общую статистику
      - DHCP-события
      - DNS-события
    """
    packets = []
    dhcp_events = []
    dns_events = []
    proto_counter = Counter()
    ip_src_counter = Counter()
    ip_dst_counter = Counter()

    for raw in raw_packets:
        layers = raw.get("_source", {}).get("layers", {})
        frame = layers.get("frame", {})
        ip    = layers.get("ip", {})
        dhcp  = layers.get("dhcp", {})
        dns   = layers.get("dns", {})

        # базовые поля пакета
        ts_raw = frame.get("frame.time_epoch") or frame.get("frame.time", "")
        try:
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        except Exception:
            ts = None

        src_ip = ip.get("ip.src", "")
        dst_ip = ip.get("ip.dst", "")
        protocols = frame.get("frame.protocols", "")
        length = int(frame.get("frame.len", 0))

        if src_ip:
            ip_src_counter[src_ip] += 1
        if dst_ip:
            ip_dst_counter[dst_ip] += 1
        for proto in protocols.split(":"):
            proto_counter[proto.upper()] += 1

        packets.append({
            "ts": ts,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocols": protocols,
            "length": length,
        })

        # DHCP
        if dhcp:
            msg_code = dhcp.get("dhcp.option.dhcp", dhcp.get("dhcp.type", "?"))
            dhcp_events.append({
                "ts":         ts,
                "msg_type":   DHCP_MSG_TYPES.get(str(msg_code), f"UNKNOWN({msg_code})"),
                "mac":        dhcp.get("dhcp.hw.mac_addr", ""),
                "offered_ip": dhcp.get("dhcp.ip.your", "0.0.0.0"),
                "server_id":  dhcp.get("dhcp.option.dhcp_server_id", ""),
                "hostname":   dhcp.get("dhcp.option.hostname", ""),
                "src_ip":     src_ip,
                "dst_ip":     dst_ip,
            })

        # DNS
        if dns:
            flags_str = dns.get("dns.flags", "0x0000")
            try:
                is_response = bool(int(flags_str, 16) & 0x8000)
            except (ValueError, TypeError):
                is_response = False

            dns_events.append({
                "ts":          ts,
                "domain":      dns.get("dns.qry.name") or dns.get("dns.resp.name", ""),
                "is_response": is_response,
                "rcode":       dns.get("dns.flags.rcode", "0"),
                "src_ip":      src_ip,
                "dst_ip":      dst_ip,
            })

    return {
        "packets":        packets,
        "dhcp":           dhcp_events,
        "dns":            dns_events,
        "proto_counter":  proto_counter,
        "ip_src_counter": ip_src_counter,
        "ip_dst_counter": ip_dst_counter,
    }

# ── подозрительные IP ─────────────────────────────────────────────────────────

def find_suspicious_ips(ip_src_counter, ip_dst_counter):
    """Возвращает список подозрительных IP с пояснениями."""
    found = []
    all_ips = set(ip_src_counter) | set(ip_dst_counter)
    for ip in all_ips:
        if ip == "0.0.0.0":
            found.append((ip, "Нулевой адрес источника (клиент без IP)"))
        elif ip == "255.255.255.255":
            found.append((ip, "Широковещательный адрес (broadcast)"))
        elif ip.startswith("169.254."):
            found.append((ip, "APIPA-адрес (клиент не получил IP от DHCP)"))
    return found

# ── отчёт в консоль ──

def print_report(data, name):
    sep = "-" * 60
    pkts = data["packets"]

    print(f"\n{'=' * 60}")
    print(f"  ОТЧЕТ по дампу: {name}")
    print(f"{'=' * 60}")

    # 1. Общая статистика
    print("\n[1] ОБЩАЯ СТАТИСТИКА")
    print(sep)
    timestamps = [p["ts"] for p in pkts if p["ts"]]
    first_ts = min(timestamps) if timestamps else None
    last_ts  = max(timestamps) if timestamps else None
    duration = (last_ts - first_ts).total_seconds() if first_ts and last_ts else 0
    total_bytes = sum(p["length"] for p in pkts)

    print(f"  Всего пакетов : {len(pkts)}")
    print(f"  Общий объём   : {total_bytes} байт ({total_bytes / 1024:.1f} КБ)")
    if first_ts:
        print(f"  Начало захвата: {first_ts.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"  Конец захвата : {last_ts.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"  Длительность  : {duration:.3f} сек")

    # 2. Протоколы
    print("\n[2] ПРОТОКОЛЫ")
    print(sep)
    for proto, cnt in data["proto_counter"].most_common(10):
        print(f"  {proto:<12} {cnt} пакетов")

    # 3. Топ IP
    print("\n[3] ТОП IP-АДРЕСОВ")
    print(sep)
    print("  Источники:")
    for ip, cnt in data["ip_src_counter"].most_common(10):
        print(f"    {ip:<22} {cnt} пакетов")
    print("  Назначения:")
    for ip, cnt in data["ip_dst_counter"].most_common(10):
        print(f"    {ip:<22} {cnt} пакетов")

    # 4. DHCP
    dhcp = data["dhcp"]
    print("\n[4] DHCP")
    print(sep)
    if not dhcp:
        print("  DHCP-трафик не обнаружен.")
    else:
        msg_counts = Counter(e["msg_type"] for e in dhcp)
        print(f"  Всего DHCP-пакетов: {len(dhcp)}")
        print("  Типы сообщений:")
        for mt, cnt in sorted(msg_counts.items()):
            print(f"    {mt:<12} {cnt}")

        macs = set(e["mac"] for e in dhcp if e["mac"])
        print(f"\n  Уникальных клиентов (MAC): {len(macs)}")
        for mac in macs:
            offered = next(
                (e["offered_ip"] for e in dhcp
                 if e["mac"] == mac and e["offered_ip"] not in ("0.0.0.0", "")), "—"
            )
            hostname = next(
                (e["hostname"] for e in dhcp if e["mac"] == mac and e["hostname"]), "—"
            )
            print(f"    MAC: {mac}  ->  IP: {offered}  (hostname: {hostname})")

        servers = set(e["server_id"] for e in dhcp if e["server_id"])
        if servers:
            print(f"\n  DHCP-серверы: {', '.join(servers)}")

        discovers = msg_counts.get("DISCOVER", 0)
        acks      = msg_counts.get("ACK", 0)
        naks      = msg_counts.get("NAK", 0)
        if discovers > 0 and acks == 0:
            print("\n  [!] Есть DISCOVER, но нет ACK — полный handshake не захвачен")
        if naks > 0:
            print(f"\n  [!] {naks} NAK-ответа — сервер отклонил запросы")

    # 5. DNS
    dns = data["dns"]
    print("\n[5] DNS")
    print(sep)
    if not dns:
        print("  DNS-трафик не обнаружен.")
    else:
        queries   = [e for e in dns if not e["is_response"]]
        responses = [e for e in dns if e["is_response"]]
        print(f"  Всего DNS-пакетов: {len(dns)}  (запросов: {len(queries)}, ответов: {len(responses)})")

        domains = Counter(e["domain"] for e in queries if e["domain"])
        print("\n  Топ запрашиваемых доменов:")
        for domain, cnt in domains.most_common(10):
            print(f"    {domain:<40} {cnt} раз")

        errors = [e for e in responses if str(e["rcode"]) not in ("0", "")]
        if errors:
            print(f"\n  [!] DNS-ошибки (rcode != 0): {len(errors)} ответов")

    # 6. Подозрительные IP
    suspicious = find_suspicious_ips(data["ip_src_counter"], data["ip_dst_counter"])
    print("\n[6] ПОДОЗРИТЕЛЬНЫЕ IP-АДРЕСА")
    print(sep)
    if not suspicious:
        print("  Подозрительных адресов не найдено.")
    else:
        for ip, reason in suspicious:
            print(f"  [!] {ip:<22} — {reason}")

    print(f"\n{'=' * 60}\n")

# ── визуализация ──

def _barh(ax, labels, vals, color, title, xlabel):
    """Вспомогательная функция: горизонтальный бар-чарт с подписями."""
    bars = ax.barh(labels[::-1], vals[::-1], color=color)
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    for bar, val in zip(bars, vals[::-1]):
        ax.text(bar.get_width() + 0.02, bar.get_y() + bar.get_height() / 2,
                str(val), va="center", fontsize=8)


def _no_data(ax, title, reason="Нет данных"):
    ax.text(0.5, 0.5, reason, ha="center", va="center", fontsize=11, color="gray")
    ax.set_title(title)
    ax.axis("off")


def visualize(data, output_path):
    dhcp = data["dhcp"]
    dns  = data["dns"]

    fig, axes = plt.subplots(2, 3, figsize=(16, 10))
    fig.suptitle("Анализ сетевого трафика", fontsize=14, fontweight="bold")

    # ── строка 1 ──

    # [0,0] протоколы (прикладной уровень)
    ax = axes[0, 0]
    skip = {"ETH", "ETHERTYPE", "IP", "UDP", "TCP", "FRAME"}
    app_protos = {p: c for p, c in data["proto_counter"].items() if p not in skip}
    if not app_protos:
        app_protos = dict(data["proto_counter"].most_common(6))
    labels, sizes = zip(*sorted(app_protos.items(), key=lambda x: -x[1]))
    ax.pie(sizes, labels=labels, autopct="%1.0f%%", startangle=90)
    ax.set_title("Протоколы")

    # [0,1] DHCP: типы сообщений
    ax = axes[0, 1]
    if dhcp:
        msg_counts = Counter(e["msg_type"] for e in dhcp)
        ax.bar(list(msg_counts.keys()), list(msg_counts.values()), color="#4C72B0")
        ax.set_title("DHCP: типы сообщений")
        ax.set_ylabel("Количество")
        for i, (k, v) in enumerate(msg_counts.items()):
            ax.text(i, v + 0.05, str(v), ha="center")
    else:
        _no_data(axes[0, 1], "DHCP: типы сообщений", "DHCP не обнаружен")

    # [0,2] DNS: топ запрашиваемых доменов
    ax = axes[0, 2]
    queries = [e for e in dns if not e["is_response"] and e["domain"]]
    if queries:
        top = Counter(e["domain"] for e in queries).most_common(8)
        dom_labels = [d[:30] + "…" if len(d) > 30 else d for d, _ in top]
        dom_vals   = [v for _, v in top]
        _barh(ax, dom_labels, dom_vals, "#55A868", "DNS: топ запрашиваемых доменов", "Количество")
    else:
        _no_data(ax, "DNS: топ запрашиваемых доменов", "DNS не обнаружен")

    # ── строка 2 ──

    # [1,0] DHCP: топ клиентов по числу запросов (DISCOVER / REQUEST / INFORM)
    ax = axes[1, 0]
    if dhcp:
        client_req = Counter(
            e["mac"] for e in dhcp
            if e["mac"] and e["msg_type"] in ("DISCOVER", "REQUEST", "INFORM")
        )
        if client_req:
            top = client_req.most_common(8)
            mac_labels = [m[-8:] for m, _ in top]
            mac_vals   = [v for _, v in top]
            _barh(ax, mac_labels, mac_vals, "#E07B39",
                  "DHCP: топ клиентов (запросы)", "Количество пакетов")
        else:
            _no_data(ax, "DHCP: топ клиентов (запросы)")
    else:
        _no_data(ax, "DHCP: топ клиентов (запросы)", "DHCP не обнаружен")

    # [1,1] DHCP: топ серверов по числу ответов (OFFER / ACK / NAK)
    ax = axes[1, 1]
    if dhcp:
        server_resp = Counter(
            e["src_ip"] for e in dhcp
            if e["src_ip"] and e["msg_type"] in ("OFFER", "ACK", "NAK")
        )
        if server_resp:
            top = server_resp.most_common(8)
            _barh(ax, [ip for ip, _ in top], [v for _, v in top],
                  "#C44E52", "DHCP: топ серверов (ответы)", "Количество пакетов")
        else:
            _no_data(ax, "DHCP: топ серверов (ответы)")
    else:
        _no_data(ax, "DHCP: топ серверов (ответы)", "DHCP не обнаружен")

    # [1,2] DNS: топ клиентов по числу запросов
    ax = axes[1, 2]
    if dns:
        dns_clients = Counter(
            e["src_ip"] for e in dns if not e["is_response"] and e["src_ip"]
        )
        if dns_clients:
            top = dns_clients.most_common(8)
            _barh(ax, [ip for ip, _ in top], [v for _, v in top],
                  "#8172B2", "DNS: топ клиентов (запросы)", "Количество запросов")
        else:
            _no_data(ax, "DNS: топ клиентов (запросы)")
    else:
        _no_data(ax, "DNS: топ клиентов (запросы)", "DNS не обнаружен")

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    print(f"[+] Визуализация: {output_path}")

# ── экспорт CSV ──

def export_csv(data, base_path):
    # все пакеты
    df = pd.DataFrame([{
        "timestamp":    p["ts"].isoformat() if p["ts"] else "",
        "src_ip":       p["src_ip"],
        "dst_ip":       p["dst_ip"],
        "protocols":    p["protocols"],
        "length_bytes": p["length"],
    } for p in data["packets"]])
    path = base_path + "_packets.csv"
    df.to_csv(path, index=False, encoding="utf-8")
    print(f"[+] Пакеты CSV : {path}")

    # DHCP
    if data["dhcp"]:
        df_dhcp = pd.DataFrame([{
            "timestamp":  e["ts"].isoformat() if e["ts"] else "",
            "msg_type":   e["msg_type"],
            "mac":        e["mac"],
            "offered_ip": e["offered_ip"],
            "server_id":  e["server_id"],
            "hostname":   e["hostname"],
        } for e in data["dhcp"]])
        path = base_path + "_dhcp.csv"
        df_dhcp.to_csv(path, index=False, encoding="utf-8")
        print(f"[+] DHCP CSV   : {path}")

    # DNS
    if data["dns"]:
        df_dns = pd.DataFrame([{
            "timestamp":   e["ts"].isoformat() if e["ts"] else "",
            "domain":      e["domain"],
            "is_response": e["is_response"],
            "rcode":       e["rcode"],
            "src_ip":      e["src_ip"],
            "dst_ip":      e["dst_ip"],
        } for e in data["dns"]])
        path = base_path + "_dns.csv"
        df_dns.to_csv(path, index=False, encoding="utf-8")
        print(f"[+] DNS CSV    : {path}")

# ── main ──

def main():
    parser = argparse.ArgumentParser(description="Форензика сетевого трафика")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pcap", metavar="FILE.pcapng", help="Путь к pcapng (нужен tshark)")
    group.add_argument("--json", metavar="FILE.json",   help="JSON-экспорт из Wireshark")
    parser.add_argument("--out", metavar="DIR", default=".", help="Папка для результатов")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)

    if args.pcap:
        raw = load_via_tshark(args.pcap)
        name = os.path.splitext(os.path.basename(args.pcap))[0]
    else:
        raw = load_json(args.json)
        name = os.path.splitext(os.path.basename(args.json))[0]

    if not raw:
        print("[!] Данные не загружены.")
        sys.exit(1)

    print(f"[*] Загружено пакетов: {len(raw)}")

    data = parse_packets(raw)
    print_report(data, name)
    visualize(data, os.path.join(args.out, name + "_analysis.png"))
    export_csv(data, os.path.join(args.out, name))

    print(f"\n[+] Готово. Результаты в: {os.path.abspath(args.out)}")

if __name__ == "__main__":
    main()