import json
import os

import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.gridspec as gridspec
import seaborn as sns

import warnings
warnings.filterwarnings("ignore")


# ── Справочник подозрительных EventCode ──────────────────────

SUSPICIOUS_EVENTS = {
    "4703": ("Изменение привилегий токена",  "Высокий",
             "Эскалация привилегий — массовое изменение прав"),
    "4688": ("Создание процесса",            "Средний",
             "Запуск нового процесса — возможен вредоносный запуск"),
    "4624": ("Успешный вход (сетевой)",      "Средний",
             "Kerberos + делегирование через сеть — lateral movement"),
    "4656": ("Запрос дескриптора объекта",   "Средний",
             "Доступ к системным каталогам"),
}

RISK_COLOR = {"Высокий": "#e74c3c", "Средний": "#f39c12", "Низкий": "#3498db"}

# Тёмная тема
C = {
    "bg":    "#181b2b",
    "panel": "#212540",
    "text":  "#e0e2f0",
    "muted": "#8a8fb5",
    "grid":  "#2d3157",
}


# ══════════════════════════════════════════════════════════════
#  Этап 1. Загрузка и подготовка данных
# ══════════════════════════════════════════════════════════════

def _last(val):
    """Если поле — список, берём последний элемент (целевая учётка)."""
    if isinstance(val, list):
        return val[-1] if val else "N/A"
    return val or "N/A"


def _proc(record):
    """Короткое имя процесса из полного пути."""
    raw = record.get("New_Process_Name") or record.get("Process_Name") or ""
    return raw.split("\\")[-1] if raw else ""


def load_data(path):
    """
    Читает botsv1.json → два датафрейма (WinEventLog и DNS).
    Нормализация: списки → скаляры, пути → имена процессов.
    """
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)

    win_rows, dns_rows = [], []

    for entry in raw:
        r = entry.get("result", {})
        code = str(r.get("EventCode", ""))

        if code == "DNS":
            dns_rows.append({
                "QueryName":    r.get("QueryName", ""),
                "ClientIP":     r.get("ClientIP", ""),
                "Host":         r.get("dvc", ""),
                "EventType":    str(r.get("eventtype", [])),
                "Time":         r.get("_time", ""),
            })
        else:
            win_rows.append({
                "EventCode":   code,
                "User":        _last(r.get("Account_Name")),
                "Host":        r.get("host", ""),
                "Process":     _proc(r),
                "LogonType":   r.get("Logon_Type", ""),
                "AuthPackage": r.get("Authentication_Package", ""),
                "ObjectName":  r.get("Object_Name", ""),
                "Accesses":    r.get("Accesses", ""),
                "Time":        r.get("_time", ""),
            })

    win_df = pd.DataFrame(win_rows)
    dns_df = pd.DataFrame(dns_rows)

    print(f"Загружено: {len(raw)} записей "
          f"(WinEventLog: {len(win_df)}, DNS: {len(dns_df)})")

    return win_df, dns_df, raw


# ══════════════════════════════════════════════════════════════
#  Этап 2. Анализ данных
# ══════════════════════════════════════════════════════════════

# --- WinEventLog ---

def analyze_winevent(df):
    """
    Анализ WinEventLog: помечаем подозрительные события по EventCode.
    Возвращает обогащённый df и таблицу агрегации.
    """
    df["Label"] = df["EventCode"].map(
        lambda c: SUSPICIOUS_EVENTS.get(c, ("Штатное событие",))[0])
    df["Risk"] = df["EventCode"].map(
        lambda c: SUSPICIOUS_EVENTS.get(c, ("", "Низкий"))[1])
    df["Reason"] = df["EventCode"].map(
        lambda c: SUSPICIOUS_EVENTS.get(c, ("", "", "—"))[2])
    df["IsSuspicious"] = df["EventCode"].isin(SUSPICIOUS_EVENTS)

    # агрегация
    counts = df.groupby("EventCode").size().reset_index(name="Count")
    hosts  = df.groupby("EventCode")["Host"].nunique().reset_index(name="Hosts")
    agg = counts.merge(hosts, on="EventCode")
    agg["Label"] = agg["EventCode"].map(
        lambda c: SUSPICIOUS_EVENTS.get(c, ("Штатное событие",))[0])
    agg["Risk"] = agg["EventCode"].map(
        lambda c: SUSPICIOUS_EVENTS.get(c, ("", "Низкий"))[1])
    agg["IsSuspicious"] = agg["EventCode"].isin(SUSPICIOUS_EVENTS)

    return df, agg.sort_values("Count", ascending=False)


# --- DNS ---

def classify_dns(row):
    """
    Классификация DNS-запроса:
      - по eventtype (suspicious / beaconing)
      - по имени домена (c2.*, malicious*)
      - длинные случайные домены (возможный DGA)
    """
    q  = str(row["QueryName"]).lower()
    et = str(row["EventType"]).lower()

    if "suspicious" in et or "beaconing" in et:
        return "Подозрительный", "Средний", "Помечен в eventtype как suspicious/beaconing"
    if "malicious" in q or "c2." in q:
        return "Вредоносный", "Высокий", "Имя домена содержит маркер C2/malicious"
    if len(q.replace(".", "")) > 20 and q.count(".") <= 2:
        return "DGA (возможно)", "Средний", "Длинное случайное имя — возможный DGA"
    return "Легитимный", "Низкий", ""


def analyze_dns(df):
    """Классифицирует DNS-запросы, возвращает (df, summary)."""
    if df.empty:
        for col in ("Category", "Risk", "Reason", "IsSuspicious"):
            df[col] = []
        return df, pd.DataFrame(columns=["Category", "Count"])

    results = df.apply(classify_dns, axis=1, result_type="expand")
    df["Category"], df["Risk"], df["Reason"] = results[0], results[1], results[2]
    df["IsSuspicious"] = df["Category"] != "Легитимный"

    summary = df.groupby("Category").size().reset_index(name="Count")
    return df, summary


# --- Объединённый топ-10 ---

def build_top10(win_df, dns_df):
    """
    Собирает единый список подозрительных событий из обоих источников.
    Каждое событие = строка с описанием + риск + источник.
    Возвращает DataFrame с топ-10 (по кол-ву и уровню риска).
    """
    rows = []
    risk_score = {"Высокий": 3, "Средний": 2, "Низкий": 1}

    # WinEventLog — подозрительные EventCode
    for code, (label, risk, reason) in SUSPICIOUS_EVENTS.items():
        subset = win_df[win_df["EventCode"] == code]
        if subset.empty:
            continue
        rows.append({
            "Event":   f"[Win] {code} — {label}",
            "Count":   len(subset),
            "Risk":    risk,
            "Score":   risk_score[risk],
            "Source":  "WinEventLog",
            "Detail":  reason,
        })

    # DNS — подозрительные запросы (каждый домен отдельно)
    if not dns_df.empty and "IsSuspicious" in dns_df.columns:
        for _, row in dns_df[dns_df["IsSuspicious"]].iterrows():
            rows.append({
                "Event":   f"[DNS] {row['Category']} — {row['QueryName']}",
                "Count":   1,
                "Risk":    row["Risk"],
                "Score":   risk_score.get(row["Risk"], 1),
                "Source":  "DNS",
                "Detail":  row["Reason"],
            })

    top = pd.DataFrame(rows)
    if top.empty:
        return top
    # сортируем: сначала по риску (desc), потом по количеству (desc)
    top = top.sort_values(["Score", "Count"], ascending=[False, False])
    return top.head(10).reset_index(drop=True)


# ══════════════════════════════════════════════════════════════
#  Консольный отчёт
# ══════════════════════════════════════════════════════════════

def print_report(win_df, win_agg, dns_df, dns_summary, top10):
    print("\n" + "=" * 60)
    print("  АНАЛИЗ WINEVENTLOG")
    print("=" * 60)
    print(win_agg[["EventCode", "Label", "Risk", "Count", "Hosts"]].to_string(index=False))

    susp_win = win_df[win_df["IsSuspicious"]]
    print(f"\nПодозрительных событий: {len(susp_win)} из {len(win_df)}")

    procs = win_df[win_df["EventCode"] == "4688"]["Process"].value_counts()
    if not procs.empty:
        print("\nПроцессы (EventCode 4688):")
        for name, cnt in procs.items():
            print(f"  {name}: {cnt}")

    print("\n" + "=" * 60)
    print("  АНАЛИЗ DNS")
    print("=" * 60)
    if dns_df.empty:
        print("Нет DNS-логов")
    else:
        print(dns_summary.to_string(index=False))
        susp_dns = dns_df[dns_df["IsSuspicious"]]
        if not susp_dns.empty:
            print("\nПодозрительные домены:")
            for _, r in susp_dns.iterrows():
                print(f"  {r['QueryName']}  ({r['ClientIP']})  [{r['Category']}]")

    print("\n" + "=" * 60)
    print("  ТОП-10 ПОДОЗРИТЕЛЬНЫХ СОБЫТИЙ")
    print("=" * 60)
    if top10.empty:
        print("Подозрительных событий не найдено")
    else:
        print(top10[["Event", "Count", "Risk", "Detail"]].to_string(index=False))


# ══════════════════════════════════════════════════════════════
#  Этап 3. Визуализация
# ══════════════════════════════════════════════════════════════

def _style(ax, title=""):
    """Базовая стилизация оси."""
    ax.set_facecolor(C["panel"])
    if title:
        ax.set_title(title, color=C["text"], fontsize=13,
                     fontweight="bold", pad=12, loc="left")
    ax.tick_params(colors=C["muted"], labelsize=9)
    for s in ax.spines.values():
        s.set_color(C["grid"])


def _grid(ax):
    ax.xaxis.grid(True, color=C["grid"], ls="--", alpha=.5, zorder=0)
    ax.set_axisbelow(True)


# --- График 1: Топ-10 подозрительных событий (главный) ---

def plot_top10(ax, top10):
    """Горизонтальный барчарт — топ-10 подозрительных событий."""
    if top10.empty:
        ax.text(.5, .5, "Нет подозрительных событий",
                transform=ax.transAxes, ha="center", color=C["muted"])
        _style(ax, "Топ-10 подозрительных событий")
        return

    data = top10.iloc[::-1]  # снизу вверх
    colors = [RISK_COLOR.get(r, "#888") for r in data["Risk"]]

    bars = ax.barh(data["Event"], data["Count"],
                   color=colors, height=.6, zorder=3)

    for bar, (_, row) in zip(bars, data.iterrows()):
        w = bar.get_width()
        ax.text(w + .15, bar.get_y() + bar.get_height() / 2,
                f"{int(w)}",
                va="center", color=C["text"], fontsize=10, fontweight="bold")

    _style(ax, "Топ-10 подозрительных событий (WinEventLog + DNS)")
    ax.set_xlabel("Количество событий", color=C["muted"], fontsize=10)
    _grid(ax)
    ax.set_xlim(0, top10["Count"].max() * 1.3)

    patches = [mpatches.Patch(color=c, label=l) for l, c in RISK_COLOR.items()]
    ax.legend(handles=patches, fontsize=8, loc="lower right",
              facecolor=C["panel"], edgecolor=C["grid"], labelcolor=C["muted"])


# --- График 2: Donut — WinEventLog ---

def plot_donut(ax, win_agg):
    """Donut-диаграмма — доли EventCode в WinEventLog."""
    data = win_agg.sort_values("Count", ascending=False)
    colors = [RISK_COLOR.get(r, "#888") for r in data["Risk"]]

    wedges, labels, pcts = ax.pie(
        data["Count"], labels=data["EventCode"],
        autopct="%1.0f%%", colors=colors,
        startangle=140, pctdistance=.78,
        wedgeprops={"edgecolor": C["bg"], "linewidth": 2, "width": .48},
    )
    for t in labels:
        t.set(color=C["muted"], fontsize=10, fontweight="bold")
    for t in pcts:
        t.set(color="white", fontsize=8.5, fontweight="bold")

    ax.text(0, 0, f"{len(data)}\nтипов", ha="center", va="center",
            color=C["text"], fontsize=16, fontweight="bold", linespacing=1.6)

    legend = [f"{r.EventCode} — {r.Label} ({r.Count})" for r in data.itertuples()]
    ax.legend(wedges, legend, loc="lower center", bbox_to_anchor=(.5, -.22),
              fontsize=8, framealpha=0, labelcolor=C["muted"], ncol=1)
    _style(ax, "WinEventLog — распределение EventCode")


# --- График 3: DNS ---

DNS_COLORS = {
    "Вредоносный":    "#e74c3c",
    "Подозрительный": "#f39c12",
    "DGA (возможно)": "#9b59b6",
    "Легитимный":     "#3498db",
}

def plot_dns(ax, dns_df, dns_summary):
    """Барчарт категорий DNS-запросов."""
    if dns_summary.empty:
        ax.text(.5, .5, "Нет DNS-логов", transform=ax.transAxes,
                ha="center", color=C["muted"], fontsize=12, style="italic")
        _style(ax, "DNS — анализ запросов")
        ax.axis("off")
        return

    data = dns_summary.sort_values("Count", ascending=True)
    colors = [DNS_COLORS.get(c, "#888") for c in data["Category"]]

    bars = ax.barh(data["Category"], data["Count"],
                   color=colors, height=.5, zorder=3)

    for bar, val in zip(bars, data["Count"]):
        ax.text(bar.get_width() + .05, bar.get_y() + bar.get_height() / 2,
                str(int(val)), va="center", color=C["text"],
                fontsize=10, fontweight="bold")

    _style(ax, "DNS — анализ запросов")
    ax.set_xlabel("Количество", color=C["muted"], fontsize=10)
    _grid(ax)
    ax.set_xlim(0, data["Count"].max() * 1.6)

    # подозрительные домены
    susp = dns_df[dns_df["IsSuspicious"]]
    if not susp.empty:
        lines = [f"· {r['QueryName']}  ({r['ClientIP']})" for _, r in susp.iterrows()]
        ax.text(.97, .95, "Подозрительные домены:\n" + "\n".join(lines),
                transform=ax.transAxes, ha="right", va="top",
                fontsize=7.5, color="#f39c12", fontfamily="monospace",
                bbox=dict(boxstyle="round,pad=.4", fc=C["bg"],
                          ec="#f39c12", alpha=.9))


# --- График 4: Находки ---

def plot_findings(ax, win_df):
    """Карточки с ключевыми находками."""
    ax.set_facecolor(C["panel"])
    ax.axis("off")
    ax.set_title("Ключевые находки", color=C["text"], fontsize=13,
                 fontweight="bold", pad=12, loc="left")

    ev4656 = win_df[win_df["EventCode"] == "4656"]
    user_4656 = ev4656.iloc[0]["User"] if not ev4656.empty else "—"
    obj_4656  = ev4656.iloc[0]["ObjectName"] if not ev4656.empty else "—"

    cards = [
        ("4703 · Изменение прав токена", "ВЫСОКИЙ", "#e74c3c", [
            "12 событий на 11 хостах (svchost.exe / SYSTEM)",
            "Массовое изменение привилегий → эскалация прав",
        ]),
        ("4624 · Успешный вход (Kerberos)", "СРЕДНИЙ", "#f39c12", [
            "Logon Type 3, Kerberos + делегирование",
            "IPv6 link-local (fe80::…) → lateral movement",
        ]),
        ("4656 · Доступ к объекту", "СРЕДНИЙ", "#9b59b6", [
            f"Пользователь: {user_4656}",
            f"Объект: {obj_4656}",
        ]),
    ]

    card_h = .28
    gap = .035
    y = .95

    for title, risk, color, lines in cards:
        rect = mpatches.FancyBboxPatch(
            (.03, y - card_h), .94, card_h,
            boxstyle="round,pad=.012", transform=ax.transAxes, clip_on=False,
            facecolor=C["bg"], edgecolor=color, linewidth=1.5,
        )
        ax.add_patch(rect)

        ax.text(.06, y - .035, title, transform=ax.transAxes,
                color=C["text"], fontsize=10, fontweight="bold", va="top")
        ax.text(.95, y - .035, f"▲ {risk}", transform=ax.transAxes,
                color=color, fontsize=9, fontweight="bold", ha="right", va="top")

        for i, line in enumerate(lines):
            ax.text(.07, y - .11 - i * .075, f"· {line}",
                    transform=ax.transAxes, color=C["muted"], fontsize=9, va="top")

        y -= card_h + gap


# --- Сборка дашборда ---

def build_dashboard(win_df, dns_df, win_agg, dns_summary, top10, raw):
    """
    Дашборд 3×2:
      Ряд 1: Топ-10 подозрительных (на всю ширину)
      Ряд 2: Donut WinEventLog + DNS-анализ
      Ряд 3: Ключевые находки (на всю ширину)
    """
    fig = plt.figure(figsize=(16, 20), facecolor=C["bg"])
    gs = gridspec.GridSpec(3, 2, figure=fig,
                           height_ratios=[1.1, 1, 1.1],
                           hspace=.35, wspace=.30,
                           left=.08, right=.97, top=.92, bottom=.03)

    # заголовок
    fig.suptitle(
        "Анализ безопасности BOTSv1  ·  WinEventLog:Security + DNS  ·  28 августа 2016",
        fontsize=15, fontweight="bold", color=C["text"], y=.97)

    total_susp = len(win_df[win_df["IsSuspicious"]]) + (
        len(dns_df[dns_df["IsSuspicious"]]) if "IsSuspicious" in dns_df.columns else 0)
    fig.text(.5, .94,
             f"Записей: {len(raw)}  |  WinEventLog: {len(win_df)}  |  "
             f"DNS: {len(dns_df)}  |  Подозрительных: {total_susp}",
             ha="center", fontsize=10, color=C["muted"])

    # ряд 1: топ-10 на всю ширину
    plot_top10(fig.add_subplot(gs[0, :]), top10)

    # ряд 2: donut + DNS
    plot_donut(fig.add_subplot(gs[1, 0]), win_agg)
    plot_dns(fig.add_subplot(gs[1, 1]), dns_df, dns_summary)

    # ряд 3: находки на всю ширину
    plot_findings(fig.add_subplot(gs[2, :]), win_df)

    return fig


# ══════════════════════════════════════════════════════════════
#  Точка входа
# ══════════════════════════════════════════════════════════════

def main():
    # Этап 1: загрузка
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "botsv1.json")
    if not os.path.exists(path):
        path = "/mnt/user-data/uploads/botsv1.json"

    win_df, dns_df, raw = load_data(path)

    # Этап 2: анализ
    win_df, win_agg = analyze_winevent(win_df)
    dns_df, dns_summary = analyze_dns(dns_df)
    top10 = build_top10(win_df, dns_df)

    # Консольный отчёт
    print_report(win_df, win_agg, dns_df, dns_summary, top10)

    # Этап 3: визуализация
    fig = build_dashboard(win_df, dns_df, win_agg, dns_summary, top10, raw)

    out = os.path.join(here, "botsv1_analysis.png")
    if not os.access(here, os.W_OK):
        out = "/mnt/user-data/outputs/botsv1_analysis.png"
    plt.savefig(out, dpi=150, bbox_inches="tight", facecolor=C["bg"])
    plt.close()
    print(f"\nДашборд сохранён: {out}")


if __name__ == "__main__":
    main()