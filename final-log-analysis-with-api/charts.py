"""
charts.py — модуль визуализации результатов анализа Suricata.

Назначение:
  - построение 6 графиков в сетке 3×2
  - отображение активности по IP, категориям алертов, динамике событий и CVSS

Входные данные:
  1. analysis (dict) — агрегаты анализа:
     - ip_counts, cat_counts, alerts_df
  2. df (pandas.DataFrame) — исходные события Suricata (EVE)
  3. vulners_results (list[dict] | None) — результаты обогащения CVE из Vulners

Результат работы:
  - сохранение изображения с графиками в файл CHART_FILE (например, threats_chart.png)
  - логирование этапа построения графиков

Использование:
  - вызывается из основного пайплайна через функцию build_charts(...)
"""

import random
import logging
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from config import ALERT_THRESHOLD, BLOCK_THRESHOLD, CHART_FILE

logger = logging.getLogger(__name__)

# Цветовая палитра
BG_PAGE      = "#0f1117"
BG_AX        = "#1a1d27"
RED          = "#e63946"
ORANGE       = "#f4a261"
TEAL         = "#2ec4b6"
BLUE         = "#457b9d"
PURPLE       = "#c77dff"
GREEN        = "#80b918"
TEXT         = "#e0e0e0"
GRID         = "#2a2d3a"
PIE_COLORS   = [RED, ORANGE, TEAL, BLUE, "#a8dadc", PURPLE, GREEN]
STACK_COLORS = [RED, ORANGE, TEAL, BLUE, PURPLE, GREEN, "#e377c2"]

# Резервное сопоставление CVSS по категориям (используется, если в данных нет CVSS)
CVSS_MAP = {
    "Malware Command and Control Activity Detected": (9.5, 10.0),
    "A Network Trojan was Detected":                 (9.0, 10.0),
    "Attempted Administrator Privilege Gain":        (8.8,  9.5),
    "Web Application Attack":                        (7.5,  9.0),
    "Misc Attack":                                   (5.5,  7.5),
    "Network Scan":                                  (5.0,  6.5),
    "Potentially Bad Traffic":                       (4.0,  6.0),
}

# Диапазоны критичности CVSS: (минимум_включительно, цвет, метка)
CVSS_RANGES = [
    (9.0, RED,       "Критический"),
    (7.0, ORANGE,    "Высокий"),
    (4.0, "#f9c74f", "Средний"),
    (0.0, GREEN,     "Низкий"),
]


def _assign_cvss(row: pd.Series) -> float:
    """Возвращает псевдослучайный CVSS из диапазона для категории алерта.

    Используется как резервное значение, когда реальный CVSS из Vulners недоступен.
    random.seed(42) фиксируется перед вызовом, чтобы значения были воспроизводимы.
    """
    lo, hi = CVSS_MAP.get(row.get("category"), (3.0, 7.0))
    return round(random.uniform(lo, hi), 1)


def _style_ax(ax, grid_axis: str = "both") -> None:
    """Применяет единый тёмный стиль к оси: фон, сетка, обводка."""
    ax.set_facecolor(BG_AX)
    ax.grid(axis=grid_axis, color=GRID, linewidth=0.7, alpha=0.8)
    ax.set_axisbelow(True)
    for spine in ax.spines.values():
        spine.set_edgecolor(GRID)


def _cvss_color(score: float) -> str:
    """Возвращает цвет по значению CVSS согласно диапазонам CVSS_RANGES."""
    for threshold, color, _ in CVSS_RANGES:
        if score >= threshold:
            return color
    return GREEN


def build_charts(
    analysis: dict,
    df: pd.DataFrame,
    vulners_results: list[dict] | None = None,
) -> None:
    """Строит 6 графиков и сохраняет их в CHART_FILE.

    Графики:
      1. Горизонтальный bar — топ IP-источников по числу алертов
      2. Круговая диаграмма — распределение категорий алертов
      3. Временной ряд — алерты vs прочие события (шаг 30 мин)
      4. Кольцевая диаграмма — нормальные / алерты / аномалии
      5. Накопленный bar — категории алертов по топ-IP
      6. Пузырьковая диаграмма — средний CVSS по категориям
    """
    logger.info("\n" + "=" * 60)
    logger.info("  ЭТАП 4б: Построение графиков")
    logger.info("=" * 60)

    # Сохраняем полный рейтинг IP для следующих графиков
    ip_counts_full = analysis["ip_counts"]
    ip_counts = ip_counts_full.head(7)

    cat_counts = analysis["cat_counts"]
    alerts_df = analysis["alerts_df"].copy()

    # CVSS: используем реальное значение, если есть; иначе назначаем воспроизводимое резервное
    if "cvss" not in alerts_df.columns or alerts_df["cvss"].isna().all():
        random.seed(42)
        alerts_df["cvss"] = alerts_df.apply(_assign_cvss, axis=1)

    # Переопределяем реальными CVSS3 из Vulners, где это возможно
    cve_score_map = {
        str(r["cve"]).upper(): r["cvss3_score"]
        for r in (vulners_results or [])
        if r.get("status") == "ok" and r.get("cvss3_score") is not None and r.get("cve")
    }

    if cve_score_map and ("alert_cves" in alerts_df.columns or "signature" in alerts_df.columns):
        def _real_cvss(row: pd.Series) -> float:
            if "alert_cves" in alerts_df.columns:
                for cve in (row.get("alert_cves") or []):
                    cve_norm = str(cve).strip().upper()
                    if cve_norm in cve_score_map:
                        return float(cve_score_map[cve_norm])

            sig = str(row.get("signature") or "").upper()
            for cve, score in cve_score_map.items():
                if cve in sig:
                    return float(score)

            return float(row["cvss"])

        alerts_df["cvss"] = alerts_df.apply(_real_cvss, axis=1)

    plt.rcParams.update({
        "font.family":     "DejaVu Sans",
        "text.color":      TEXT,
        "axes.labelcolor": TEXT,
        "xtick.color":     TEXT,
        "ytick.color":     TEXT,
    })

    fig = plt.figure(figsize=(22, 20), facecolor=BG_PAGE)
    gs = gridspec.GridSpec(
        3, 2, figure=fig,
        hspace=0.52, wspace=0.38,
        left=0.07, right=0.97,
        top=0.92, bottom=0.05,
    )

    # Заголовок
    fig.text(
        0.5, 0.965, "Сводка Suricata EVE",
        ha="center", va="center",
        fontsize=24, fontweight="bold", color=TEXT,
    )
    fig.text(
        0.5, 0.945, "Обзор угроз и аномалий",
        ha="center", va="center", fontsize=13, color="#888ea8",
    )
    fig.add_artist(
        plt.Line2D([0.07, 0.97], [0.935, 0.935],
                   transform=fig.transFigure,
                   color=GRID, linewidth=1)
    )

    # Горизонтальная диаграмма: самые активные источники (по числу алертов)
    ax1 = fig.add_subplot(gs[0, 0])
    _style_ax(ax1, "x")

    bar_colors = [
        RED if c >= BLOCK_THRESHOLD else ORANGE
        for c in ip_counts["alert_count"]
    ]
    bars = ax1.barh(
        ip_counts["src_ip"],
        ip_counts["alert_count"],
        color=bar_colors,
        edgecolor=BG_PAGE,
        linewidth=0.8,
        height=0.55,
    )
    ax1.invert_yaxis()
    ax1.axvline(
        BLOCK_THRESHOLD, color=RED, linestyle="--", linewidth=1.3,
        label=f"Блокировка ≥ {BLOCK_THRESHOLD}"
    )
    ax1.axvline(
        ALERT_THRESHOLD, color=ORANGE, linestyle=":", linewidth=1.3,
        label=f"Алерт ≥ {ALERT_THRESHOLD}"
    )

    max_val = float(ip_counts["alert_count"].max()) if not ip_counts.empty else 0.0
    for bar, val in zip(bars, ip_counts["alert_count"]):
        ax1.text(
            bar.get_width() + (max_val * 0.02 if max_val else 0.2),
            bar.get_y() + bar.get_height() / 2,
            str(int(val)),
            va="center", ha="left",
            fontsize=10, fontweight="bold", color=TEXT,
        )

    ax1.set_xlim(0, max_val + max_val * 0.22 if max_val else 1)
    ax1.set_xlabel("Количество алертов", fontsize=10, labelpad=8)
    ax1.set_title(
        "Топ IP-источников по числу алертов",
        fontsize=12, fontweight="bold", color=TEXT, pad=12,
    )
    ax1.legend(
        fontsize=8.5, frameon=True, facecolor=BG_PAGE,
        edgecolor=GRID, labelcolor=TEXT, loc="lower right",
    )

    # Круговая диаграмма: распределение категорий алертов
    ax2 = fig.add_subplot(gs[0, 1])
    ax2.set_facecolor(BG_AX)

    wedges, _, autotexts = ax2.pie(
        cat_counts["count"],
        labels=None,
        autopct="%1.0f%%",
        colors=PIE_COLORS[:len(cat_counts)],
        startangle=140,
        pctdistance=0.72,
        wedgeprops={"edgecolor": BG_PAGE, "linewidth": 2},
        textprops={"color": TEXT, "fontsize": 9},
    )
    for at in autotexts:
        at.set_fontweight("bold")

    legend_labels = [
        f"{r['category']} — {r['count']}"
        for _, r in cat_counts.iterrows()
    ]
    ax2.legend(
        wedges, legend_labels,
        loc="center left", bbox_to_anchor=(1.02, 0.5),
        fontsize=8.5, frameon=True,
        facecolor=BG_PAGE, edgecolor=GRID, labelcolor=TEXT,
    )
    ax2.set_title(
        "Категории алертов (распределение)",
        fontsize=12, fontweight="bold", color=TEXT, pad=12,
    )

    # Временной ряд: алерты vs не-алерты (интервалы по 30 минут)
    ax3 = fig.add_subplot(gs[1, 0])
    _style_ax(ax3)

    df_copy = df.copy()
    df_copy["timestamp"] = pd.to_datetime(df_copy["timestamp"], errors="coerce")
    df_copy = df_copy.dropna(subset=["timestamp"]).set_index("timestamp")

    if df_copy.empty:
        ax3.text(
            0.5, 0.5, "Нет данных с временными метками",
            transform=ax3.transAxes,
            ha="center", va="center",
            fontsize=12, color="#888ea8",
        )
        ax3.set_title(
            "Динамика событий во времени (шаг 30 минут)",
            fontsize=12, fontweight="bold", color=TEXT, pad=12,
        )
    else:
        normal_ts = df_copy[~df_copy["is_alert"]].resample("30min").size()
        alert_ts  = df_copy[ df_copy["is_alert"]].resample("30min").size()
        all_idx   = normal_ts.index.union(alert_ts.index)
        normal_ts = normal_ts.reindex(all_idx, fill_value=0)
        alert_ts  = alert_ts.reindex(all_idx, fill_value=0)

        x_labels = [t.strftime("%H:%M") for t in all_idx]
        x_pos = range(len(x_labels))

        ax3.fill_between(x_pos, normal_ts.values, alpha=0.2, color=TEAL, step="mid")
        ax3.fill_between(x_pos, alert_ts.values,  alpha=0.3, color=RED,  step="mid")
        ax3.step(x_pos, normal_ts.values, color=TEAL, linewidth=1.8, label="Не-алерт события", where="mid")
        ax3.step(x_pos, alert_ts.values,  color=RED,  linewidth=1.8, label="Алерты/аномалии", where="mid")

        tick_step = max(1, len(x_labels) // 8)
        ax3.set_xticks(list(x_pos)[::tick_step])
        ax3.set_xticklabels(x_labels[::tick_step], rotation=30, ha="right", fontsize=8)
        ax3.set_xlabel("Время (UTC)", fontsize=10, labelpad=8)
        ax3.set_ylabel("Событий за 30 минут", fontsize=10, labelpad=8)
        ax3.set_title(
            "Динамика событий во времени (шаг 30 минут)",
            fontsize=12, fontweight="bold", color=TEXT, pad=12,
        )
        ax3.legend(
            fontsize=8.5, frameon=True, facecolor=BG_PAGE,
            edgecolor=GRID, labelcolor=TEXT,
        )
        ax3.set_xlim(0, len(x_labels) - 1)

    # Кольцевая диаграмма: нормальные события vs алерты vs аномалии
    ax4 = fig.add_subplot(gs[1, 1])
    ax4.set_facecolor(BG_AX)
    ax4.set_aspect("equal")

    _NORMAL_TYPES = {"dns", "flow", "tls", "http", "fileinfo", "netflow", "smb", "rdp", "ssh", "stats"}
    n_normal  = int(df["event_type"].isin(_NORMAL_TYPES).sum())
    n_alerts  = int((df["event_type"] == "alert").sum())
    n_anomaly = int((df["event_type"] == "anomaly").sum())
    total = n_normal + n_alerts + n_anomaly

    segments = []
    if n_normal > 0:
        segments.append(("Нормальные", n_normal, TEAL))
    if n_alerts > 0:
        segments.append(("Алерты", n_alerts, RED))
    if n_anomaly > 0:
        segments.append(("Аномалии", n_anomaly, ORANGE))

    if total == 0 or not segments:
        ax4.text(
            0.5, 0.5, "Нет данных по типам событий",
            transform=ax4.transAxes,
            ha="center", va="center",
            fontsize=12, color="#888ea8",
        )
        ax4.set_title(
            "Распределение типов событий",
            fontsize=12, fontweight="bold", color=TEXT, pad=12,
        )
    else:
        seg_vals   = [s[1] for s in segments]
        seg_colors = [s[2] for s in segments]

        wedges, _ = ax4.pie(
            seg_vals,
            colors=seg_colors,
            startangle=90,
            wedgeprops={"width": 0.50, "edgecolor": BG_PAGE, "linewidth": 3},
            counterclock=False,
            center=(0, 0),
            radius=1,
        )

        pct_threats = (n_alerts + n_anomaly) / total * 100
        threat_level = "ВЫСОКИЙ" if pct_threats >= 40 else "СРЕДНИЙ" if pct_threats >= 20 else "НИЗКИЙ"
        threat_color = RED if pct_threats >= 40 else ORANGE if pct_threats >= 20 else TEAL

        ax4.text(0.5, 0.54, f"{pct_threats:.0f}%",
                 transform=ax4.transAxes, ha="center", va="center",
                 fontsize=30, fontweight="bold", color=threat_color)
        ax4.text(0.5, 0.47, "доля угроз",
                 transform=ax4.transAxes, ha="center", va="center",
                 fontsize=11, color="#888ea8")
        ax4.text(0.5, 0.41, threat_level,
                 transform=ax4.transAxes, ha="center", va="center",
                 fontsize=10, fontweight="bold", color=threat_color,
                 bbox=dict(boxstyle="round,pad=0.3", facecolor=threat_color,
                           alpha=0.15, edgecolor=threat_color))

        legend_labels = [f"{lbl} — {val}" for lbl, val, _ in segments]
        ax4.legend(
            wedges, legend_labels,
            loc="lower center", bbox_to_anchor=(0.5, -0.08),
            bbox_transform=ax4.transAxes,
            fontsize=9, frameon=True,
            facecolor=BG_PAGE, edgecolor=GRID, labelcolor=TEXT, ncol=1,
        )
        ax4.set_xlim(-1.4, 1.4)
        ax4.set_ylim(-1.4, 1.4)
        ax4.set_title(
            "Распределение типов событий",
            fontsize=12, fontweight="bold", color=TEXT, pad=12,
        )

    # Накопленная столбчатая диаграмма: смесь категорий для топ-IP
    ax5 = fig.add_subplot(gs[2, 0])
    _style_ax(ax5, "y")

    top_ips = ip_counts_full.head(10)["src_ip"].tolist()
    stack_data = (
        alerts_df[alerts_df["src_ip"].isin(top_ips)]
        .groupby(["src_ip", "category"])
        .size()
        .unstack(fill_value=0)
    )

    if stack_data.empty:
        ax5.text(
            0.5, 0.5, "Нет данных об алертах для топ-IP",
            transform=ax5.transAxes,
            ha="center", va="center",
            fontsize=12, color="#888ea8",
        )
        ax5.set_title(
            "Состав категорий алертов по топ IP-источникам",
            fontsize=12, fontweight="bold", color=TEXT, pad=12,
        )
    else:
        stack_data = stack_data.loc[
            stack_data.sum(axis=1).sort_values(ascending=False).index
        ]

        bottom = pd.Series([0.0] * len(stack_data), index=stack_data.index)
        for i, col in enumerate(stack_data.columns):
            vals = stack_data[col]
            ax5.bar(
                stack_data.index,
                vals,
                bottom=bottom,
                color=STACK_COLORS[i % len(STACK_COLORS)],
                edgecolor=BG_PAGE,
                linewidth=0.6,
                label=col,
                width=0.55,
            )
            for j, (v, b) in enumerate(zip(vals, bottom)):
                if v > 0:
                    ax5.text(
                        j, b + v / 2, str(int(v)),
                        ha="center", va="center",
                        fontsize=8, fontweight="bold", color=TEXT,
                    )
            bottom += vals

        ax5.set_xticks(range(len(stack_data.index)))
        ax5.set_xticklabels(stack_data.index, rotation=15, ha="right", fontsize=8)
        ax5.set_ylabel("Количество алертов", fontsize=10, labelpad=8)
        ax5.set_title(
            "Состав категорий алертов по топ IP-источникам",
            fontsize=12, fontweight="bold", color=TEXT, pad=12,
        )
        ax5.legend(
            fontsize=7.5, frameon=True, facecolor=BG_PAGE,
            edgecolor=GRID, labelcolor=TEXT,
            loc="upper right", ncol=1,
        )

    # Пузырьковая диаграмма: средний CVSS vs частота по категориям
    ax6 = fig.add_subplot(gs[2, 1])
    ax6.set_facecolor(BG_AX)
    for spine in ax6.spines.values():
        spine.set_edgecolor(GRID)

    bubble_df = (
        alerts_df.groupby("category")
        .agg(mean_cvss=("cvss", "mean"), count=("cvss", "count"))
        .reset_index()
        .sort_values("mean_cvss", ascending=True)
    )

    if bubble_df.empty:
        ax6.text(
            0.5, 0.5, "Нет данных CVSS",
            transform=ax6.transAxes,
            ha="center", va="center",
            fontsize=12, color="#888ea8",
        )
        ax6.set_title(
            "CVSS по категориям алертов (среднее и частота)",
            fontsize=12, fontweight="bold", color=TEXT, pad=12,
        )
    else:
        bubble_colors = [_cvss_color(float(s)) for s in bubble_df["mean_cvss"]]
        max_count = float(bubble_df["count"].max()) if bubble_df["count"].max() else 1.0
        sizes = (bubble_df["count"] / max_count) * 3000 + 400

        ax6.scatter(
            bubble_df["mean_cvss"],
            range(len(bubble_df)),
            s=sizes,
            c=bubble_colors,
            alpha=0.85,
            edgecolors=BG_PAGE,
            linewidths=1.5,
            zorder=3,
        )

        for i, row in bubble_df.reset_index(drop=True).iterrows():
            ax6.text(
                float(row["mean_cvss"]), i,
                f"{float(row['mean_cvss']):.1f}\n({int(row['count'])})",
                ha="center", va="center",
                fontsize=7.5, fontweight="bold", color=TEXT, zorder=4,
            )

        for lo, hi, clr, lbl in [
            (0, 4, GREEN, "Низкий"),
            (4, 7, "#f9c74f", "Средний"),
            (7, 9, ORANGE, "Высокий"),
            (9, 10, RED, "Критический"),
        ]:
            ax6.axvspan(lo, hi, alpha=0.07, color=clr, zorder=0)
            ax6.text(
                (lo + hi) / 2, len(bubble_df) - 0.15, lbl,
                ha="center", va="top", fontsize=7.5,
                color=clr, alpha=0.9, fontstyle="italic",
            )

        ax6.set_yticks(range(len(bubble_df)))
        ax6.set_yticklabels(bubble_df["category"], fontsize=8)
        ax6.set_xlim(0, 10)
        ax6.set_ylim(-0.7, len(bubble_df) - 0.3)
        ax6.set_xlabel("Средний балл CVSS", fontsize=10, labelpad=8)
        ax6.grid(axis="x", color=GRID, linewidth=0.7, alpha=0.8)
        ax6.set_axisbelow(True)

        subtitle = "реальный CVSS3 (Vulners)" if cve_score_map else "резервный CVSS"
        ax6.text(
            0.98, 0.02, f"Размер пузыря = число событий  •  {subtitle}",
            transform=ax6.transAxes, ha="right", va="bottom",
            fontsize=8, color="#888ea8", fontstyle="italic",
        )
        ax6.set_title(
            "CVSS по категориям алертов (среднее и частота)",
            fontsize=12, fontweight="bold", color=TEXT, pad=12,
        )

    plt.savefig(CHART_FILE, dpi=150, bbox_inches="tight", facecolor=BG_PAGE)
    plt.close()
    plt.rcParams.update(plt.rcParamsDefault)
    logger.info(f"  ✅ График сохранен: {CHART_FILE}")
