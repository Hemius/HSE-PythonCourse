import json
import pandas as pd
import matplotlib.pyplot as plt


def load_data(filepath: str) -> pd.DataFrame:
    """Загружает данные из JSON-файла в DataFrame."""
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    return pd.DataFrame(data["events"])


def analyze_data(df: pd.DataFrame) -> pd.Series:
    """Выполняет анализ данных и возвращает распределение событий по сигнатурам."""
    print("=" * 60)
    print("АНАЛИЗ СОБЫТИЙ ИНФОРМАЦИОННОЙ БЕЗОПАСНОСТИ")
    print("=" * 60)

    print(f"Всего событий: {len(df)}")
    print(f"Уникальных сигнатур: {df['signature'].nunique()}")

    print("\nПримеры событий:")
    print(df.head())

    event_distribution = df["signature"].value_counts()

    print("\nРаспределение событий по типам:")
    for signature, count in event_distribution.items():
        print(f"- {signature}: {count}")

    return event_distribution


def plot_event_distribution(event_distribution: pd.Series) -> None:
    """Строит график распределения событий по типам."""
    plt.figure(figsize=(12, 6))
    event_distribution.plot(kind="bar")
    plt.title("Распределение событий информационной безопасности")
    plt.xlabel("Тип события")
    plt.ylabel("Количество")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.show()


def main():
    df = load_data("events.json")
    event_distribution = analyze_data(df)
    plot_event_distribution(event_distribution)


if __name__ == "__main__":
    main()