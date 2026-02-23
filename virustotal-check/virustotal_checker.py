"""
=============================================================
  VirusTotal API — проверка домена или хеша файла
=============================================================

Описание:
  Скрипт обращается к публичному API VirusTotal и выводит
  результаты анализа для домена или хеша файла (MD5/SHA1/SHA256).

Как запустить:
  1. Установите зависимости:
       pip install requests python-dotenv

  2. Получите бесплатный API-ключ на https://www.virustotal.com/
     (бесплатный план: 4 запроса/мин, 500 запросов/сутки)

  3. Создайте файл .env в той же папке, что и скрипт:
       VT_API_KEY=ваш_ключ_здесь

     Важно: добавьте .env в .gitignore, чтобы не публиковать ключ:
       echo ".env" >> .gitignore

  4. Запустите скрипт:
       python virustotal_checker.py

  5. Введите домен или хеш файла при запросе.

Примеры входных данных:
  Домен:  google.com
  MD5:    44d88612fea8a8f36de82e1278abb02f
  SHA256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
=============================================================
"""

import os
import sys
import json
import requests
from dotenv import load_dotenv

# Конфигурация

# Загружаем переменные из файла .env (если файл существует)
load_dotenv()

# Читаем API-ключ из переменной VT_API_KEY в .env
API_KEY = os.getenv("VT_API_KEY", "")

BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS = {
    "x-apikey": API_KEY,
    "Accept": "application/json",
}


# Вспомогательные функции

def detect_input_type(value: str) -> str:
    """Определяет тип введённого значения: domain, md5, sha1 или sha256."""
    value = value.strip()
    length = len(value)

    # Хеши состоят только из hex-символов
    if all(c in "0123456789abcdefABCDEF" for c in value):
        if length == 32:
            return "md5"
        elif length == 40:
            return "sha1"
        elif length == 64:
            return "sha256"

    # Иначе считаем доменом
    return "domain"


def check_domain(domain: str) -> dict:
    """Запрос к VirusTotal: анализ домена."""
    url = f"{BASE_URL}/domains/{domain}"
    response = requests.get(url, headers=HEADERS, timeout=15)
    response.raise_for_status()
    return response.json()


def check_file_hash(file_hash: str) -> dict:
    """Запрос к VirusTotal: анализ хеша файла."""
    url = f"{BASE_URL}/files/{file_hash}"
    response = requests.get(url, headers=HEADERS, timeout=15)
    response.raise_for_status()
    return response.json()


# Форматированный вывод результатов

def print_domain_report(data: dict, domain: str):
    """Выводит читаемый отчёт по домену."""
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    print(f"\n{'='*55}")
    print(f"  ОТЧЁТ ПО ДОМЕНУ: {domain}")
    print(f"{'='*55}")
    print(f"  Вредоносных детектов : {stats.get('malicious', 0)}")
    print(f"  Подозрительных       : {stats.get('suspicious', 0)}")
    print(f"  Безопасных           : {stats.get('harmless', 0)}")
    print(f"  Без детекта          : {stats.get('undetected', 0)}")

    categories = attrs.get("categories", {})
    if categories:
        cats = ", ".join(set(categories.values()))
        print(f"  Категории            : {cats}")

    reputation = attrs.get("reputation")
    if reputation is not None:
        print(f"  Репутация            : {reputation}")

    print(f"{'='*55}\n")


def print_file_report(data: dict, file_hash: str):
    """Выводит читаемый отчёт по хешу файла."""
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    print(f"\n{'='*55}")
    print(f"  ОТЧЁТ ПО ФАЙЛУ (хеш): {file_hash}")
    print(f"{'='*55}")
    print(f"  Имя файла            : {attrs.get('meaningful_name', 'неизвестно')}")
    print(f"  Тип файла            : {attrs.get('type_description', 'неизвестно')}")
    print(f"  Размер               : {attrs.get('size', 'н/д')} байт")
    print(f"  Вредоносных детектов : {stats.get('malicious', 0)}")
    print(f"  Подозрительных       : {stats.get('suspicious', 0)}")
    print(f"  Безопасных           : {stats.get('harmless', 0)}")
    print(f"  Без детекта          : {stats.get('undetected', 0)}")

    # Список антивирусов, обнаруживших угрозу
    engines = attrs.get("last_analysis_results", {})
    detected = [
        (eng, info.get("result"))
        for eng, info in engines.items()
        if info.get("category") == "malicious"
    ]
    if detected:
        print(f"\n  Обнаружено следующими антивирусами ({len(detected)}):")
        for eng, result in detected[:10]:  # показываем первые 10
            print(f"    • {eng}: {result}")
        if len(detected) > 10:
            print(f"    ... и ещё {len(detected) - 10} других")

    print(f"{'='*55}\n")


# Сохранение JSON-ответа в файл

def save_json(data: dict, filename: str):
    """Сохраняет JSON-ответ API в файл."""
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"  JSON-ответ сохранён в файл: {filename}")


# Основная логика

def main():
    if not API_KEY:
        print("\n[!] API-ключ не найден.")
        print("    Создайте файл .env рядом со скриптом и добавьте строку:")
        print("    VT_API_KEY=ваш_ключ_здесь\n")
        sys.exit(1)

    print("\n  VirusTotal API — проверка домена или хеша файла")
    print("  Введите домен (например: google.com)")
    print("  или хеш MD5/SHA1/SHA256 файла.\n")

    target = input("  >> Введите значение для проверки: ").strip()
    if not target:
        print("  [!] Пустой ввод. Завершение.")
        sys.exit(1)

    input_type = detect_input_type(target)
    print(f"\n  Определён тип: {input_type.upper()}")
    print("  Отправляем запрос к VirusTotal API...")

    try:
        if input_type == "domain":
            raw_data = check_domain(target)
            print_domain_report(raw_data, target)
            save_json(raw_data, f"vt_domain_{target}.json")

        else:  # md5 / sha1 / sha256
            raw_data = check_file_hash(target)
            print_file_report(raw_data, target)
            save_json(raw_data, f"vt_hash_{target[:12]}.json")

    except requests.exceptions.HTTPError as e:
        status = e.response.status_code
        if status == 401:
            print("\n  [!] Ошибка 401: Неверный API-ключ.")
        elif status == 404:
            print("\n  [!] Ошибка 404: Объект не найден в базе VirusTotal.")
        elif status == 429:
            print("\n  [!] Ошибка 429: Превышен лимит запросов (4 req/min для бесплатного плана).")
        else:
            print(f"\n  [!] HTTP-ошибка: {e}")
        sys.exit(1)

    except requests.exceptions.ConnectionError:
        print("\n  [!] Нет подключения к интернету или VirusTotal недоступен.")
        sys.exit(1)

    except requests.exceptions.Timeout:
        print("\n  [!] Превышено время ожидания ответа от API.")
        sys.exit(1)


if __name__ == "__main__":
    main()