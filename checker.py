#!/usr/bin/env python3
"""
Быстрая проверка и дедупликация списка URL-адресов подписок.
Использование:
    python checker.py --input configs.txt --output clean_configs.txt [--threads 10]
"""
import argparse
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set

# Обработка отсутствия библиотеки requests
try:
    import requests
except ImportError:
    print("Ошибка: библиотека 'requests' не установлена.")
    print("Установите её командой: pip install requests")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
}

def check_url(url: str, timeout: int = 10) -> bool:
    """Возвращает True, если URL отдаёт 200 OK."""
    try:
        resp = requests.head(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
        if resp.status_code == 405:
            resp = requests.get(url, headers=HEADERS, timeout=timeout, stream=True)
            resp.close()
        return resp.status_code == 200
    except requests.exceptions.Timeout:
        logger.debug(f"Таймаут: {url}")
    except requests.exceptions.ConnectionError:
        logger.debug(f"Ошибка соединения: {url}")
    except requests.exceptions.RequestException as e:
        logger.debug(f"Ошибка запроса {url}: {e}")
    return False

def process_urls(input_file: str, output_file: str, threads: int = 10) -> None:
    # Проверка существования входного файла
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            raw_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        logger.error(f"Файл '{input_file}' не найден. Убедитесь, что он существует.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Не удалось прочитать файл '{input_file}': {e}")
        sys.exit(1)

    if not raw_urls:
        logger.warning("Входной файл пуст. Выходной файл не создан.")
        return

    logger.info(f"Прочитано {len(raw_urls)} URL")

    # Дедупликация (точное совпадение строк)
    unique_urls: List[str] = []
    seen: Set[str] = set()
    for url in raw_urls:
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)

    logger.info(f"Уникальных URL: {len(unique_urls)} (удалено {len(raw_urls) - len(unique_urls)})")

    # Проверка доступности
    logger.info(f"Проверка доступности (потоков: {threads})...")
    working_urls: List[str] = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_url = {executor.submit(check_url, url): url for url in unique_urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                if future.result():
                    working_urls.append(url)
                    logger.info(f"✅ {url}")
                else:
                    logger.warning(f"❌ Недоступен: {url}")
            except Exception as e:
                logger.error(f"Непредвиденная ошибка при проверке {url}: {e}")

    # Сохранение результата
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(working_urls))
        logger.info(f"Готово. Рабочих URL: {len(working_urls)} → {output_file}")
    except Exception as e:
        logger.error(f"Не удалось записать выходной файл '{output_file}': {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Проверка и дедупликация URL подписок.')
    parser.add_argument('--input', required=True, help='Входной файл (например, configs.txt)')
    parser.add_argument('--output', default='clean_configs.txt', help='Выходной файл')
    parser.add_argument('--threads', type=int, default=10, help='Число потоков')
    args = parser.parse_args()

    if args.threads < 1:
        logger.error("Число потоков должно быть >= 1")
        sys.exit(1)

    process_urls(args.input, args.output, args.threads)

if __name__ == '__main__':
    main()
