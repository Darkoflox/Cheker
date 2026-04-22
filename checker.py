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

import requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
}

def check_url(url: str, timeout: int = 10) -> bool:
    """Возвращает True, если URL отдаёт 200 OK."""
    try:
        # HEAD‑запрос для экономии трафика
        resp = requests.head(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
        if resp.status_code == 405:  # Метод не поддерживается
            resp = requests.get(url, headers=HEADERS, timeout=timeout, stream=True)
            resp.close()
        return resp.status_code == 200
    except requests.RequestException:
        return False

def process_urls(input_file: str, output_file: str, threads: int = 10) -> None:
    # Чтение
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            raw_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        logger.error(f"Файл {input_file} не найден")
        sys.exit(1)

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
                    logger.debug(f"✅ {url}")
                else:
                    logger.warning(f"❌ Недоступен: {url}")
            except Exception as e:
                logger.error(f"Ошибка {url}: {e}")

    # Сохранение
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(working_urls))

    logger.info(f"Готово. Рабочих URL: {len(working_urls)} → {output_file}")

def main():
    parser = argparse.ArgumentParser(description='Проверка и дедупликация URL подписок.')
    parser.add_argument('--input', required=True, help='Входной файл (например, configs.txt)')
    parser.add_argument('--output', default='clean_configs.txt', help='Выходной файл')
    parser.add_argument('--threads', type=int, default=10, help='Число потоков')
    args = parser.parse_args()
    process_urls(args.input, args.output, args.threads)

if __name__ == '__main__':
    main()
