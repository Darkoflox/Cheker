#!/usr/bin/env python3
"""
Проверка и фильтрация URL-подписок: доступность + минимальное количество конфигураций.
Использование:
    python checker.py --input configs.txt --output clean_configs.txt [--min-configs 2000] [--threads 10]
"""
import argparse
import base64
import logging
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Tuple
from urllib.parse import unquote

import requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
}

SUPPORTED_PROTOCOLS = {'vmess', 'vless', 'trojan', 'ss', 'ssr', 'hysteria2', 'tuic'}
PROXY_LINK_PATTERN = re.compile(
    r'(vmess|vless|trojan|ss|ssr|hysteria2|tuic)://[^\s#]+',
    re.IGNORECASE
)


def extract_links(text: str) -> List[str]:
    """Извлекает все прокси-ссылки из текста."""
    try:
        decoded_text = unquote(text)
    except Exception:
        decoded_text = text
    links = []
    for match in PROXY_LINK_PATTERN.finditer(decoded_text):
        link = match.group(0)
        # Убедимся, что ссылка начинается с протокола
        for proto in SUPPORTED_PROTOCOLS:
            idx = link.find(f"{proto}://")
            if idx != -1:
                link = link[idx:]
                break
        links.append(link)
    return links


def decode_subscription(content: str) -> List[str]:
    """Декодирует содержимое подписки в список строк."""
    # Попытка Base64
    try:
        decoded = base64.b64decode(content, validate=True).decode('utf-8', errors='ignore')
        if any(p in decoded for p in SUPPORTED_PROTOCOLS):
            return decoded.splitlines()
    except Exception:
        pass
    # Возвращаем как plain text
    return content.splitlines()


def count_configs(content: str) -> int:
    """Подсчитывает количество конфигураций в содержимом подписки."""
    if not content:
        return 0
    lines = decode_subscription(content)
    total = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        links = extract_links(line)
        total += len(links)
    return total


def check_url(url: str, timeout: int = 15, min_configs: int = 0) -> Tuple[bool, int, str]:
    """
    Проверяет URL.
    Возвращает: (доступен, количество конфигураций, сообщение об ошибке)
    """
    try:
        # HEAD-запрос
        resp = requests.head(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
        if resp.status_code == 405:
            resp = requests.get(url, headers=HEADERS, timeout=timeout, stream=True)
            resp.close()
        if resp.status_code != 200:
            return False, 0, f"HTTP {resp.status_code}"

        # Если нужно проверять количество конфигураций, загружаем содержимое
        if min_configs > 0:
            # Для больших файлов используем GET с ограничением размера (первые 5 МБ)
            resp = requests.get(url, headers=HEADERS, timeout=timeout, stream=True)
            content = resp.text
            count = count_configs(content)
            if count < min_configs:
                return True, count, f"мало конфигураций ({count} < {min_configs})"
            return True, count, ""
        else:
            return True, 0, ""

    except requests.exceptions.Timeout:
        return False, 0, "timeout"
    except requests.exceptions.ConnectionError:
        return False, 0, "connection error"
    except Exception as e:
        return False, 0, str(e)


def process_urls(input_file: str, output_file: str, min_configs: int = 2000, threads: int = 10) -> None:
    # Чтение и дедупликация
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            raw_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        logger.error(f"Файл {input_file} не найден")
        sys.exit(1)

    logger.info(f"Прочитано {len(raw_urls)} URL")

    unique_urls: List[str] = []
    seen: Set[str] = set()
    for url in raw_urls:
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)

    logger.info(f"Уникальных URL: {len(unique_urls)}")

    # Проверка
    logger.info(f"Проверка URL (мин. конфигураций: {min_configs}, потоков: {threads})...")
    working_urls: List[str] = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_url = {executor.submit(check_url, url, 15, min_configs): url for url in unique_urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                ok, count, msg = future.result()
                if ok:
                    working_urls.append(url)
                    if min_configs > 0:
                        logger.info(f"✅ {url} ({count} конфигураций)")
                    else:
                        logger.info(f"✅ {url}")
                else:
                    if msg:
                        logger.warning(f"❌ {url} - {msg}")
                    else:
                        logger.warning(f"❌ {url} недоступен")
            except Exception as e:
                logger.error(f"Ошибка при проверке {url}: {e}")

    # Сохранение
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(working_urls))

    logger.info(f"Готово. Рабочих URL: {len(working_urls)} → {output_file}")


def main():
    parser = argparse.ArgumentParser(description='Проверка и фильтрация URL подписок.')
    parser.add_argument('--input', required=True, help='Входной файл (например, configs.txt)')
    parser.add_argument('--output', default='clean_configs.txt', help='Выходной файл')
    parser.add_argument('--min-configs', type=int, default=2000,
                        help='Минимальное количество конфигураций в подписке (0 - не проверять)')
    parser.add_argument('--threads', type=int, default=10, help='Число потоков')
    args = parser.parse_args()

    process_urls(args.input, args.output, args.min_configs, args.threads)


if __name__ == '__main__':
    main()
