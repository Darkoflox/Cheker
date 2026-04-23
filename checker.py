#!/usr/bin/env python3
"""
Расширенная проверка URL-подписок:
- доступность
- минимальное общее количество конфигураций (по умолчанию 5000)
- опционально: минимальное количество конфигураций с российскими IP/доменами
- отбор лучших N источников

Использование:
    python checker.py --input configs.txt --output top100.txt --min-configs 5000 --top 100 --threads 20 [--check-russia]
"""
import argparse
import base64
import ipaddress
import logging
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import unquote, urlparse

import requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
SUPPORTED_PROTOCOLS = {'vmess', 'vless', 'trojan', 'ss', 'ssr', 'hysteria2', 'tuic'}
PROXY_LINK_PATTERN = re.compile(r'(vmess|vless|trojan|ss|ssr|hysteria2|tuic)://[^\s#]+', re.IGNORECASE)


# ---------- Фильтр РФ (упрощённая версия из парсера) ----------
class RussianFilter:
    def __init__(self, ip_file="russia_ip.txt", domain_file="russia_domains.txt"):
        self.ip_networks = []
        self.domains = set()
        self._load_lists(ip_file, domain_file)
        self._dns_cache = {}

    def _ensure_file(self, path: str, example: str):
        if not Path(path).exists():
            Path(path).write_text(example, encoding='utf-8')
            logger.info(f"📄 Создан файл {path}")

    def _load_lists(self, ip_file: str, domain_file: str):
        self._ensure_file(ip_file, "# IP-адреса и CIDR РФ\n")
        self._ensure_file(domain_file, "# Домены РФ\n")
        with open(ip_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    self.ip_networks.append(ipaddress.ip_network(line, strict=False))
                except ValueError:
                    pass
        with open(domain_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip().lower()
                if not line or line.startswith('#'):
                    continue
                self.domains.add(line)
        logger.info(f"🛡️ РФ: IP-сетей {len(self.ip_networks)}, доменов {len(self.domains)}")

    def is_russian(self, host: str) -> bool:
        if not host:
            return False
        host_lower = host.lower()
        for d in self.domains:
            if host_lower == d or host_lower.endswith('.' + d):
                return True
        try:
            ip = ipaddress.ip_address(host)
            for net in self.ip_networks:
                if ip in net:
                    return True
        except ValueError:
            resolved = self._resolve_host(host)
            if resolved:
                try:
                    ip = ipaddress.ip_address(resolved)
                    for net in self.ip_networks:
                        if ip in net:
                            return True
                except ValueError:
                    pass
        return False

    def _resolve_host(self, host: str) -> Optional[str]:
        if host in self._dns_cache:
            return self._dns_cache[host]
        try:
            ip = socket.gethostbyname(host)
            self._dns_cache[host] = ip
            return ip
        except socket.gaierror:
            self._dns_cache[host] = None
            return None


# ---------- Парсинг конфигураций ----------
def extract_links(text: str) -> List[str]:
    try:
        decoded_text = unquote(text)
    except Exception:
        decoded_text = text
    links = []
    for match in PROXY_LINK_PATTERN.finditer(decoded_text):
        link = match.group(0)
        for proto in SUPPORTED_PROTOCOLS:
            idx = link.find(f"{proto}://")
            if idx != -1:
                link = link[idx:]
                break
        links.append(link)
    return links


def decode_subscription(content: str) -> List[str]:
    try:
        decoded = base64.b64decode(content, validate=True).decode('utf-8', errors='ignore')
        if any(p in decoded for p in SUPPORTED_PROTOCOLS):
            return decoded.splitlines()
    except Exception:
        pass
    return content.splitlines()


def parse_host_from_link(link: str) -> Optional[str]:
    try:
        parsed = urlparse(link)
        return parsed.hostname
    except Exception:
        return None


def count_configs(content: str, russian_filter: Optional[RussianFilter] = None) -> Tuple[int, int]:
    """
    Возвращает (общее количество конфигураций, количество российских конфигураций).
    """
    if not content:
        return 0, 0
    lines = decode_subscription(content)
    total = 0
    russia_count = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        for link in extract_links(line):
            total += 1
            if russian_filter:
                host = parse_host_from_link(link)
                if host and russian_filter.is_russian(host):
                    russia_count += 1
    return total, russia_count


def check_url(url: str,
              timeout: int = 15,
              min_configs: int = 0,
              russian_filter: Optional[RussianFilter] = None,
              min_russia_configs: int = 0) -> Tuple[bool, int, int, str]:
    """
    Возвращает (успех, всего конфигураций, российских конфигураций, сообщение).
    """
    try:
        resp = requests.head(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
        if resp.status_code == 405:
            resp = requests.get(url, headers=HEADERS, timeout=timeout, stream=True)
            resp.close()
        if resp.status_code != 200:
            return False, 0, 0, f"HTTP {resp.status_code}"

        if min_configs > 0 or (russian_filter and min_russia_configs > 0):
            resp = requests.get(url, headers=HEADERS, timeout=timeout, stream=True)
            content = resp.text
            total, russia = count_configs(content, russian_filter)

            if total < min_configs:
                return True, total, russia, f"мало конфигураций ({total} < {min_configs})"
            if russian_filter and russia < min_russia_configs:
                return True, total, russia, f"мало российских конфигураций ({russia} < {min_russia_configs})"

            return True, total, russia, ""
        return True, 0, 0, ""
    except requests.exceptions.Timeout:
        return False, 0, 0, "timeout"
    except requests.exceptions.ConnectionError:
        return False, 0, 0, "connection error"
    except Exception as e:
        return False, 0, 0, str(e)


def process_urls(input_file: str,
                 output_file: str,
                 min_configs: int,
                 top: int,
                 threads: int,
                 check_russia: bool,
                 min_russia_configs: int) -> None:
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            raw_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        logger.error(f"Файл {input_file} не найден")
        sys.exit(1)

    logger.info(f"Прочитано {len(raw_urls)} URL")

    unique_urls = list(dict.fromkeys(raw_urls))
    logger.info(f"Уникальных URL: {len(unique_urls)}")

    russian_filter = RussianFilter() if check_russia else None

    logger.info(f"Проверка (мин. общих конфигураций: {min_configs}, "
                f"{'мин. российских: ' + str(min_russia_configs) if check_russia else ''} потоков: {threads})...")

    working: Dict[str, Tuple[int, int]] = {}  # url -> (total, russia)
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_url = {
            executor.submit(check_url, url, 15, min_configs, russian_filter, min_russia_configs): url
            for url in unique_urls
        }
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                ok, total, russia, msg = future.result()
                if ok:
                    working[url] = (total, russia)
                    if check_russia:
                        logger.info(f"✅ {url} (всего: {total}, РФ: {russia})")
                    else:
                        logger.info(f"✅ {url} ({total} конф.)")
                else:
                    logger.warning(f"❌ {url} - {msg}")
            except Exception as e:
                logger.error(f"Ошибка {url}: {e}")

    # Сортировка по общему количеству конфигураций (можно изменить на другое)
    sorted_urls = sorted(working.keys(), key=lambda u: working[u][0], reverse=True)
    if top and top > 0:
        sorted_urls = sorted_urls[:top]
        logger.info(f"Оставлено {len(sorted_urls)} лучших источников (top {top})")

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted_urls))
    logger.info(f"✅ Результат сохранён в {output_file} ({len(sorted_urls)} URL)")


def main():
    parser = argparse.ArgumentParser(description='Проверка и фильтрация URL подписок.')
    parser.add_argument('--input', required=True, help='Входной файл')
    parser.add_argument('--output', default='clean_configs.txt', help='Выходной файл')
    parser.add_argument('--min-configs', type=int, default=5000, help='Мин. количество конфигураций')
    parser.add_argument('--top', type=int, default=None, help='Оставить N лучших источников')
    parser.add_argument('--threads', type=int, default=10, help='Число потоков')
    parser.add_argument('--check-russia', action='store_true', help='Проверять наличие российских конфигураций')
    parser.add_argument('--min-russia-configs', type=int, default=1, help='Мин. количество российских конфигураций (только при --check-russia)')
    args = parser.parse_args()

    process_urls(args.input, args.output, args.min_configs, args.top, args.threads,
                 args.check_russia, args.min_russia_configs)


if __name__ == '__main__':
    main()
