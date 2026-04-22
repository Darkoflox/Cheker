#!/usr/bin/env python3
"""
Быстрый чекер прокси-конфигураций:
- удаляет дубликаты (по ключевым параметрам)
- проверяет TCP-доступность сервера (connect)
- сохраняет только рабочие ссылки

Использование:
    python fast_checker.py --input файл_с_конфигами.txt --output чистый_список.txt [--threads 50] [--timeout 3]
"""
import argparse
import base64
import json
import logging
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Tuple
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

SUPPORTED_PROTOCOLS = ['vmess', 'vless', 'trojan', 'ss', 'ssr', 'hysteria2', 'tuic']


def normalize_link(link: str) -> str:
    """Приводит ссылку к каноническому виду для дедупликации."""
    try:
        proto = link.split('://')[0].lower()
        if proto == 'vmess':
            b64 = link[8:]
            padding = 4 - (len(b64) % 4)
            if padding != 4:
                b64 += '=' * padding
            data = json.loads(base64.b64decode(b64).decode('utf-8'))
            return f"vmess://{data.get('add', '')}:{data.get('port', '')}@{data.get('id', '')}"
        elif proto in ('vless', 'trojan'):
            parsed = urlparse(link)
            return f"{proto}://{parsed.username}@{parsed.hostname}:{parsed.port}"
        elif proto == 'ss':
            parsed = urlparse(link)
            userinfo = parsed.username
            if userinfo:
                try:
                    decoded = base64.b64decode(userinfo).decode('utf-8')
                    method, password = decoded.split(':', 1)
                    return f"ss://{method}:{password}@{parsed.hostname}:{parsed.port}"
                except Exception:
                    pass
            return f"ss://{parsed.hostname}:{parsed.port}"
        else:
            return link
    except Exception:
        return link


def extract_host_port(link: str) -> Tuple[str, int]:
    """Извлекает хост и порт из прокси-ссылки."""
    try:
        proto = link.split('://')[0].lower()
        if proto == 'vmess':
            b
