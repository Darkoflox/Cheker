#!/usr/bin/env python3
"""
Универсальный чекер прокси-конфигураций с автоочисткой дубликатов и нерабочих ссылок.
Использует Xray-core для реальной проверки соединения.

Использование:
    python checker.py --input файл_с_конфигами.txt --output результат.txt [--max-ping 800] [--threads 10]
"""
import os
import sys
import json
import base64
import subprocess
import tempfile
import time
import argparse
import threading
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, unquote
from typing import List, Dict, Optional, Tuple, Set
import logging
import platform

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Поддерживаемые протоколы и их обработчики
SUPPORTED_PROTOCOLS = ['vmess', 'vless', 'trojan', 'ss']

# URL для скачивания Xray-core (последняя версия)
XRAY_DOWNLOAD_URLS = {
    'linux-amd64': 'https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip',
    'darwin-amd64': 'https://github.com/XTLS/Xray-core/releases/latest/download/Xray-macos-64.zip',
    'darwin-arm64': 'https://github.com/XTLS/Xray-core/releases/latest/download/Xray-macos-arm64-v8a.zip',
    'windows-amd64': 'https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip',
}

class ConfigChecker:
    def __init__(self, max_ping: int = 800, threads: int = 10):
        self.max_ping = max_ping
        self.threads = threads
        self.xray_path = self._ensure_xray()
        self.lock = threading.Lock()
        self.working_configs = []
        self.failed_configs = []

    def _get_platform(self) -> str:
        """Определяет текущую платформу для скачивания Xray."""
        system = platform.system().lower()
        machine = platform.machine().lower()
        if system == 'linux':
            return 'linux-amd64'
        elif system == 'darwin':
            if 'arm' in machine:
                return 'darwin-arm64'
            return 'darwin-amd64'
        elif system == 'windows':
            return 'windows-amd64'
        else:
            raise RuntimeError(f"Неподдерживаемая платформа: {system}")

    def _ensure_xray(self) -> str:
        """Проверяет наличие Xray, при необходимости скачивает."""
        xray_bin = 'xray'
        if platform.system().lower() == 'windows':
            xray_bin += '.exe'

        # Если Xray уже есть в текущей папке, используем его
        if os.path.exists(xray_bin):
            logger.info(f"✅ Найден Xray: {xray_bin}")
            return os.path.abspath(xray_bin)

        logger.info("📥 Xray не найден, скачиваем...")
        platform_key = self._get_platform()
        url = XRAY_DOWNLOAD_URLS.get(platform_key)
        if not url:
            raise RuntimeError(f"Нет URL для платформы {platform_key}")

        zip_path = 'xray.zip'
        try:
            urllib.request.urlretrieve(url, zip_path)
        except Exception as e:
            raise RuntimeError(f"Не удалось скачать Xray: {e}")

        # Распаковываем
        import zipfile
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for member in zf.namelist():
                if member.endswith(xray_bin):
                    # Извлекаем только бинарник
                    source = zf.open(member)
                    target_path = xray_bin
                    with open(target_path, 'wb') as f:
                        f.write(source.read())
                    os.chmod(target_path, 0o755)
                    break
        os.remove(zip_path)
        logger.info(f"✅ Xray установлен: {xray_bin}")
        return os.path.abspath(xray_bin)

    def normalize_link(self, link: str) -> str:
        """
        Нормализует ссылку для дедупликации.
        Для vmess: vmess://add:port@uuid
        Для vless/trojan: protocol://uuid@host:port
        Для ss: ss://method:password@host:port
        """
        try:
            proto = link.split('://')[0].lower()
            if proto == 'vmess':
                b64 = link[8:]
                # Добавляем padding
                padding = 4 - (len(b64) % 4)
                if padding != 4:
                    b64 += '=' * padding
                decoded = base64.b64decode(b64).decode('utf-8')
                data = json.loads(decoded)
                return f"vmess://{data.get('add', '')}:{data.get('port', '')}@{data.get('id', '')}"
            elif proto in ('vless', 'trojan'):
                parsed = urlparse(link)
                return f"{proto}://{parsed.username}@{parsed.hostname}:{parsed.port}"
            elif proto == 'ss':
                parsed = urlparse(link)
                userinfo = parsed.username
                if userinfo:
                    # Декодируем Base64 userinfo (method:password)
                    try:
                        decoded = base64.b64decode(userinfo).decode('utf-8')
                        method, password = decoded.split(':', 1)
                        return f"ss://{method}:{password}@{parsed.hostname}:{parsed.port}"
                    except:
                        pass
                return f"ss://{parsed.hostname}:{parsed.port}"
            else:
                return link
        except Exception:
            return link

    def deduplicate(self, links: List[str]) -> List[str]:
        """Удаляет дубликаты, сохраняя оригинальные строки."""
        seen = set()
        unique_links = []
        for link in links:
            norm = self.normalize_link(link.strip())
            if norm not in seen:
                seen.add(norm)
                unique_links.append(link.strip())
        logger.info(f"🧹 Удалено дубликатов: {len(links) - len(unique_links)}")
        return unique_links

    def generate_xray_config(self, link: str, port: int) -> Optional[Dict]:
        """
        Преобразует прокси-ссылку в конфигурацию Xray (исходящее соединение).
        Возвращает словарь с inbounds (socks5 на localhost:port) и outbounds.
        """
        proto = link.split('://')[0].lower()
        outbound = None

        try:
            if proto == 'vmess':
                b64 = link[8:]
                padding = 4 - (len(b64) % 4)
                if padding != 4:
                    b64 += '=' * padding
                decoded = base64.b64decode(b64).decode('utf-8')
                data = json.loads(decoded)
                outbound = {
                    "protocol": "vmess",
                    "settings": {
                        "vnext": [{
                            "address": data['add'],
                            "port": int(data['port']),
                            "users": [{
                                "id": data['id'],
                                "alterId": int(data.get('aid', 0)),
                                "security": data.get('scy', 'auto')
                            }]
                        }]
                    },
                    "streamSettings": self._build_stream_settings(data)
                }
            elif proto == 'vless':
                parsed = urlparse(link)
                uuid = parsed.username
                params = parse_qs(parsed.query)
                outbound = {
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": parsed.hostname,
                            "port": parsed.port,
                            "users": [{
                                "id": uuid,
                                "encryption": params.get('encryption', ['none'])[0],
                                "flow": params.get('flow', [''])[0]
                            }]
                        }]
                    },
                    "streamSettings": self._build_stream_settings_from_params(parsed, params)
                }
            elif proto == 'trojan':
                parsed = urlparse(link)
                password = parsed.username
                params = parse_qs(parsed.query)
                outbound = {
                    "protocol": "trojan",
                    "settings": {
                        "servers": [{
                            "address": parsed.hostname,
                            "port": parsed.port,
                            "password": password
                        }]
                    },
                    "streamSettings": self._build_stream_settings_from_params(parsed, params)
                }
            elif proto == 'ss':
                parsed = urlparse(link)
                userinfo = parsed.username
                if userinfo:
                    decoded = base64.b64decode(userinfo).decode('utf-8')
                    method, password = decoded.split(':', 1)
                else:
                    # Некоторые ss ссылки без userinfo
                    raise ValueError("Неверный формат ss ссылки")
                outbound = {
                    "protocol": "shadowsocks",
                    "settings": {
                        "servers": [{
                            "address": parsed.hostname,
                            "port": parsed.port,
                            "method": method,
                            "password": password
                        }]
                    }
                }
            else:
                logger.warning(f"⚠️ Неподдерживаемый протокол: {proto}")
                return None
        except Exception as e:
            logger.debug(f"❌ Ошибка парсинга {link}: {e}")
            return None

        if outbound is None:
            return None

        # Добавляем streamSettings для trojan/vless, если есть transport
        # (для vmess уже добавлено)
        if proto in ('vless', 'trojan') and 'streamSettings' not in outbound:
            outbound['streamSettings'] = self._build_stream_settings_from_params(parsed, params)

        config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "socks",
                "settings": {"udp": True}
            }],
            "outbounds": [outbound]
        }
        return config

    def _build_stream_settings(self, data: Dict) -> Dict:
        """Создаёт streamSettings для vmess."""
        net = data.get('net', 'tcp')
        stream = {"network": net, "security": data.get('tls', '')}
        if net == 'ws':
            stream["wsSettings"] = {
                "path": data.get('path', '/'),
                "headers": {"Host": data.get('host', '')}
            }
        elif net == 'grpc':
            stream["grpcSettings"] = {"serviceName": data.get('path', '')}
        elif net == 'tcp' and data.get('type') == 'http':
            stream["tcpSettings"] = {
                "header": {
                    "type": "http",
                    "request": {
                        "path": data.get('path', '/'),
                        "headers": {"Host": data.get('host', '')}
                    }
                }
            }
        return stream

    def _build_stream_settings_from_params(self, parsed, params: Dict) -> Dict:
        """Создаёт streamSettings из параметров URL (для vless/trojan)."""
        stream = {"network": "tcp", "security": "none"}
        # Определяем транспорт
        if 'type' in params:
            net = params['type'][0]
            stream["network"] = net
        if 'security' in params:
            stream["security"] = params['security'][0]
        if 'sni' in params:
            stream["sni"] = params['sni'][0]

        if stream["network"] == "ws":
            ws = {}
            if 'path' in params:
                ws["path"] = params['path'][0]
            if 'host' in params:
                ws["headers"] = {"Host": params['host'][0]}
            stream["wsSettings"] = ws
        elif stream["network"] == "grpc":
            grpc = {}
            if 'serviceName' in params:
                grpc["serviceName"] = params['serviceName'][0]
            stream["grpcSettings"] = grpc
        return stream

    def test_config(self, link: str, timeout: int = 10) -> Tuple[bool, float]:
        """
        Проверяет конфигурацию: запускает Xray с SOCKS5 прокси,
        затем через него выполняет HTTP-запрос к http://cp.cloudflare.com/ (или другой).
        Возвращает (успех, задержка в мс).
        """
        port = self._find_free_port()
        config = self.generate_xray_config(link, port)
        if config is None:
            return False, 0.0

        # Записываем временный конфиг
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config, f)
            config_path = f.name

        xray_process = None
        try:
            # Запускаем Xray
            xray_process = subprocess.Popen(
                [self.xray_path, 'run', '-c', config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            # Даём время на запуск
            time.sleep(1.5)

            # Настраиваем прокси для urllib
            proxy_handler = urllib.request.ProxyHandler({
                'http': f'socks5://127.0.0.1:{port}',
                'https': f'socks5://127.0.0.1:{port}'
            })
            opener = urllib.request.build_opener(proxy_handler)

            start = time.time()
            # Пробуем получить тестовую страницу
            req = urllib.request.Request('http://cp.cloudflare.com/', headers={'User-Agent': 'Mozilla/5.0'})
            with opener.open(req, timeout=timeout) as response:
                if response.status == 204 or response.status == 200:
                    latency = (time.time() - start) * 1000
                    return True, latency
            return False, 0.0

        except Exception as e:
            logger.debug(f"Ошибка проверки {link}: {e}")
            return False, 0.0
        finally:
            if xray_process:
                xray_process.terminate()
                try:
                    xray_process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    xray_process.kill()
            # Удаляем временный конфиг
            try:
                os.unlink(config_path)
            except:
                pass

    def _find_free_port(self) -> int:
        """Находит свободный порт на localhost."""
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', 0))
            return s.getsockname()[1]

    def check_batch(self, links: List[str]) -> List[str]:
        """
        Проверяет список ссылок в многопоточном режиме.
        Возвращает только рабочие ссылки.
        """
        working = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_link = {executor.submit(self.test_config, link): link for link in links}
            for future in as_completed(future_to_link):
                link = future_to_link[future]
                try:
                    success, latency = future.result()
                    if success and latency <= self.max_ping:
                        with self.lock:
                            working.append(link)
                            logger.info(f"✅ {link[:50]}... (ping: {latency:.0f}ms)")
                    else:
                        logger.debug(f"❌ {link[:50]}... (failed or slow)")
                except Exception as e:
                    logger.debug(f"❌ Ошибка при проверке {link}: {e}")
        return working

def main():
    parser = argparse.ArgumentParser(description='Проверка прокси-конфигураций с автоочисткой.')
    parser.add_argument('--input', required=True, help='Входной файл со ссылками')
    parser.add_argument('--output', default='working_configs.txt', help='Выходной файл с рабочими ссылками')
    parser.add_argument('--max-ping', type=int, default=800, help='Максимальный допустимый пинг (мс)')
    parser.add_argument('--threads', type=int, default=10, help='Количество потоков')
    args = parser.parse_args()

    # Чтение входного файла
    if not os.path.exists(args.input):
        logger.error(f"Файл {args.input} не найден")
        sys.exit(1)

    with open(args.input, 'r', encoding='utf-8') as f:
        raw_links = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    logger.info(f"📂 Загружено {len(raw_links)} ссылок из {args.input}")

    checker = ConfigChecker(max_ping=args.max_ping, threads=args.threads)

    # Дедупликация
    unique_links = checker.deduplicate(raw_links)
    logger.info(f"🔍 Уникальных ссылок после дедупликации: {len(unique_links)}")

    # Проверка
    logger.info("🚀 Начинаем проверку...")
    working_links = checker.check_batch(unique_links)
    logger.info(f"✅ Проверка завершена. Рабочих ссылок: {len(working_links)}")

    # Сохранение результата
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write('\n'.join(working_links))
    logger.info(f"💾 Результат сохранён в {args.output}")

if __name__ == '__main__':
    main()
