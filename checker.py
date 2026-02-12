#!/usr/bin/env python3
import re
import socket
import struct
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple
import time

PROXY_SOURCE = "https://proxymania.su/free-proxy"
PAGES_TO_PARSE = 10
TEST_URL = "http://httpbin.org/ip"
TIMEOUT = 8
MAX_WORKERS = 30

def fetch_proxies_from_proxymania() -> List[Tuple[str, str]]:
    """Парсит все типы прокси с proxymania.su (первые 10 страниц)"""
    print(f"📡 Загрузка прокси с {PROXY_SOURCE}...")
    
    all_proxies = []
    
    for page in range(1, PAGES_TO_PARSE + 1):
        try:
            url = f"{PROXY_SOURCE}?page={page}"
            print(f"📄 Страница {page}/{PAGES_TO_PARSE}...", end=" ")
            
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Ищем строки таблицы с прокси
            rows = soup.find_all('tr')
            page_proxies = 0
            
            for row in rows:
                cells = row.find_all('td')
                if len(cells) >= 3:
                    # Первая ячейка - IP:PORT
                    proxy_text = cells[0].get_text(strip=True)
                    # Третья ячейка - тип (HTTPS, SOCKS5, etc)
                    proxy_type = cells[2].get_text(strip=True)
                    
                    # Берем все типы прокси
                    if ':' in proxy_text and proxy_type in ['HTTP', 'HTTPS', 'SOCKS4', 'SOCKS5']:
                        all_proxies.append((proxy_text, proxy_type))
                        page_proxies += 1
            
            print(f"✅ Найдено {page_proxies} прокси")
            time.sleep(0.5)  # Небольшая задержка между запросами
            
        except Exception as e:
            print(f"❌ Ошибка: {e}")
            continue
    
    # Подсчитываем по типам
    types_count = {}
    for _, ptype in all_proxies:
        types_count[ptype] = types_count.get(ptype, 0) + 1
    
    print(f"\n✅ Всего прокси: {len(all_proxies)}")
    for ptype, count in sorted(types_count.items()):
        print(f"   {ptype}: {count}")
    
    return all_proxies

def check_socks5_handshake(host: str, port: int, timeout: int = 5) -> bool:
    """Проверяет SOCKS5 handshake напрямую"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # SOCKS5 greeting
        sock.sendall(b'\x05\x01\x00')
        response = sock.recv(2)
        
        if len(response) != 2 or response[0] != 0x05:
            sock.close()
            return False
        
        # CONNECT request к httpbin.org:80
        request = b'\x05\x01\x00\x03'
        domain = b'httpbin.org'
        request += bytes([len(domain)]) + domain
        request += struct.pack('>H', 80)
        
        sock.sendall(request)
        response = sock.recv(10)
        
        sock.close()
        
        # Проверяем успешный ответ
        return len(response) >= 2 and response[1] == 0x00
        
    except Exception:
        return False

def check_socks4_handshake(host: str, port: int, timeout: int = 5) -> bool:
    """Проверяет SOCKS4 handshake напрямую"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # SOCKS4 CONNECT request
        request = b'\x04\x01'  # Version 4, CONNECT
        request += struct.pack('>H', 80)  # Port 80
        request += socket.inet_aton('1.1.1.1')  # IP
        request += b'\x00'  # NULL terminator
        
        sock.sendall(request)
        response = sock.recv(8)
        
        sock.close()
        
        # Проверяем успешный ответ (0x5A = granted)
        return len(response) >= 2 and response[1] == 0x5A
        
    except Exception:
        return False

def check_proxy(proxy: str, proxy_type: str) -> Tuple[str, str, bool, float]:
    """Проверяет работоспособность прокси"""
    start_time = time.time()
    
    try:
        host, port = proxy.split(':')
        port = int(port)
        
        # Проверяем в зависимости от типа
        if proxy_type == 'SOCKS5':
            if not check_socks5_handshake(host, port, TIMEOUT):
                elapsed = time.time() - start_time
                print(f"❌ [{proxy_type}] {proxy} - Неверный handshake ({elapsed:.1f}s)")
                return (proxy, proxy_type, False, elapsed)
            
            proxies = {
                'http': f'socks5://{host}:{port}',
                'https': f'socks5://{host}:{port}'
            }
        
        elif proxy_type == 'SOCKS4':
            if not check_socks4_handshake(host, port, TIMEOUT):
                elapsed = time.time() - start_time
                print(f"❌ [{proxy_type}] {proxy} - Неверный handshake ({elapsed:.1f}s)")
                return (proxy, proxy_type, False, elapsed)
            
            proxies = {
                'http': f'socks4://{host}:{port}',
                'https': f'socks4://{host}:{port}'
            }
        
        elif proxy_type in ['HTTP', 'HTTPS']:
            proxies = {
                'http': f'http://{host}:{port}',
                'https': f'http://{host}:{port}'
            }
        
        else:
            return (proxy, proxy_type, False, 0)
        
        # Полная проверка через HTTP запрос
        response = requests.get(TEST_URL, proxies=proxies, timeout=TIMEOUT)
        elapsed = time.time() - start_time
        
        if response.status_code == 200:
            print(f"✅ [{proxy_type}] {proxy} - Работает! ({elapsed:.1f}s)")
            return (proxy, proxy_type, True, elapsed)
        else:
            print(f"⚠️  [{proxy_type}] {proxy} - HTTP {response.status_code} ({elapsed:.1f}s)")
            return (proxy, proxy_type, False, elapsed)
        
    except requests.exceptions.ProxyError:
        elapsed = time.time() - start_time
        print(f"❌ [{proxy_type}] {proxy} - Ошибка прокси ({elapsed:.1f}s)")
    except requests.exceptions.Timeout:
        elapsed = time.time() - start_time
        print(f"⏱️  [{proxy_type}] {proxy} - Таймаут ({elapsed:.1f}s)")
    except requests.exceptions.ConnectionError:
        elapsed = time.time() - start_time
        print(f"🔌 [{proxy_type}] {proxy} - Нет соединения ({elapsed:.1f}s)")
    except Exception as e:
        elapsed = time.time() - start_time
        print(f"❓ [{proxy_type}] {proxy} - {type(e).__name__} ({elapsed:.1f}s)")
    
    return (proxy, proxy_type, False, time.time() - start_time)

def main():
    print("=" * 70)
    print("🔍 ПРОКСИ ЧЕКЕР (HTTP/HTTPS/SOCKS4/SOCKS5)")
    print("=" * 70)
    
    start_time = time.time()
    
    # Получаем прокси
    proxies = fetch_proxies_from_proxymania()
    
    if not proxies:
        print("❌ Прокси не найдены!")
        return
    
    print(f"\n🎯 Всего прокси: {len(proxies)}")
    print(f"⚙️  Потоков: {MAX_WORKERS}")
    print(f"⏱️  Таймаут: {TIMEOUT}s")
    print("-" * 70)
    
    valid_proxies = []
    checked = 0
    total_time = 0
    
    # Проверяем параллельно
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check_proxy, proxy, ptype): (proxy, ptype) for proxy, ptype in proxies}
        
        for future in as_completed(futures):
            proxy, ptype, is_valid, elapsed = future.result()
            checked += 1
            total_time += elapsed
            
            if is_valid:
                valid_proxies.append((proxy, ptype, elapsed))
            
            # Прогресс каждые 5 прокси
            if checked % 5 == 0 or checked == len(proxies):
                percent = (checked * 100) // len(proxies)
                avg_time = total_time / checked
                print(f"📊 [{percent:3d}%] {checked}/{len(proxies)} | ✅ Валидных: {len(valid_proxies)} | ⌀ {avg_time:.1f}s")
    
    # Группируем по типам
    proxies_by_type = {}
    for proxy, ptype, speed in valid_proxies:
        if ptype not in proxies_by_type:
            proxies_by_type[ptype] = []
        proxies_by_type[ptype].append((proxy, speed))
    
    # Сортируем каждый тип по скорости
    for ptype in proxies_by_type:
        proxies_by_type[ptype].sort(key=lambda x: x[1])
    
    # Сохраняем результаты
    elapsed_total = time.time() - start_time
    print("-" * 70)
    print(f"✅ Валидных прокси: {len(valid_proxies)}/{len(proxies)} ({len(valid_proxies)*100//len(proxies) if proxies else 0}%)")
    print(f"⏱️  Общее время: {elapsed_total:.1f}s")
    
    with open('valid_proxies.txt', 'w', encoding='utf-8') as f:
        f.write(f"# Источник: {PROXY_SOURCE}\n")
        f.write(f"# Обновлено: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Валидных: {len(valid_proxies)}/{len(proxies)}\n")
        f.write(f"# Отсортировано по типу и скорости\n\n")
        
        for ptype in sorted(proxies_by_type.keys()):
            f.write(f"# ===== {ptype} ({len(proxies_by_type[ptype])}) =====\n")
            for proxy, speed in proxies_by_type[ptype]:
                f.write(f"{proxy}  # {speed:.1f}s\n")
            f.write(f"\n")
    
    # Показываем статистику по типам
    print("\n📈 Статистика по типам:")
    for ptype in sorted(proxies_by_type.keys()):
        count = len(proxies_by_type[ptype])
        fastest = proxies_by_type[ptype][0]
        print(f"   {ptype}: {count} шт. | Самый быстрый: {fastest[0]} ({fastest[1]:.1f}s)")
    
    print(f"\n💾 Результаты сохранены в valid_proxies.txt")
    print("=" * 70)

if __name__ == "__main__":
    main()
