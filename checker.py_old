#!/usr/bin/env python3
import re
import socket
import struct
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple
import time

TELEGRAM_URL = "https://t.me/s/freeproxysocks5"
TEST_URL = "http://httpbin.org/ip"
TIMEOUT = 8
MAX_WORKERS = 30

def fetch_proxies_from_telegram() -> List[str]:
    """Парсит прокси из Telegram канала (последние 10 сообщений)"""
    print(f"📡 Загрузка прокси из {TELEGRAM_URL}...")
    
    try:
        response = requests.get(TELEGRAM_URL, timeout=15)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Ищем все сообщения с прокси
        messages = soup.find_all('div', class_='tgme_widget_message_text')
        
        # Берем только последние 10 сообщений
        recent_messages = messages[-10:] if len(messages) > 10 else messages
        print(f"📝 Обработка последних {len(recent_messages)} сообщений...")
        
        proxies = []
        for msg in recent_messages:
            text = msg.get_text()
            # Паттерн для IP:PORT
            pattern = r'(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}'
            found = re.findall(pattern, text)
            proxies.extend(found)
        
        unique_proxies = list(set(proxies))
        print(f"✅ Найдено {len(unique_proxies)} уникальных прокси")
        return unique_proxies
    
    except Exception as e:
        print(f"❌ Ошибка загрузки: {e}")
        return []

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

def check_proxy(proxy: str) -> Tuple[str, bool, float]:
    """Проверяет работоспособность SOCKS5 прокси"""
    start_time = time.time()
    
    try:
        host, port = proxy.split(':')
        port = int(port)
        
        # Сначала проверяем SOCKS5 handshake
        if not check_socks5_handshake(host, port, TIMEOUT):
            elapsed = time.time() - start_time
            print(f"❌ {proxy} - Неверный SOCKS5 handshake ({elapsed:.1f}s)")
            return (proxy, False, elapsed)
        
        # Теперь полная проверка через requests
        proxies = {
            'http': f'socks5://{host}:{port}',
            'https': f'socks5://{host}:{port}'
        }
        
        response = requests.get(TEST_URL, proxies=proxies, timeout=TIMEOUT)
        elapsed = time.time() - start_time
        
        if response.status_code == 200:
            print(f"✅ {proxy} - Работает! ({elapsed:.1f}s)")
            return (proxy, True, elapsed)
        else:
            print(f"⚠️  {proxy} - HTTP {response.status_code} ({elapsed:.1f}s)")
            return (proxy, False, elapsed)
        
    except requests.exceptions.ProxyError:
        elapsed = time.time() - start_time
        print(f"❌ {proxy} - Ошибка прокси ({elapsed:.1f}s)")
    except requests.exceptions.Timeout:
        elapsed = time.time() - start_time
        print(f"⏱️  {proxy} - Таймаут ({elapsed:.1f}s)")
    except requests.exceptions.ConnectionError:
        elapsed = time.time() - start_time
        print(f"🔌 {proxy} - Нет соединения ({elapsed:.1f}s)")
    except Exception as e:
        elapsed = time.time() - start_time
        print(f"❓ {proxy} - {type(e).__name__} ({elapsed:.1f}s)")
    
    return (proxy, False, time.time() - start_time)

def main():
    print("=" * 70)
    print("🔍 SOCKS5 ПРОКСИ ЧЕКЕР")
    print("=" * 70)
    
    start_time = time.time()
    
    # Получаем прокси
    proxies = fetch_proxies_from_telegram()
    
    if not proxies:
        print("❌ Прокси не найдены!")
        return
    
    print(f"\n🎯 Найдено прокси: {len(proxies)}")
    print(f"⚙️  Потоков: {MAX_WORKERS}")
    print(f"⏱️  Таймаут: {TIMEOUT}s")
    print("-" * 70)
    
    valid_proxies = []
    checked = 0
    total_time = 0
    
    # Проверяем параллельно
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check_proxy, proxy): proxy for proxy in proxies}
        
        for future in as_completed(futures):
            proxy, is_valid, elapsed = future.result()
            checked += 1
            total_time += elapsed
            
            if is_valid:
                valid_proxies.append((proxy, elapsed))
            
            # Прогресс каждые 5 прокси
            if checked % 5 == 0 or checked == len(proxies):
                percent = (checked * 100) // len(proxies)
                avg_time = total_time / checked
                print(f"📊 [{percent:3d}%] {checked}/{len(proxies)} | ✅ Валидных: {len(valid_proxies)} | ⌀ {avg_time:.1f}s")
    
    # Сортируем по скорости
    valid_proxies.sort(key=lambda x: x[1])
    
    # Сохраняем результаты
    elapsed_total = time.time() - start_time
    print("-" * 70)
    print(f"✅ Валидных прокси: {len(valid_proxies)}/{len(proxies)} ({len(valid_proxies)*100//len(proxies) if proxies else 0}%)")
    print(f"⏱️  Общее время: {elapsed_total:.1f}s")
    
    with open('valid_proxies.txt', 'w', encoding='utf-8') as f:
        f.write(f"# Обновлено: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Валидных: {len(valid_proxies)}/{len(proxies)}\n")
        f.write(f"# Отсортировано по скорости\n\n")
        for proxy, speed in valid_proxies:
            f.write(f"{proxy}  # {speed:.1f}s\n")
    
    if valid_proxies:
        print(f"\n🚀 Самый быстрый: {valid_proxies[0][0]} ({valid_proxies[0][1]:.1f}s)")
    
    print(f"💾 Результаты сохранены в valid_proxies.txt")
    print("=" * 70)

if __name__ == "__main__":
    main()
