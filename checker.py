#!/usr/bin/env python3
import re
import socket
import socks
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

TELEGRAM_URL = "https://t.me/s/freeproxysocks5"
TEST_URL = "http://httpbin.org/ip"
TIMEOUT = 10
MAX_WORKERS = 50

def fetch_proxies_from_telegram() -> List[str]:
    """Парсит прокси из Telegram канала"""
    print(f"Fetching proxies from {TELEGRAM_URL}...")
    
    try:
        response = requests.get(TELEGRAM_URL, timeout=15)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Ищем все сообщения с прокси
        messages = soup.find_all('div', class_='tgme_widget_message_text')
        proxies = []
        
        for msg in messages:
            text = msg.get_text()
            # Паттерн для IP:PORT
            pattern = r'(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}'
            found = re.findall(pattern, text)
            proxies.extend(found)
        
        unique_proxies = list(set(proxies))
        print(f"Found {len(unique_proxies)} unique proxies")
        return unique_proxies
    
    except Exception as e:
        print(f"Error fetching proxies: {e}")
        return []

def check_proxy(proxy: str) -> Tuple[str, bool]:
    """Проверяет работоспособность SOCKS5 прокси"""
    try:
        host, port = proxy.split(':')
        port = int(port)
        
        # Настраиваем SOCKS5
        socks.set_default_proxy(socks.SOCKS5, host, port)
        socket.socket = socks.socksocket
        
        # Тестируем запрос
        response = requests.get(TEST_URL, timeout=TIMEOUT)
        
        # Сбрасываем настройки
        socket.socket = socket._socketobject
        
        if response.status_code == 200:
            print(f"✓ VALID: {proxy}")
            return (proxy, True)
        
    except Exception as e:
        print(f"✗ FAILED: {proxy} - {type(e).__name__}")
    
    finally:
        # Всегда сбрасываем сокет
        socket.socket = socket._socketobject
    
    return (proxy, False)

def main():
    print("=" * 60)
    print("SOCKS5 Proxy Checker")
    print("=" * 60)
    
    # Получаем прокси
    proxies = fetch_proxies_from_telegram()
    
    if not proxies:
        print("❌ No proxies found!")
        return
    
    print(f"\n🔍 Checking {len(proxies)} proxies with {MAX_WORKERS} workers...")
    print(f"⏱️  Timeout: {TIMEOUT}s per proxy")
    print("-" * 60)
    
    valid_proxies = []
    checked = 0
    
    # Проверяем параллельно
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check_proxy, proxy): proxy for proxy in proxies}
        
        for future in as_completed(futures):
            proxy, is_valid = future.result()
            checked += 1
            
            if is_valid:
                valid_proxies.append(proxy)
            
            # Прогресс
            if checked % 10 == 0 or checked == len(proxies):
                print(f"📊 Progress: {checked}/{len(proxies)} | Valid: {len(valid_proxies)}")
    
    # Сохраняем результаты
    print("-" * 60)
    print(f"✅ Valid proxies: {len(valid_proxies)}/{len(proxies)} ({len(valid_proxies)*100//len(proxies) if proxies else 0}%)")
    
    with open('valid_proxies.txt', 'w') as f:
        f.write(f"# Updated: {__import__('datetime').datetime.now().isoformat()}\n")
        f.write(f"# Valid: {len(valid_proxies)}/{len(proxies)}\n\n")
        for proxy in sorted(valid_proxies):
            f.write(f"{proxy}\n")
    
    print(f"💾 Results saved to valid_proxies.txt")
    print("=" * 60)

if __name__ == "__main__":
    main()
