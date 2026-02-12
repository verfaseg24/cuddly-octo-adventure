# Proxy Checker (HTTP/HTTPS/SOCKS4/SOCKS5)

Автоматический чекер валидных прокси всех типов на GitHub Actions.

## Источник прокси
https://proxymania.su/free-proxy (первые 10 страниц)

## Поддерживаемые типы
- HTTP
- HTTPS
- SOCKS4
- SOCKS5

## Как использовать

1. Fork этот репозиторий
2. Включите GitHub Actions в настройках репозитория
3. Прокси будут проверяться автоматически каждые 6 часов
4. Валидные прокси сохраняются в `valid_proxies.txt` (разделены по типам)

## Ручной запуск

Actions → Proxy Checker → Run workflow

## Локальный запуск

```bash
pip install requests beautifulsoup4
python checker.py
```

## Результаты

Валидные прокси: [valid_proxies.txt](valid_proxies.txt)
