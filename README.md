# SOCKS5 Proxy Checker

Автоматический чекер валидных SOCKS5 прокси на GitHub Actions.

## Источник прокси
https://t.me/s/freeproxysocks5

## Как использовать

1. Fork этот репозиторий
2. Включите GitHub Actions в настройках репозитория
3. Прокси будут проверяться автоматически каждые 6 часов
4. Валидные прокси сохраняются в `valid_proxies.txt`

## Ручной запуск

Actions → SOCKS5 Proxy Checker → Run workflow

## Локальный запуск

```bash
pip install requests pysocks beautifulsoup4
python checker.py
```

## Результаты

Валидные прокси: [valid_proxies.txt](valid_proxies.txt)
