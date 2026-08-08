#!/usr/bin/env bash

INTERFACE="xeovo-random"
CHECK_URL="http://api.ipify.org"
LOG_TAG="vpn-checker"

# Делаем запрос с таймаутом в 5 секунд
RESPONSE=$(curl -s -m 5 "$CHECK_URL" 2>&1)

# Проверяем на наличие текста блокировки Xeovo или ошибку соединения
if echo "$RESPONSE" | grep -qE "(BitTorrent is forbidden|access blocked|SSL routines)"; then
    logger -t "$LOG_TAG" "[WARNING] VPN $INTERFACE is blocked by provider. Rotating IP..."
    echo "[WARNING] VPN blocked. Rotating $INTERFACE..."
    
    # Перезапуск интерфейса AmneziaWG (замените awg-quick на wg-quick, если используете стандартный WireGuard)
    awg-quick down "$INTERFACE" && sleep 2 && awg-quick up "$INTERFACE"
    
    # Перезапуск 3proxy, чтобы он подхватил обновленный сетевой интерфейс
    systemctl restart 3proxy
    
    logger -t "$LOG_TAG" "[OK] Interface $INTERFACE restarted."
elif [[ -z "$RESPONSE" ]]; then
    logger -t "$LOG_TAG" "[ERROR] No response from $CHECK_URL. Restarting $INTERFACE..."
    awg-quick down "$INTERFACE" && sleep 2 && awg-quick up "$INTERFACE"
    systemctl restart 3proxy
else
    # Всё работает штатно
    echo "[OK] VPN is working fine. Public IP: $RESPONSE"
fi
