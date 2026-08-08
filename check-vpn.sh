#!/usr/bin/env bash

INTERFACE="xeovo-random"
VPN_SERVICE="awg-quick@xeovo-random.service"
CHECK_URL="http://api.ipify.org"

# 1. Проверяем, запущен ли systemd-юнит и существует ли интерфейс
if ! systemctl is-active --quiet "$VPN_SERVICE" || ! ip link show "$INTERFACE" >/dev/null 2>&1; then
    echo "[ERROR] Service $VPN_SERVICE is stopped or interface is down. Restarting via systemd..."
    systemctl restart "$VPN_SERVICE"
    systemctl restart 3proxy
    exit 0
fi

# 2. Делаем запрос СТРОГО через VPN-интерфейс
RESPONSE=$(curl -s -m 5 --interface "$INTERFACE" "$CHECK_URL" 2>&1)

# 3. Проверяем на бан от Xeovo или SSL-ошибку
if echo "$RESPONSE" | grep -qE "(BitTorrent is forbidden|access blocked|SSL routines)"; then
    echo "[WARNING] VPN blocked by Xeovo. Rotating IP via systemd restart..."
    systemctl restart "$VPN_SERVICE"
    systemctl restart 3proxy

# 4. Проверяем таймаут или отсутствие связи
elif [[ -z "$RESPONSE" ]] || echo "$RESPONSE" | grep -qE "(Could not resolve|Failed to connect)"; then
    echo "[ERROR] No connectivity via $INTERFACE. Restarting via systemd..."
    systemctl restart "$VPN_SERVICE"
    systemctl restart 3proxy
else
    echo "[OK] VPN is working fine. Public IP: $RESPONSE"
fi
