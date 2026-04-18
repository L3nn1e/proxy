#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Xeovo → Xray Config Converter (v2.1 Fix)
- Исправлена ошибка 'not all dependencies are resolved' (синхронизация тегов)
- Поддержка Hysteria2 для Xray-core (protocol: hysteria)
- Балансировщик leastPing, routeOnly sniffing
- Фильтр CN / Shadowsocks
"""
import json
import base64
import urllib.parse
import os
import sys
import argparse
import asyncio
import socket
import ssl

def get_tag(url: str) -> str:
    """Извлекает и декодирует название узла из URL."""
    if '#' in url:
        return urllib.parse.unquote(url.split('#')[-1])
    return "unknown_node"

def make_unique_tag(base_tag: str, used_tags: set) -> str:
    """Делает тег уникальным, добавляя суффикс при совпадении."""
    if base_tag not in used_tags:
        used_tags.add(base_tag)
        return base_tag
    counter = 1
    while f"{base_tag}-{counter}" in used_tags:
        counter += 1
    unique_tag = f"{base_tag}-{counter}"
    used_tags.add(unique_tag)
    return unique_tag

def parse_trojan(url: str) -> dict:
    tag = get_tag(url)
    parsed = urllib.parse.urlparse(url.split('#')[0])
    host, port = parsed.hostname, parsed.port
    password = parsed.username
    query = dict(urllib.parse.parse_qsl(parsed.query))
    
    net = query.get('type', 'tcp')
    sni = query.get('sni', host)
    ws_path = query.get('path', '/')
    ws_host = query.get('host', host)
    
    out = {
        "tag": tag,
        "protocol": "trojan",
        "settings": {
            "servers": [{"address": host, "port": port, "password": password}]
        },
        "streamSettings": {
            "network": net,
            "security": "tls",
            "tlsSettings": {"serverName": sni, "fingerprint": "chrome"}
        }
    }
    if net == 'ws':
        out["streamSettings"]["wsSettings"] = {"path": ws_path, "headers": {"Host": ws_host}}
    return out

def parse_vless(url: str) -> dict:
    tag = get_tag(url)
    parsed = urllib.parse.urlparse(url.split('#')[0])
    host, port = parsed.hostname, parsed.port
    uuid = parsed.username
    query = dict(urllib.parse.parse_qsl(parsed.query))
    
    net = query.get('type', 'tcp')
    sni = query.get('sni', host)
    ws_path = query.get('path', parsed.path.lstrip('/'))
    ws_host = query.get('host', host)
    security = query.get('security', 'tls')
    
    out = {
        "tag": tag,
        "protocol": "vless",
        "settings": {
            "vnext": [{"address": host, "port": port, "users": [{"id": uuid, "encryption": "none"}]}]
        },
        "streamSettings": {"network": net, "security": security}
    }
    if security == 'tls':
        out["streamSettings"]["tlsSettings"] = {"serverName": sni, "fingerprint": "chrome"}
    if net == 'ws':
        out["streamSettings"]["wsSettings"] = {"path": ws_path, "headers": {"Host": ws_host}}
    return out

def parse_vmess(url: str) -> dict:
    tag = get_tag(url)
    try:
        b64 = url.split('://')[1].strip()
        b64 += '=' * (4 - len(b64) % 4) if len(b64) % 4 != 0 else ''
        data = json.loads(base64.b64decode(b64).decode('utf-8'))
    except Exception:
        return None
        
    host, port = data['add'], int(data['port'])
    net, tls = data.get('net', 'tcp'), data.get('tls', 'none')
    sni = data.get('sni', host)
    ws_path = data.get('path', '/')
    ws_host = data.get('host', host)
    
    out = {
        "tag": tag,
        "protocol": "vmess",
        "settings": {
            "vnext": [{"address": host, "port": port, "users": [
                {"id": data['id'], "alterId": int(data.get('aid', 0)), "security": data.get('scy', 'auto')}
            ]}]
        },
        "streamSettings": {"network": net, "security": tls}
    }
    if tls == 'tls':
        out["streamSettings"]["tlsSettings"] = {"serverName": sni, "fingerprint": "chrome"}
    if net == 'ws':
        out["streamSettings"]["wsSettings"] = {"path": ws_path, "headers": {"Host": ws_host}}
    return out

def parse_hysteria2_for_xray(url: str) -> dict:
    """Парсит hysteria2:// для Xray-core (protocol: hysteria)."""
    tag = get_tag(url)
    parsed = urllib.parse.urlparse(url.split('#')[0])
    host, port = parsed.hostname, parsed.port
    auth = urllib.parse.unquote(parsed.username or '')
    query = dict(urllib.parse.parse_qsl(parsed.query))
    sni = query.get('sni', host)
    
    return {
        "tag": tag,
        "protocol": "hysteria",  # Важно: для Xray-core это "hysteria"
        "settings": {
            "version": 2,
            "address": host,
            "port": port,
            "auth": auth
        },
        "streamSettings": {
            "network": "hysteria",
            "security": "tls",
            "tlsSettings": {
                "serverName": sni,
                "fingerprint": "chrome",
                "alpn": ["h3"]
            },
            "hysteriaSettings": {
                "version": 2,
                "up": "100 mbps",
                "down": "100 mbps"
            }
        }
    }

async def check_reachability(host: str, port: int, is_udp: bool = False, timeout: float = 2.5) -> bool:
    """Проверяет доступность узла."""
    try:
        if is_udp:
            # Для Hysteria проверяем TCP как эвристику доступности хоста
            await asyncio.get_running_loop().run_in_executor(None, socket.create_connection, (host, port), timeout)
            return True
        else:
            # Для TCP/WS/TLS проверяем рукопожатие
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            r, w = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx), timeout=timeout
            )
            w.close()
            return True
    except Exception:
        return False

async def test_nodes(nodes_data: list, timeout: float = 2.5, max_concurrent: int = 30) -> list:
    """Асинхронно тестирует узлы и возвращает только рабочие outbound-ы."""
    sem = asyncio.Semaphore(max_concurrent)
    
    async def run_test(host, port, is_udp, outbound):
        async with sem:
            ok = await check_reachability(host, port, is_udp, timeout)
            return ok, outbound

    tasks = [run_test(*data) for data in nodes_data]
    results = await asyncio.gather(*tasks)
    return [out for ok, out in results if ok]

def main():
    parser = argparse.ArgumentParser(description="Xeovo → Xray config converter (v2.1 Fix)")
    parser.add_argument("-i", "--input", default="xeovo-any-URL_List_All_Protocols(2).txt")
    parser.add_argument("-o", "--output", default="xray_config.json")
    parser.add_argument("--test-timeout", type=float, default=2.5, help="Таймаут проверки (сек)")
    parser.add_argument("--no-test", action="store_true", help="Пропустить проверку доступности")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"❌ Файл {args.input} не найден"); sys.exit(1)

    with open(args.input, 'r', encoding='utf-8') as f:
        lines = [l.strip() for l in f if l.strip()]

    nodes_data = []  # (host, port, is_udp, outbound_dict)
    
    for line in lines:
        tag = get_tag(line)
        p = urllib.parse.urlparse(line)
        host = (p.hostname or "").lower()
        
        # 🔴 Фильтр CN
        if 'cn' in tag.lower() or 'cn' in host:
            continue
        # 🔴 Фильтр Shadowsocks
        if line.startswith('ss://'):
            continue
            
        try:
            if line.startswith('trojan://'):
                out = parse_trojan(line)
                nodes_data.append((out['settings']['servers'][0]['address'], out['settings']['servers'][0]['port'], False, out))
            elif line.startswith('vless://'):
                out = parse_vless(line)
                is_tls = out['streamSettings'].get('security') == 'tls'
                nodes_data.append((out['settings']['vnext'][0]['address'], out['settings']['vnext'][0]['port'], False, out))
            elif line.startswith('vmess://'):
                out = parse_vmess(line)
                if out is None: continue
                is_tls = out['streamSettings'].get('security') == 'tls'
                nodes_data.append((out['settings']['vnext'][0]['address'], out['settings']['vnext'][0]['port'], False, out))
            elif line.startswith('hysteria2://'):
                out = parse_hysteria2_for_xray(line)
                nodes_data.append((out['settings']['address'], out['settings']['port'], True, out))
        except Exception as e:
            print(f"⚠️ Ошибка парсинга [{tag}]: {e}")

    # 🧪 Проверка доступности
    print(f"📥 Загружено: {len(nodes_data)} узлов. Проверка...")
    if not args.no_test:
        passed_outbounds = asyncio.run(test_nodes(nodes_data, timeout=args.test_timeout))
        print(f"✅ Прошло проверку: {len(passed_outbounds)}")
    else:
        passed_outbounds = [data[3] for data in nodes_data]
        print("⏭️ Проверка пропущена")

    # 🔧 Исправление тегов и сборка финального списка
    final_outbounds = []
    used_tags = set()
    selector_tags = [] # Список тегов ТОЛЬКО для балансировщика (уже уникальных)

    for out in passed_outbounds:
        # Генерируем уникальный тег
        unique_tag = make_unique_tag(out["tag"], used_tags)
        
        # Записываем уникальный тег в outbound
        out["tag"] = unique_tag
        final_outbounds.append(out)
        
        # Добавляем этот же тег в список для балансировщика
        selector_tags.append(unique_tag)

    # Системные outbounds
    final_outbounds.append({
        "tag": "direct",
        "protocol": "freedom",
        "settings": {},
        "streamSettings": {"sockopt": {"domainStrategy": "UseIPv4", "tcpFastOpen": True, "tcpKeepAliveInterval": 15}}
    })
    final_outbounds.append({
        "tag": "block",
        "protocol": "blackhole",
        "settings": {"response": {"type": "http"}}
    })

    # 🛡️ Сборка конфига
    config = {
        "log": {"loglevel": "debug", "access": "", "error": ""},
        "inbounds": [
            {"tag": "socks-inbound", "port": 20808,
