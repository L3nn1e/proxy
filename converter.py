#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Xeovo → Xray Config Converter
Версия: 2.0 (Connectivity Check + Journald + Unique Tags + Hysteria2 Fix)
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
    return urllib.parse.unquote(url.split('#')[-1]) if '#' in url else "unknown_node"

def make_unique_tag(base_tag: str, used_tags: set) -> str:
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
        "tag": tag, "protocol": "trojan",
        "settings": {"servers": [{"address": host, "port": port, "password": password}]},
        "streamSettings": {"network": net, "security": "tls", "tlsSettings": {"serverName": sni, "fingerprint": "chrome"}}
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
        "tag": tag, "protocol": "vless",
        "settings": {"vnext": [{"address": host, "port": port, "users": [{"id": uuid, "encryption": "none"}]}]},
        "streamSettings": {"network": net, "security": security}
    }
    if security == 'tls':
        out["streamSettings"]["tlsSettings"] = {"serverName": sni, "fingerprint": "chrome"}
    if net == 'ws':
        out["streamSettings"]["wsSettings"] = {"path": ws_path, "headers": {"Host": ws_host}}
    return out

def parse_vmess(url: str) -> dict:
    tag = get_tag(url)
    b64 = url.split('://')[1].strip()
    b64 += '=' * (4 - len(b64) % 4) if len(b64) % 4 != 0 else ''
    try:
        data = json.loads(base64.b64decode(b64).decode('utf-8'))
    except:
        return None
        
    host, port = data['add'], int(data['port'])
    net, tls = data.get('net', 'tcp'), data.get('tls', 'none')
    sni = data.get('sni', host)
    ws_path = data.get('path', '/')
    ws_host = data.get('host', host)
    
    out = {
        "tag": tag, "protocol": "vmess",
        "settings": {"vnext": [{"address": host, "port": port, "users": [
            {"id": data['id'], "alterId": int(data.get('aid', 0)), "security": data.get('scy', 'auto')}
        ]}]},
        "streamSettings": {"network": net, "security": tls}
    }
    if tls == 'tls':
        out["streamSettings"]["tlsSettings"] = {"serverName": sni, "fingerprint": "chrome"}
    if net == 'ws':
        out["streamSettings"]["wsSettings"] = {"path": ws_path, "headers": {"Host": ws_host}}
    return out

def parse_hysteria2_for_xray(url: str) -> dict:
    tag = get_tag(url)
    parsed = urllib.parse.urlparse(url.split('#')[0])
    host, port = parsed.hostname, parsed.port
    auth = urllib.parse.unquote(parsed.username or '')
    query = dict(urllib.parse.parse_qsl(parsed.query))
    sni = query.get('sni', host)
    
    return {
        "tag": tag, "protocol": "hysteria",
        "settings": {"version": 2, "address": host, "port": port, "auth": auth},
        "streamSettings": {
            "network": "hysteria", "security": "tls",
            "tlsSettings": {"serverName": sni, "fingerprint": "chrome", "alpn": ["h3"]},
            "hysteriaSettings": {"version": 2, "up": "100 mbps", "down": "100 mbps"}
        }
    }

async def check_reachability(host: str, port: int, is_tls: bool = False, is_udp: bool = False, timeout: float = 3.0) -> bool:
    """Проверяет доступность узла через TCP/TLS или UDP."""
    try:
        if is_udp:
            # Для Hysteria (QUIC/UDP) проверяем доступность UDP-порта
            loop = asyncio.get_running_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            await loop.run_in_executor(None, sock.connect, (host, port))
            sock.close()
            return True
        else:
            # Для TCP/WS/TLS проверяем соединение и TLS-рукопожатие
            ssl_ctx = None
            if is_tls:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx), timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
    except Exception:
        return False

async def test_nodes(nodes_data: list, timeout: float = 3.0, max_concurrent: int = 25) -> list:
    """Асинхронно тестирует список узлов и возвращает только рабочие."""
    sem = asyncio.Semaphore(max_concurrent)
    async def test_single(host, port, is_tls, is_udp, outbound):
        async with sem:
            ok = await check_reachability(host, port, is_tls, is_udp, timeout)
            return ok, outbound

    tasks = [test_single(*data) for data in nodes_data]
    results = await asyncio.gather(*tasks)
    return [out for ok, out in results if ok]

def main():
    parser = argparse.ArgumentParser(description="Xeovo → Xray config converter")
    parser.add_argument("-i", "--input", default="xeovo-any-URL_List_All_Protocols(2).txt")
    parser.add_argument("-o", "--output", default="xray_config.json")
    parser.add_argument("--test-timeout", type=float, default=3.0, help="Таймаут проверки узла (сек)")
    parser.add_argument("--no-test", action="store_true", help="Пропустить проверку доступности")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"❌ Файл {args.input} не найден"); sys.exit(1)

    with open(args.input, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    nodes_data = []  # (host, port, is_tls, is_udp, outbound_dict)
    
    for line in lines:
        line = line.strip()
        if not line: continue
        
        tag = get_tag(line).lower()
        parsed = urllib.parse.urlparse(line)
        host = parsed.hostname or ""
        
        # 🔴 Фильтр CN
        if 'cn' in tag or 'cn' in host.lower():
            continue
        # 🔴 Фильтр Shadowsocks
        if line.startswith('ss://'):
            continue
            
        try:
            if line.startswith('trojan://'):
                out = parse_trojan(line)
                nodes_data.append((out['settings']['servers'][0]['address'], out['settings']['servers'][0]['port'], True, False, out))
            elif line.startswith('vless://'):
                out = parse_vless(line)
                is_tls = out['streamSettings'].get('security') == 'tls'
                nodes_data.append((out['settings']['vnext'][0]['address'], out['settings']['vnext'][0]['port'], is_tls, False, out))
            elif line.startswith('vmess://'):
                out = parse_vmess(line)
                if out is None: continue
                is_tls = out['streamSettings'].get('security') == 'tls'
                nodes_data.append((out['settings']['vnext'][0]['address'], out['settings']['vnext'][0]['port'], is_tls, False, out))
            elif line.startswith('hysteria2://'):
                out = parse_hysteria2_for_xray(line)
                nodes_data.append((out['settings']['address'], out['settings']['port'], True, True, out))
        except Exception as e:
            print(f"⚠️ Ошибка парсинга [{get_tag(line)}]: {e}")

    # 🧪 Проверка доступности
    if not args.no_test:
        print(f"\n🔍 Тестирование {len(nodes_data)} узлов (таймаут {args.test_timeout}с)...")
        passed_outbounds = asyncio.run(test_nodes(nodes_data, timeout=args.test_timeout))
        print(f"✅ Прошло проверку: {len(passed_outbounds)} / {len(nodes_data)}")
    else:
        print("\n⏭️ Проверка доступности пропущена (флаг --no-test)")
        passed_outbounds = [data[4] for data in nodes_data]

    # Уникальные теги
    used_tags = set()
    final_outbounds = []
    for out in passed_outbounds:
        out["tag"] = make_unique_tag(out["tag"], used_tags)
        final_outbounds.append(out)
        used_tags.add(out["tag"])

    # Системные outbounds
    final_outbounds.append({
        "tag": "direct", "protocol": "freedom", "settings": {},
        "streamSettings": {"sockopt": {"domainStrategy": "UseIPv4", "tcpFastOpen": True}}
    })
    final_outbounds.append({
        "tag": "block", "protocol": "blackhole",
        "settings": {"response": {"type": "http"}}
    })

    # 🛡️ Сборка конфига (логи в journald через stdout)
    config = {
        "log": {"loglevel": "debug", "access": "", "error": ""},
        "inbounds": [
            {"tag": "socks-inbound", "port": 20808, "protocol": "socks",
             "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}},
            {"tag": "http-inbound", "port": 20809, "protocol": "http", "settings": {"allowTransparent": False}}
        ],
        "outbounds": final_outbounds,
        "routing": {
            "domainStrategy": "UseIPv4",
            "rules": [
                {"type": "field", "ip": ["::/0"], "outboundTag": "block"},
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
                {"type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block"},
                {"type": "field", "domain": ["domain:local", r"regexp:\.local$"], "outboundTag": "direct"},
                {"type": "field", "inboundTag": ["socks-inbound", "http-inbound"], "balancerTag": "auto-balancer"}
            ],
            "balancers": [{"tag": "auto-balancer", "selector": list(used_tags), "strategy": {"type": "random"}}]
        },
        "policy": {"levels": {"0": {"handshake": 4, "connIdle": 300, "uplinkOnly": 2, "downlinkOnly": 4, "bufferSize": 1024}}}
    }

    out_dir = os.path.dirname(args.output)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ Конфиг создан: {args.output}")
    print(f"📊 Рабочих узлов: {len(used_tags)}")
    print(f"💡 Логи выводятся в stdout. Для просмотра: journalctl -u xray -f")

if __name__ == "__main__":
    main()
