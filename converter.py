#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Xeovo → Xray Config Converter (v3.2 Anti-Space Fix)
- Гарантирует отсутствие пробелов в JSON-ключах
- leastPing балансировщик, routeOnly sniffing
- Фильтр CN / Shadowsocks / IPv6
- Логи в journald (stdout)
"""
import json, base64, urllib.parse, os, sys, argparse, asyncio, socket, ssl

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

# 🛡️ Функция-гарант: рекурсивно убирает пробелы из всех ключей словаря
def clean_json_keys(obj):
    if isinstance(obj, dict):
        return {str(k).strip(): clean_json_keys(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [clean_json_keys(i) for i in obj]
    elif isinstance(obj, str):
        return obj.strip()
    return obj

def parse_trojan(url: str) -> dict:
    tag = get_tag(url)
    parsed = urllib.parse.urlparse(url.split('#')[0])
    query = dict(urllib.parse.parse_qsl(parsed.query))
    net = query.get('type', 'tcp')
    sni = query.get('sni', parsed.hostname)
    out = {
        "tag": tag, "protocol": "trojan",
        "settings": {"servers": [{"address": parsed.hostname, "port": parsed.port, "password": parsed.username}]},
        "streamSettings": {"network": net, "security": "tls", "tlsSettings": {"serverName": sni, "fingerprint": "chrome"}}
    }
    if net == 'ws':
        out["streamSettings"]["wsSettings"] = {"path": query.get('path', '/'), "headers": {"Host": query.get('host', sni)}}
    return out

def parse_vless(url: str) -> dict:
    tag = get_tag(url)
    parsed = urllib.parse.urlparse(url.split('#')[0])
    query = dict(urllib.parse.parse_qsl(parsed.query))
    net = query.get('type', 'tcp')
    sec = query.get('security', 'tls')
    sni = query.get('sni', parsed.hostname)
    out = {
        "tag": tag, "protocol": "vless",
        "settings": {"vnext": [{"address": parsed.hostname, "port": parsed.port, "users": [{"id": parsed.username, "encryption": "none"}]}]},
        "streamSettings": {"network": net, "security": sec}
    }
    if sec == 'tls':
        out["streamSettings"]["tlsSettings"] = {"serverName": sni, "fingerprint": "chrome"}
    if net == 'ws':
        out["streamSettings"]["wsSettings"] = {"path": query.get('path', parsed.path.lstrip('/')), "headers": {"Host": query.get('host', sni)}}
    return out

def parse_vmess(url: str) -> dict:
    tag = get_tag(url)
    try:
        b64 = url.split('://')[1].strip()
        b64 += '=' * (4 - len(b64) % 4) if len(b64) % 4 != 0 else ''
        data = json.loads(base64.b64decode(b64).decode('utf-8'))
    except: return None
    net, tls = data.get('net', 'tcp'), data.get('tls', 'none')
    sni = data.get('sni', data['add'])
    out = {
        "tag": tag, "protocol": "vmess",
        "settings": {"vnext": [{"address": data['add'], "port": int(data['port']), "users": [
            {"id": data['id'], "alterId": int(data.get('aid', 0)), "security": data.get('scy', 'auto')}
        ]}]},
        "streamSettings": {"network": net, "security": tls}
    }
    if tls == 'tls':
        out["streamSettings"]["tlsSettings"] = {"serverName": sni, "fingerprint": "chrome"}
    if net == 'ws':
        out["streamSettings"]["wsSettings"] = {"path": data.get('path', '/'), "headers": {"Host": data.get('host', sni)}}
    return out

def parse_hysteria2_for_xray(url: str) -> dict:
    tag = get_tag(url)
    parsed = urllib.parse.urlparse(url.split('#')[0])
    auth = urllib.parse.unquote(parsed.username or '')
    query = dict(urllib.parse.parse_qsl(parsed.query))
    sni = query.get('sni', parsed.hostname)
    return {
        "tag": tag, "protocol": "hysteria",
        "settings": {"version": 2, "address": parsed.hostname, "port": parsed.port, "auth": auth},
        "streamSettings": {
            "network": "hysteria", "security": "tls",
            "tlsSettings": {"serverName": sni, "fingerprint": "chrome", "alpn": ["h3"]},
            "hysteriaSettings": {"version": 2, "up": "100 mbps", "down": "100 mbps"}
        }
    }

async def check_reachability(host: str, port: int, is_udp: bool = False, timeout: float = 2.5) -> bool:
    try:
        if is_udp:
            await asyncio.get_running_loop().run_in_executor(None, socket.create_connection, (host, port), timeout)
            return True
        else:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx), timeout=timeout)
            w.close()
            return True
    except: return False

async def test_nodes(nodes: list, timeout: float = 2.5, max_conn: int = 30) -> list:
    sem = asyncio.Semaphore(max_conn)
    async def run(h, p, is_udp, out):
        async with sem:
            return await check_reachability(h, p, is_udp, timeout), out
    results = await asyncio.gather(*(run(*n) for n in nodes))
    return [out for ok, out in results if ok]

def main():
    parser = argparse.ArgumentParser(description="Xeovo → Xray config")
    parser.add_argument("-i", "--input", default="xeovo-any-URL_List_All_Protocols(2).txt")
    parser.add_argument("-o", "--output", default="xray_config.json")
    parser.add_argument("--no-test", action="store_true")
    parser.add_argument("--test-timeout", type=float, default=2.5)
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"❌ Файл {args.input} не найден"); sys.exit(1)

    with open(args.input, 'r', encoding='utf-8') as f:
        lines = [l.strip() for l in f if l.strip()]

    raw_nodes, used_tags = [], set()
    for line in lines:
        tag = get_tag(line)
        p = urllib.parse.urlparse(line)
        host = (p.hostname or "").lower()
        if 'cn' in tag.lower() or 'cn' in host: continue
        if line.startswith('ss://'): continue
        try:
            if line.startswith('trojan://'): raw_nodes.append((p.hostname, p.port, False, parse_trojan(line)))
            elif line.startswith('vless://'): raw_nodes.append((p.hostname, p.port, False, parse_vless(line)))
            elif line.startswith('vmess://'): raw_nodes.append((p.hostname, p.port, False, parse_vmess(line)))
            elif line.startswith('hysteria2://'): raw_nodes.append((p.hostname, p.port, True, parse_hysteria2_for_xray(line)))
        except: continue

    print(f"📥 Загружено: {len(raw_nodes)} | 🚀 Проверка (таймаут {args.test_timeout}с)...")
    valid = asyncio.run(test_nodes(raw_nodes, timeout=args.test_timeout)) if not args.no_test else [n[3] for n in raw_nodes]
    print(f"✅ Прошло: {len(valid)} / {len(raw_nodes)}")

    final_outbounds, tags_list = [], []
    for out in valid:
        out["tag"] = make_unique_tag(out["tag"], used_tags)
        final_outbounds.append(out)
        tags_list.append(out["tag"])

    final_outbounds.append({"tag": "direct", "protocol": "freedom", "settings": {}, "streamSettings": {"sockopt": {"domainStrategy": "UseIPv4", "tcpFastOpen": True, "tcpKeepAliveInterval": 15}}})
    final_outbounds.append({"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "http"}}})

    config = {
        "log": {"loglevel": "debug", "access": "", "error": ""},
        "inbounds": [
            {"tag": "socks-inbound", "port": 20808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"}, "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}},
            {"tag": "http-inbound", "port": 20809, "protocol": "http", "settings": {"allowTransparent": False}}
        ],
        "outbounds": final_outbounds,
        "routing": {
            "domainStrategy": "UseIPv4",
            "rules": [
                {"type": "field", "ip": ["::/0"], "outboundTag": "block"},
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
                {"type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block"},
                {"type": "field", "domain": ["domain:local", "regexp:\\.local$"], "outboundTag": "direct"},
                {"type": "field", "inboundTag": ["socks-inbound", "http-inbound"], "balancerTag": "auto-balancer"}
            ],
            "balancers": [{"tag": "auto-balancer", "selector": tags_list, "strategy": {"type": "leastPing"}}]
        },
        "policy": {"levels": {"0": {"handshake": 8, "connIdle": 30
