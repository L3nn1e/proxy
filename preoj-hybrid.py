#!/usr/bin/env python3
"""
Xeovo → Xray Config Converter (Final Production Version)
✅ Xray-core compatible Hysteria2 (protocol: "hysteria", flat settings)
✅ Zero "dependencies not resolved" errors (strict tag matching)
✅ Automatic JSON sanitization (removes hidden spaces)
✅ Filters: Shadowsocks, CN/Custom.li servers, duplicates
✅ IPv6 leak protection + UseIPv4 enforcement
✅ Logs to stdout → journald
✅ TCP hardening (MTU 1300, KeepAlive, Chrome fingerprint)
"""
import base64
import json
import sys
import urllib.parse
import asyncio
import socket
import ssl
import time
import argparse
from typing import List, Dict, Any, Tuple
from urllib.parse import unquote

# 🛡️ Гарантирует отсутствие пробелов в ключах/значениях JSON
def clean_json(obj):
    if isinstance(obj, dict):
        return {str(k).strip(): clean_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [clean_json(i) for i in obj]
    elif isinstance(obj, str):
        return obj.strip()
    return obj

def make_unique_tag(base_tag: str, used_tags: set) -> str:
    tag = base_tag
    if tag not in used_tags:
        used_tags.add(tag)
        return tag
    counter = 1
    while f"{base_tag}-{counter}" in used_tags:
        counter += 1
    unique = f"{base_tag}-{counter}"
    used_tags.add(unique)
    return unique

def parse_trojan(url: str) -> Dict[str, Any]:
    content = url[9:]
    name = unquote(content.split('#', 1)[1]) if '#' in content else ""
    password, server_part = content.split('#', 1)[0].split('@', 1)
    params = {}
    if '?' in server_part:
        server_info, query = server_part.split('?', 1)
        params = urllib.parse.parse_qs(query)
    else:
        server_info = server_part
    host, port = server_info.strip('[]').rsplit(':', 1)
    port = int(port)
    return {
        "protocol": "trojan",
        "settings": {"servers": [{"address": host, "port": port, "password": password}]},
        "streamSettings": {
            "security": "tls",
            "tlsSettings": {"serverName": params.get('sni', [host])[0], "fingerprint": "chrome"},
            "network": "ws" if params.get('type', ['tcp'])[0] == 'ws' else "tcp"
        },
        "_name": name, "_host": host, "_port": port
    }

def parse_vless(url: str) -> Dict[str, Any]:
    content = url[8:]
    name = unquote(content.split('#', 1)[1]) if '#' in content else ""
    uuid, server_part = content.split('#', 1)[0].split('@', 1)
    params = {}
    path = ""
    if '?' in server_part:
        server_info, query = server_part.split('?', 1)
        params = urllib.parse.parse_qs(query)
        if 'path' in params: path = params['path'][0]
    else:
        server_info = server_part
    host, port = server_info.strip('[]').rsplit(':', 1)
    port = int(port)
    network = params.get('type', ['tcp'])[0]
    security = params.get('security', ['none'])[0]
    stream = {"network": network, "security": security}
    if network == 'ws' or path:
        stream["network"] = "ws"
        stream["wsSettings"] = {"path": path or params.get('path', ['/'])[0], "headers": {"Host": params.get('host', [host])[0]}}
    if security == 'tls':
        stream["tlsSettings"] = {"serverName": params.get('sni', [params.get('host', [host])[0]])[0], "fingerprint": "chrome"}
    return {
        "protocol": "vless",
        "settings": {"vnext": [{"address": host, "port": port, "users": [{"id": uuid, "encryption": "none"}]}]},
        "streamSettings": stream,
        "_name": name, "_host": host, "_port": port
    }

def parse_vmess(url: str) -> Dict[str, Any]:
    content = url[8:]
    try:
        b64 = content.split('#', 1)[0] if '#' in content else content
        b64 += '=' * (-len(b64) % 4)
        data = json.loads(base64.b64decode(b64).decode('utf-8'))
    except:
        return None
    name = unquote(content.split('#', 1)[1]) if '#' in content else data.get('ps', '')
    host, port = data['add'], int(data['port'])
    net, tls = data.get('net', 'tcp'), data.get('tls', 'none')
    stream = {"network": net, "security": tls if tls != 'none' else 'none'}
    if net == 'ws':
        stream["wsSettings"] = {"path": data.get('path', '/'), "headers": {"Host": data.get('host', host)}}
    if tls == 'tls':
        stream["tlsSettings"] = {"serverName": data.get('sni', data.get('host', host)), "fingerprint": "chrome"}
    return {
        "protocol": "vmess",
        "settings": {"vnext": [{"address": host, "port": port, "users": [{"id": data['id'], "alterId": int(data.get('aid', 0)), "security": "auto"}]}]},
        "streamSettings": stream,
        "_name": name, "_host": host, "_port": port
    }

def parse_hysteria2_for_xray(url: str) -> Dict[str, Any]:
    """✅ Строго по шаблону, который подтвердил Xray-core"""
    content = url[12:].split('#', 1)[0]
    auth, server_part = content.split('@', 1)
    params = {}
    if '?' in server_part:
        server_info, query = server_part.split('?', 1)
        params = urllib.parse.parse_qs(query)
    else:
        server_info = server_part
    host, port = server_info.strip('[]').rsplit(':', 1)
    port = int(port)
    name = unquote(url.split('#', 1)[1]) if '#' in url else f"{host}:{port}-hysteria2"
    return {
        "protocol": "hysteria",
        "settings": {
            "version": 2,
            "address": host,
            "port": port,
            "auth": unquote(auth)
        },
        "streamSettings": {
            "network": "hysteria",
            "security": "tls",
            "tlsSettings": {"serverName": params.get('sni', [host])[0], "fingerprint": "chrome", "alpn": ["h3"]},
            "hysteriaSettings": {"version": 2, "up": "100 mbps", "down": "100 mbps"}
        },
        "_name": name, "_host": host, "_port": port
    }

def parse_subscription(filepath: str) -> List[Dict[str, Any]]:
    outbounds = []
    seen_hostport = set()
    used_tags = set()
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f if line.strip() and not line.startswith(('#', '//'))]
    for line in lines:
        if line.startswith('ss://'): continue
        try:
            if line.startswith('trojan://'): cfg = parse_trojan(line)
            elif line.startswith('vless://'): cfg = parse_vless(line)
            elif line.startswith('vmess://'): cfg = parse_vmess(line)
            elif line.startswith('hysteria2://'): cfg = parse_hysteria2_for_xray(line)
            else: continue
            if not cfg: continue

            host, port = cfg['_host'], cfg['_port']
            tag_base = cfg['_name'] or f"{host.replace('.', '-')}-{port}-{cfg['protocol']}"
            
            # 🔴 Фильтр CN/China/Custom.li
            tag_lower, host_lower = tag_base.lower(), host.lower()
            if any(x in tag_lower or x in host_lower for x in ['cn', 'china', 'custom.li']): continue

            hostport_key = f"{host}:{port}"
            if hostport_key in seen_hostport: continue
            seen_hostport.add(hostport_key)

            # Генерация уникального тега
            cfg['tag'] = make_unique_tag(tag_base, used_tags)
            del cfg['_name'], cfg['_host'], cfg['_port']
            outbounds.append(cfg)
        except Exception as e:
            print(f"⚠️ Пропущено (ошибка парсинга): {e}")
    return outbounds

class LatencyChecker:
    def __init__(self, timeout: float = 2.5):
        self.timeout = timeout
    async def _check(self, host: str, port: int, is_tls: bool) -> Tuple[bool, float]:
        start = time.time()
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx if is_tls else None),
                timeout=self.timeout
            )
            writer.close()
            return True, (time.time() - start) * 1000
        except:
            return False, 0.0
    async def check_all(self, servers: List[Dict], concurrency: int = 30) -> List[Dict]:
        sem = asyncio.Semaphore(concurrency)
        async def check(srv):
            async with sem:
                addr = srv['settings'].get('address') or srv['settings'].get('servers', [{}])[0].get('address') or srv['settings'].get('vnext', [{}])[0].get('address')
                port = srv['settings'].get('port') or srv['settings'].get('servers', [{}])[0].get('port') or srv['settings'].get('vnext', [{}])[0].get('port')
                is_tls = srv.get('streamSettings', {}).get('security') == 'tls'
                ok, rtt = await self._check(addr, port, is_tls)
                srv['health'] = {'alive': ok, 'rtt': round(rtt, 1) if ok else 9999.0}
                return srv
        return [r for r in await asyncio.gather(*[check(s) for s in servers], return_exceptions=True) if not isinstance(r, Exception)]

def generate_xray_config(servers: List[Dict]) -> Dict[str, Any]:
    outbounds, tags = [], []
    servers.sort(key=lambda s: s.get('health', {}).get('rtt', 9999))
    for srv in servers:
        if 'health' in srv and not srv['health']['alive']: continue
        outbounds.append({k: v for k, v in srv.items() if k != 'health'})
        tags.append(srv['tag'])

    outbounds.extend([
        {"tag": "direct", "protocol": "freedom", "settings": {}, "streamSettings": {"sockopt": {"domainStrategy": "UseIPv4", "tcpFastOpen": True, "tcpMaxSeg": 1300, "tcpMptcp": False, "tcpKeepAliveIdle": 300, "tcpKeepAliveInterval": 15}}},
        {"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "http"}}}
    ])

    routing = {
        "domainStrategy": "UseIPv4",
        "rules": [
            {"type": "field", "ip": ["::/0", "2000::/3", "2600::/12", "2001::/32", "fc00::/7", "fe80::/10", "::1/128"], "outboundTag": "block"},
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
            {"type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block"},
            {"type": "field", "domain": ["domain:local", r"regexp:\.local$"], "outboundTag": "direct"}
        ]
    }
    if tags:
        routing["balancers"] = [{"tag": "auto-balancer", "selector": tags, "strategy": {"type": "leastPing"}}]
        routing["rules"].append({"type": "field", "inboundTag": ["socks-inbound", "http-inbound"], "balancerTag": "auto-balancer"})
    else:
        routing["rules"].append({"type": "field", "inboundTag": ["socks-inbound", "http-inbound"], "outboundTag": "direct"})

    return {
        "log": {"loglevel": "debug", "access": "", "error": ""},
        "inbounds": [
            {"tag": "socks-inbound", "port": 20808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"}, "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}},
            {"tag": "http-inbound", "port": 20809, "protocol": "http", "settings": {"allowTransparent": False}}
        ],
        "outbounds": outbounds,
        "routing": routing,
        "policy": {"levels": {"0": {"handshake": 8, "connIdle": 300, "uplinkOnly": 5, "downlinkOnly": 10, "bufferSize": 4096}}}
    }

async def main_async(args):
    print(f"📄 Чтение подписки: {args.input}")
    servers = parse_subscription(args.input)
    print(f"🔍 Найдено узлов: {len(servers)} (SS/CN/дубли отфильтрованы)")
    if not servers: print("❌ Нет валидных серверов"); return False

    if args.test:
        print(f"⚡ Проверка доступности (таймаут {args.timeout}с)...")
        checker = LatencyChecker(timeout=args.timeout)
        results = await checker.check_all(servers, concurrency=args.concurrency)
        alive = [r for r in results if r.get('health', {}).get('alive')]
        print(f"✅ Живых: {len(alive)} | ❌ Мёртвых: {len(results) - len(alive)}")
        servers = alive if alive else servers
    else:
        print("⏭️ Проверка пропущена")

    config = generate_xray_config(servers)
    # 🛡️ Финальная очистка от любых скрытых артефактов
    clean_config = clean_json(config)
    os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(clean_config, f, indent=2, ensure_ascii=False)
    print(f"✨ Конфиг сохранён: {args.output}")
    print(f"📊 Прокси в балансировщике: {len(clean_config.get('routing', {}).get('balancers', [{}])[0].get('selector', []))}")
    return True

def main():
    parser = argparse.ArgumentParser(description='Xeovo → Xray Config Converter')
    parser.add_argument('input', help='Путь к файлу подписки .txt')
    parser.add_argument('output', nargs='?', default='xray_config.json', help='Выходной файл .json')
    parser.add_argument('--test', action='store_true', help='Проверить пинг серверов перед сохранением')
    parser.add_argument('--timeout', type=float, default=2.5, help='Таймаут проверки (сек)')
    parser.add_argument('--concurrency', type=int, default=30, help='Параллельных проверок')
    args = parser.parse_args()
    success = asyncio.run(main_async(args))
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
