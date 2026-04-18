#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Xeovo → Xray Config Converter (v2.1)
- Фильтр CN/SS
- Логи в journald (stdout)
- Уникальные теги
- Hysteria2 (v2) для Xray-core
- Асинхронная проверка доступности (TCP/UDP фикс)
"""
import json, base64, urllib.parse, os, sys, argparse, asyncio, socket, ssl
from typing import List, Dict, Tuple

def get_tag(url: str) -> str:
    return urllib.parse.unquote(url.split('#')[-1]) if '#' in url else "unknown_node"

def make_unique_tag(base_tag: str, used: set) -> str:
    if base_tag not in used:
        used.add(base_tag)
        return base_tag
    i = 1
    while f"{base_tag}-{i}" in used: i += 1
    unique = f"{base_tag}-{i}"
    used.add(unique)
    return unique

def parse_trojan(url: str) -> dict:
    t = get_tag(url)
    p = urllib.parse.urlparse(url.split('#')[0])
    q = dict(urllib.parse.parse_qsl(p.query))
    return {
        "tag": t, "protocol": "trojan",
        "settings": {"servers": [{"address": p.hostname, "port": p.port, "password": p.username}]},
        "streamSettings": {
            "network": q.get('type', 'tcp'), "security": "tls",
            "tlsSettings": {"serverName": q.get('sni', p.hostname), "fingerprint": "chrome"},
            "wsSettings": {"path": q.get('path', '/'), "headers": {"Host": q.get('host', p.hostname)}} if q.get('type') == 'ws' else None
        }
    }

def parse_vless(url: str) -> dict:
    t = get_tag(url)
    p = urllib.parse.urlparse(url.split('#')[0])
    q = dict(urllib.parse.parse_qsl(p.query))
    sec = q.get('security', 'tls')
    return {
        "tag": t, "protocol": "vless",
        "settings": {"vnext": [{"address": p.hostname, "port": p.port, "users": [{"id": p.username, "encryption": "none"}]}]},
        "streamSettings": {
            "network": q.get('type', 'tcp'), "security": sec,
            "tlsSettings": {"serverName": q.get('sni', p.hostname), "fingerprint": "chrome"} if sec == 'tls' else None,
            "wsSettings": {"path": q.get('path', p.path.lstrip('/')), "headers": {"Host": q.get('host', p.hostname)}} if q.get('type') == 'ws' else None
        }
    }

def parse_vmess(url: str) -> dict:
    t = get_tag(url)
    try:
        b = url.split('://')[1].strip()
        b += '=' * (4 - len(b) % 4) if len(b) % 4 else ''
        d = json.loads(base64.b64decode(b).decode('utf-8'))
    except: return None
    return {
        "tag": t, "protocol": "vmess",
        "settings": {"vnext": [{"address": d['add'], "port": int(d['port']), "users": [{"id": d['id'], "alterId": int(d.get('aid',0)), "security": d.get('scy','auto')}]}]},
        "streamSettings": {
            "network": d.get('net','tcp'), "security": d.get('tls','none'),
            "tlsSettings": {"serverName": d.get('sni', d['add']), "fingerprint": "chrome"} if d.get('tls') == 'tls' else None,
            "wsSettings": {"path": d.get('path','/'), "headers": {"Host": d.get('host', d['add'])}} if d.get('net') == 'ws' else None
        }
    }

def parse_hysteria2(url: str) -> dict:
    t = get_tag(url)
    p = urllib.parse.urlparse(url.split('#')[0])
    q = dict(urllib.parse.parse_qsl(p.query))
    return {
        "tag": t, "protocol": "hysteria",
        "settings": {"version": 2, "address": p.hostname, "port": p.port, "auth": urllib.parse.unquote(p.username or '')},
        "streamSettings": {
            "network": "hysteria", "security": "tls",
            "tlsSettings": {"serverName": q.get('sni', p.hostname), "fingerprint": "chrome", "alpn": ["h3"]},
            "hysteriaSettings": {"version": 2, "up": "100 mbps", "down": "100 mbps"}
        }
    }

async def check_reachability(host: str, port: int, is_udp: bool = False, timeout: float = 2.5) -> bool:
    """Проверяет доступность узла. Для UDP использует TCP-зонд как эвристику."""
    try:
        loop = asyncio.get_running_loop()
        if is_udp:
            # Для Hysteria проверяем TCP на том же порту (обычно 443 открыт для CDN/fallback)
            try:
                await loop.run_in_executor(None, socket.create_connection, (host, port), timeout)
                return True
            except:
                # Если TCP закрыт, проверяем только резолв DNS
                await loop.run_in_executor(None, socket.getaddrinfo, host, port, socket.AF_INET, socket.SOCK_DGRAM)
                return True
        else:
            # TCP/TLS: ждём полного рукопожатия
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

async def test_nodes(nodes: List[Tuple], timeout: float = 2.5, max_conn: int = 30) -> List[dict]:
    """Асинхронно тестирует узлы и возвращает только рабочие."""
    sem = asyncio.Semaphore(max_conn)
    async def run(h, p, is_udp, out):
        async with sem:
            ok = await check_reachability(h, p, is_udp, timeout)
            return ok, out
    
    tasks = [run(*n) for n in nodes]
    results = await asyncio.gather(*tasks)
    return [out for ok, out in results if ok]

def main():
    parser = argparse.ArgumentParser(description="Xeovo → Xray Config")
    parser.add_argument("-i", "--input", default="xeovo-any-URL_List_All_Protocols(2).txt")
    parser.add_argument("-o", "--output", default="xray_config.json")
    parser.add_argument("--test-timeout", type=float, default=2.5, help="Таймаут проверки (сек)")
    parser.add_argument("--no-test", action="store_true", help="Пропустить проверку")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"❌ {args.input} не найден"); sys.exit(1)

    with open(args.input, 'r', encoding='utf-8') as f:
        lines = [l.strip() for l in f if l.strip()]

    raw_nodes, used_tags = [], set()
    
    for line in lines:
        tag = get_tag(line)
        p = urllib.parse.urlparse(line)
        host = (p.hostname or "").lower()
        
        # 🔴 Фильтры
        if 'cn' in tag.lower() or 'cn' in host: continue
        if line.startswith('ss://'): continue

        try:
            if line.startswith('trojan://'): raw_nodes.append((p.hostname, p.port, False, parse_trojan(line)))
            elif line.startswith('vless://'): raw_nodes.append((p.hostname, p.port, False, parse_vless(line)))
            elif line.startswith('vmess://'): raw_nodes.append((p.hostname, p.port, False, parse_vmess(line)))
            elif line.startswith('hysteria2://'): raw_nodes.append((p.hostname, p.port, True, parse_hysteria2(line)))
        except: continue

    print(f"📥 Загружено: {len(raw_nodes)} | 🚀 Проверка (таймаут {args.test_timeout}с)...")
    
    if not args.no_test and raw_nodes:
        valid_outbounds = asyncio.run(test_nodes(raw_nodes, timeout=args.test_timeout))
        print(f"✅ Прошло проверку: {len(valid_outbounds)} / {len(raw_nodes)}")
    else:
        print("⏭️ Проверка пропущена")
        valid_outbounds = [n[3] for n in raw_nodes]

    # Уникальные теги
    final_outbounds = []
    for out in valid_outbounds:
        out["tag"] = make_unique_tag(out["tag"], used_tags)
        final_outbounds.append(out)

    final_outbounds.append({"tag": "direct", "protocol": "freedom", "settings": {}, "streamSettings": {"sockopt": {"domainStrategy": "UseIPv4", "tcpFastOpen": True}}})
    final_outbounds.append({"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "http"}}})

    config = {
        "log": {"loglevel": "debug", "access": "", "error": ""}, # Пустые строки → stdout → journald
        "inbounds": [
            {"tag": "socks-inbound", "port": 20808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"}, "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}},
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

    d = os.path.dirname(args.output)
    if d and not os.path.exists(d): os.makedirs(d, exist_ok=True)

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ Готово: {args.output}")
    print(f"📊 В конфиге: {len(used_tags)} рабочих узлов")

if __name__ == "__main__":
    main()
