#!/usr/bin/env python3
"""
Xeovo → Xray Converter (Xray-core Compatible)
- ✅ Fixes Hysteria2 structure (protocol: "hysteria", version: 2) for Xray-core
- ✅ Filters Shadowsocks and CN servers
- ✅ Removes DNS section
- ✅ Logs to stdout (journald)
- ✅ Unique tags & clean JSON (removes spaces)
- ✅ Balancer strategy: leastPing
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

def clean_json(obj):
    """Recursively strips spaces from keys and string values."""
    if isinstance(obj, dict):
        return {k.strip(): clean_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [clean_json(i) for i in obj]
    elif isinstance(obj, str):
        return obj.strip()
    return obj

def decode_ss_auth(auth: str) -> tuple[str, str]:
    auth += '=' * (-len(auth) % 4)
    try:
        decoded = base64.urlsafe_b64decode(auth).decode('utf-8')
        return decoded.split(':', 1) if ':' in decoded else ("chacha20-ietf-poly1305", decoded)
    except:
        return "chacha20-ietf-poly1305", auth

def fix_ws_settings(ws_settings: Dict[str, Any], host: str) -> Dict[str, Any]:
    """Standardizes WS settings for Xray-core (uses headers.Host)."""
    result = {"path": ws_settings.get("path", "/")}
    host_val = ws_settings.get("host") or ws_settings.get("headers", {}).get("Host") or host
    result["headers"] = {"Host": host_val}
    return result

def parse_trojan_url(url: str) -> Dict[str, Any]:
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
    tls_settings = {
        "serverName": params.get('sni', [host])[0],
        "fingerprint": "chrome"
    }
    outbound = {
        "protocol": "trojan",
        "settings": {
            "servers": [{
                "address": host,
                "port": port,
                "password": password
            }]
        },
        "streamSettings": {
            "security": "tls",
            "tlsSettings": tls_settings,
            "network": "tcp"
        },
        "name": name,
        "host": host,
        "port": port,
        "proto": "trojan"
    }
    if params.get('type', ['tcp'])[0] == 'ws':
        ws_settings = {
            "path": params.get('path', ['/'])[0],
            "headers": {"Host": params.get('host', [host])[0]}
        }
        outbound["streamSettings"]["network"] = "ws"
        outbound["streamSettings"]["wsSettings"] = fix_ws_settings(ws_settings, host)
    return outbound

def parse_vless_url(url: str) -> Dict[str, Any]:
    content = url[8:]
    name = unquote(content.split('#', 1)[1]) if '#' in content else ""
    uuid, server_part = content.split('#', 1)[0].split('@', 1)
    params = {}
    path = ""
    if '?' in server_part:
        server_info, query = server_part.split('?', 1)
        params = urllib.parse.parse_qs(query)
        if 'path' in params:
            path = params['path'][0]
    else:
        server_info = server_part
    host, port = server_info.strip('[]').rsplit(':', 1)
    port = int(port)
    network = params.get('type', ['tcp'])[0]
    security = params.get('security', ['tls'])[0]
    stream_settings = {"network": network, "security": security}
    if network == 'ws' or (network == 'tcp' and path):
        ws_settings = {
            "path": path or params.get('path', ['/'])[0],
            "headers": {"Host": params.get('host', [host])[0]}
        }
        stream_settings["network"] = "ws"
        stream_settings["wsSettings"] = fix_ws_settings(ws_settings, host)
    if security == 'tls':
        stream_settings["tlsSettings"] = {
            "serverName": params.get('sni', [params.get('host', [host])[0]])[0],
            "fingerprint": "chrome"
        }
    return {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": host,
                "port": port,
                "users": [{
                    "id": uuid,
                    "encryption": params.get('encryption', ['none'])[0],
                    "flow": params.get('flow', [''])[0]
                }]
            }]
        },
        "streamSettings": stream_settings,
        "name": name,
        "host": host,
        "port": port,
        "proto": "vless"
    }

def parse_vmess_url(url: str) -> Dict[str, Any]:
    content = url[8:]
    try:
        padded = content + '=' * (-len(content) % 4)
        data = json.loads(base64.b64decode(padded).decode('utf-8'))
        host, port = data['add'], int(data['port'])
        uuid, aid = data['id'], int(data.get('aid', '0'))
        net = data.get('net', 'tcp')
        tls = data.get('tls', 'none')
        path = data.get('path', '/')
        host_header = data.get('host', host)
        sni = data.get('sni', host_header)
    except Exception:
        return None
    stream_settings = {"network": net, "security": tls if tls != 'none' else 'none'}
    if net == 'ws':
        ws_settings = {"path": path, "headers": {"Host": host_header}}
        stream_settings["network"] = "ws"
        stream_settings["wsSettings"] = fix_ws_settings(ws_settings, host)
    if tls == 'tls':
        stream_settings["tlsSettings"] = {"serverName": sni, "fingerprint": "chrome"}
    return {
        "protocol": "vmess",
        "settings": {
            "vnext": [{
                "address": host,
                "port": port,
                "users": [{
                    "id": uuid,
                    "alterId": aid,
                    "security": data.get('scy', 'auto')
                }]
            }]
        },
        "streamSettings": stream_settings,
        "name": data.get('ps', ''),
        "host": host,
        "port": port,
        "proto": "vmess"
    }

def parse_hysteria2_url(url: str) -> Dict[str, Any]:
    """Parses Hysteria2 URL for Xray-core (protocol: hysteria, version: 2)"""
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
    return {
        "protocol": "hysteria",
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
                "serverName": params.get('sni', [host])[0],
                "fingerprint": "chrome",
                "alpn": ["h3"]
            },
            "hysteriaSettings": {
                "version": 2,
                "up": "100 mbps",
                "down": "100 mbps"
            }
        },
        "name": unquote(url.split('#', 1)[1]) if '#' in url else "",
        "host": host,
        "port": port,
        "proto": "hysteria2"
    }

def parse_subscription_file(filepath: str) -> List[Dict[str, Any]]:
    outbounds = []
    seen_hostport = set()
    used_tags = set()
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f.readlines() if line.strip() and not line.startswith(('#', '//'))]
    for line in lines:
        if line.startswith('ss://'):
            continue
        try:
            config = None
            if line.startswith('trojan://'):
                config = parse_trojan_url(line)
            elif line.startswith('vless://'):
                config = parse_vless_url(line)
            elif line.startswith('vmess://'):
                config = parse_vmess_url(line)
            elif line.startswith('hysteria2://'):
                config = parse_hysteria2_url(line)
            else:
                continue
            if not config:
                continue
            host = config['host']
            port = config['port']
            name = config.get('name', '')
            if 'cn' in host.lower() or 'cn' in name.lower():
                continue
            hostport_key = f"{host}:{port}"
            if hostport_key in seen_hostport:
                continue
            seen_hostport.add(hostport_key)
            base_tag = f"{host.replace('.', '-')}-{port}-{config['proto']}"
            tag = base_tag
            counter = 1
            while tag in used_tags:
                tag = f"{base_tag}-{counter}"
                counter += 1
            used_tags.add(tag)
            config['tag'] = tag
            del config['host']
            del config['port']
            if 'proto' in config: del config['proto']
            outbounds.append(config)
        except Exception:
            continue
    return outbounds

class LatencyChecker:
    def __init__(self, timeout: float = 2.5):
        self.timeout = timeout
    async def _check(self, host: str, port: int) -> Tuple[bool, float]:
        start = time.time()
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            writer.close()
            return True, (time.time() - start) * 1000
        except Exception:
            return False, 0.0
    async def check_all(self, servers: List[Dict[str, Any]], concurrency: int = 30) -> List[Dict[str, Any]]:
        sem = asyncio.Semaphore(concurrency)
        async def check(server):
            async with sem:
                if 'settings' in server:
                    s = server['settings']
                    if 'servers' in s:
                        host = s['servers'][0]['address']
                        port = s['servers'][0]['port']
                    elif 'vnext' in s:
                        host = s['vnext'][0]['address']
                        port = s['vnext'][0]['port']
                    elif 'address' in s:
                        host = s['address']
                        port = s['port']
                    else:
                        return server
                else:
                    return server
                ok, rtt = await self._check(host, port)
                server['health'] = {'alive': ok, 'rtt': round(rtt, 1) if ok else 9999.0}
                return server
        tasks = [check(s) for s in servers]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if not isinstance(r, Exception)]

def generate_xray_config(servers: List[Dict[str, Any]]) -> Dict[str, Any]:
    outbounds = []
    tags = []
    servers.sort(key=lambda s: s.get('health', {}).get('rtt', 9999))
    for server in servers:
        if 'health' in server and not server['health']['alive']:
            continue
        outbound = {
            "tag": server["tag"],
            "protocol": server["protocol"],
            "settings": server["settings"]
        }
        if "streamSettings" in server:
            outbound["streamSettings"] = server["streamSettings"]
        outbounds.append(outbound)
        tags.append(server["tag"])
    outbounds.extend([
        {
            "tag": "direct",
            "protocol": "freedom",
            "settings": {},
            "streamSettings": {
                "sockopt": {
                    "domainStrategy": "UseIPv4",
                    "tcpFastOpen": True,
                    "tcpKeepAliveInterval": 15
                }
            }
        },
        {
            "tag": "block",
            "protocol": "blackhole",
            "settings": {"response": {"type": "http"}}
        }
    ])
    routing = {
        "domainStrategy": "UseIPv4",
        "rules": [
            {"type": "field", "ip": ["::/0"], "outboundTag": "block"},
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
            {"type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block"},
            {"type": "field", "domain": ["domain:local", "regexp:\\.local$"], "outboundTag": "direct"}
        ]
    }
    if tags:
        # ✅ ИЗМЕНЕНИЕ: Стратегия заменена на leastPing
        routing["balancers"] = [{
            "tag": "auto-balancer",
            "selector": tags,
            "strategy": {"type": "leastPing"}
        }]
        routing["rules"].append({
            "type": "field",
            "inboundTag": ["socks-inbound", "http-inbound"],
            "balancerTag": "auto-balancer"
        })
    else:
        routing["rules"].append({
            "type": "field",
            "inboundTag": ["socks-inbound", "http-inbound"],
            "outboundTag": "direct"
        })
    return {
        "log": {"loglevel": "debug", "access": "", "error": ""},
        "inbounds": [
            {
                "tag": "socks-inbound", "port": 20808, "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}
            },
            {
                "tag": "http-inbound", "port": 20809, "protocol": "http",
                "settings": {"allowTransparent": False}
            }
        ],
        "outbounds": outbounds,
        "routing": routing,
        "policy": {
            "levels": {
                "0": {"handshake": 4, "connIdle": 300, "uplinkOnly": 2, "downlinkOnly": 10, "bufferSize": 4096}
            }
        }
    }

async def main_async(args):
    print(f"📄 Reading subscription: {args.input_file}")
    servers = parse_subscription_file(args.input_file)
    print(f"🔍 Found {len(servers)} valid servers (filtered SS/CN/Duplicates)")
    if not servers:
        print("❌ ERROR: No valid proxy URLs found")
        return False
    if args.test:
        print(f"⚡ Measuring latency (timeout={args.timeout}s)...")
        checker = LatencyChecker(timeout=args.timeout)
        results = await checker.check_all(servers, concurrency=args.concurrency)
        alive = [r for r in results if r.get('health', {}).get('alive')]
        dead = len(results) - len(alive)
        print(f"✅ {len(alive)} alive | ❌ {dead} dead")
        if alive:
            servers = alive
        else:
            print("⚠️ No healthy servers found - will use all (unverified)")
    else:
        print("⚠️ Skipping health checks (using all servers)")
    config = generate_xray_config(servers)
    clean_config = clean_json(config)
    with open(args.output_file, 'w', encoding='utf-8') as f:
        json.dump(clean_config, f, indent=2, ensure_ascii=False)
    print(f"✨ Config saved: {args.output_file}")
    return True

def main():
    parser = argparse.ArgumentParser(description='Xeovo → Xray Converter')
    parser.add_argument('input_file', help='Path to subscription file')
    parser.add_argument('output_file', nargs='?', default='xray_config.json', help='Output config path')
    parser.add_argument('--test', action='store_true', help='Perform latency health checks')
    parser.add_argument('--timeout', type=float, default=2.5, help='Timeout per server check')
    parser.add_argument('--concurrency', type=int, default=30, help='Max concurrent checks')
    args = parser.parse_args()
    success = asyncio.run(main_async(args))
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
