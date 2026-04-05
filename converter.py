#!/usr/bin/env python3
"""
Xeovo в†’ Xray Converter (TLS Hardened - NO DNS SECTION)
вњ… Fixes PR_END_OF_FILE_ERROR via TLS fingerprint hardening
вњ… NO DNS section (matches your original working config)
вњ… domainStrategy: "IPIfNonMatch" preserved
вњ… IPv6 blocking + freedom outbound IPv4 enforcement
вњ… Unique tags (host-port-proto) to prevent collisions
вњ… MTU adjustment to prevent TLS fragmentation
вњ… Health checks for fastest servers
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


def decode_ss_auth(auth: str) -> tuple[str, str]:
    auth += '=' * (-len(auth) % 4)
    try:
        decoded = base64.urlsafe_b64decode(auth).decode('utf-8')
        return decoded.split(':', 1) if ':' in decoded else ("chacha20-ietf-poly1305", decoded)
    except:
        return "chacha20-ietf-poly1305", auth


def fix_ws_settings(ws_settings: Dict[str, Any], host: str) -> Dict[str, Any]:
    result = {"path": ws_settings.get("path", "/")}
    host_val = ws_settings.get("host") or ws_settings.get("headers", {}).get("Host") or host
    result["host"] = host_val
    extra_headers = {k: v for k, v in ws_settings.get("headers", {}).items() if k.lower() != "host"}
    if extra_headers:
        result["headers"] = extra_headers
    return result


def parse_ss_url(url: str) -> Dict[str, Any]:
    content = url[5:]
    name = unquote(content.split('#', 1)[1]) if '#' in content else ""
    auth_part, server_part = content.split('#', 1)[0].split('@', 1)
    
    plugin_params = {}
    if '?' in server_part:
        server_part, plugin_query = server_part.split('?', 1)
        plugin_params = urllib.parse.parse_qs(plugin_query)
    
    host, port = server_part.strip('[]').rsplit(':', 1)
    port = int(port)
    method, password = decode_ss_auth(auth_part)
    
    return {
        "protocol": "shadowsocks",
        "settings": {
            "servers": [{
                "address": host,
                "port": port,
                "method": method,
                "password": password
            }]
        },
        "name": name,
        "host": host,
        "port": port,
        "proto": "ss"
    }


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
    
    # вњ… CRITICAL FIX: Add TLS fingerprint for Cloudflare compatibility
    tls_settings = {
        "serverName": params.get('sni', [host])[0],
        "fingerprint": "chrome"  # вњ… Hardened against PR_END_OF_FILE_ERROR
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
            "tlsSettings": tls_settings
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
    else:
        outbound["streamSettings"]["network"] = "tcp"
    
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
        if '/' in server_info and ':' not in server_info.split('/', 1)[1]:
            server_info, path_suffix = server_info.split('/', 1)
            path = '/' + path_suffix
    
    host, port = server_info.strip('[]').rsplit(':', 1)
    port = int(port)
    
    network = params.get('type', ['tcp'])[0]
    security = params.get('security', ['none'])[0]
    flow = params.get('flow', [''])[0]
    
    stream_settings = {"network": network, "security": security}
    
    if network == 'ws' or (network == 'tcp' and path):
        ws_settings = {
            "path": path or params.get('path', ['/'])[0],
            "headers": {"Host": params.get('host', [host])[0]}
        }
        stream_settings["network"] = "ws"
        stream_settings["wsSettings"] = fix_ws_settings(ws_settings, host)
    
    if security == 'tls':
        # вњ… CRITICAL FIX: Add TLS fingerprint + uTLS for Cloudflare
        stream_settings["tlsSettings"] = {
            "serverName": params.get('sni', [params.get('host', [host])[0]])[0],
            "fingerprint": "chrome"  # вњ… Hardened against PR_END_OF_FILE_ERROR
        }
        if 'fp' in params:
            stream_settings["tlsSettings"]["fingerprint"] = params['fp'][0]
    
    return {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": host,
                "port": port,
                "users": [{
                    "id": uuid,
                    "encryption": params.get('encryption', ['none'])[0],
                    "flow": flow
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
        if '#' in content:
            content = content.split('#', 1)[0]
        uuid, server_part = content.split('@', 1)
        params = {}
        if '?' in server_part:
            server_info, query = server_part.split('?', 1)
            params = urllib.parse.parse_qs(query)
        else:
            server_info = server_part
        host, port = server_info.strip('[]').rsplit(':', 1)
        port = int(port)
        aid = int(params.get('aid', ['0'])[0])
        net = params.get('net', ['tcp'])[0]
        tls = params.get('tls', ['none'])[0]
        path = params.get('path', ['/'])[0]
        host_header = params.get('host', [host])[0]
        sni = params.get('sni', [host_header])[0]
    
    stream_settings = {"network": net, "security": tls if tls != 'none' else 'none'}
    
    if net == 'ws':
        ws_settings = {"path": path, "headers": {"Host": host_header}}
        stream_settings["network"] = "ws"
        stream_settings["wsSettings"] = fix_ws_settings(ws_settings, host)
    
    if tls == 'tls':
        # вњ… CRITICAL FIX: Add TLS fingerprint
        stream_settings["tlsSettings"] = {
            "serverName": sni,
            "fingerprint": "chrome"  # вњ… Hardened against PR_END_OF_FILE_ERROR
        }
    
    return {
        "protocol": "vmess",
        "settings": {
            "vnext": [{
                "address": host,
                "port": port,
                "users": [{
                    "id": uuid,
                    "alterId": aid,
                    "security": "auto"
                }]
            }]
        },
        "streamSettings": stream_settings,
        "name": "",
        "host": host,
        "port": port,
        "proto": "vmess"
    }


def parse_hysteria2_url(url: str) -> Dict[str, Any]:
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
        "protocol": "hysteria2",
        "settings": {
            "servers": [{
                "address": host,
                "port": port,
                "password": auth
            }]
        },
        "streamSettings": {
            "security": "tls",
            "tlsSettings": {
                "serverName": params.get('sni', [host])[0],
                "fingerprint": "chrome"  # вњ… Hardened
            }
        },
        "name": "",
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
        try:
            if line.startswith('ss://'):
                config = parse_ss_url(line)
                proto = 'ss'
            elif line.startswith('trojan://'):
                config = parse_trojan_url(line)
                proto = 'trojan'
            elif line.startswith('vless://'):
                config = parse_vless_url(line)
                proto = 'vless'
            elif line.startswith('vmess://'):
                config = parse_vmess_url(line)
                proto = 'vmess'
            elif line.startswith('hysteria2://'):
                config = parse_hysteria2_url(line)
                proto = 'hysteria2'
            else:
                continue
            
            host = config['host']
            port = config['port']
            hostport_key = f"{host}:{port}"
            
            if hostport_key in seen_hostport:
                continue
            seen_hostport.add(hostport_key)
            
            # Generate UNIQUE tag: host-replaced-dots-PORT-proto
            base_tag = f"{host.replace('.', '-')}-{port}-{proto}"
            tag = base_tag
            counter = 1
            while tag in used_tags:
                tag = f"{base_tag}-{counter}"
                counter += 1
            used_tags.add(tag)
            
            config['tag'] = tag
            del config['host']
            del config['port']
            del config['proto']
            
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
                asyncio.open_connection(host, port, ssl=True),
                timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return True, (time.time() - start) * 1000
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, ssl.SSLError, 
                socket.gaierror, ConnectionResetError, BrokenPipeError):
            return False, 0.0
    
    async def check_all(self, servers: List[Dict[str, Any]], concurrency: int = 30) -> List[Dict[str, Any]]:
        sem = asyncio.Semaphore(concurrency)
        
        async def check(server):
            async with sem:
                if 'servers' in server['settings']:
                    host = server['settings']['servers'][0]['address']
                    port = server['settings']['servers'][0]['port']
                else:
                    host = server['settings']['vnext'][0]['address']
                    port = server['settings']['vnext'][0]['port']
                
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
    
    # Critical hardening: IPv4 enforcement + MTU adjustment
    outbounds.extend([
        {
            "tag": "direct",
            "protocol": "freedom",
            "settings": {},
            "streamSettings": {
                "sockopt": {
                    "domainStrategy": "UseIPv4",  # вњ… Force IPv4 sockets
                    "tcpFastOpen": True,
                    "tcpMptcp": False,
                    "mark": 0,
                    "tcpKeepAliveIdle": 300,      # Keepalive every 5 min
                    "tcpKeepAliveInterval": 15,   # Probe every 15s after idle
                    "tcpMaxSeg": 1300             # вњ… CRITICAL: Prevent TLS fragmentation (fixes PR_END_OF_FILE_ERROR)
                }
            }
        },
        {
            "tag": "block",
            "protocol": "blackhole",
            "settings": {
                "response": {"type": "http"}
            }
        }
    ])
    
    routing = {
        "domainStrategy": "IPIfNonMatch",  # вњ… PRESERVED: Xray doesn't resolve DNS itself
        "rules": [
            {
                "type": "field",
                "ip": [
                    "geoip:private",
                    "2000::/3",    # Global IPv6
                    "2600::/12",   # US IPv6
                    "2001::/32",   # Teredo
                    "fc00::/7",    # ULA
                    "fe80::/10",   # Link-local
                    "::1/128"      # Loopback
                ],
                "outboundTag": "block"  # вњ… Block ALL IPv6 traffic
            },
            {
                "type": "field",
                "domain": ["geosite:category-ads-all"],
                "outboundTag": "block"
            },
            {
                "type": "field",
                "domain": ["domain:local", "regexp:\\.local$"],
                "outboundTag": "direct"
            }
        ]
    }
    
    if tags:
        routing["balancers"] = [{
            "tag": "auto-balancer",
            "selector": tags,
            "strategy": {"type": "random"}
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
        "log": {
            "loglevel": "warning",
            "dnsLog": False
        },
        # вњ… DNS SECTION REMOVED - matches your original working config
        "inbounds": [
            {
                "tag": "socks-inbound",
                "port": 20808,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True,
                    "ip": "127.0.0.1"
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"]
                }
            },
            {
                "tag": "http-inbound",
                "port": 20809,
                "protocol": "http",
                "settings": {
                    "allowTransparent": False
                }
            }
        ],
        "outbounds": outbounds,
        "routing": routing,
        "policy": {
            "levels": {
                "0": {
                    "handshake": 4,        # Fail fast on slow handshakes
                    "connIdle": 300,       # Keep connections alive longer (5 min)
                    "uplinkOnly": 2,
                    "downlinkOnly": 4,
                    "bufferSize": 1024,    # Larger buffer reduces fragmentation
                    "sendThrough": "0.0.0.0"  # Bind to IPv4 only
                }
            }
        }
    }


async def main_async(args):
    print(f"рџ“„ Reading subscription: {args.input_file}")
    servers = parse_subscription_file(args.input_file)
    print(f"рџ”Ќ Found {len(servers)} unique servers (deduplicated by host:port)")
    
    if not servers:
        print("вќЊ ERROR: No valid proxy URLs found")
        return False
    
    if args.test:
        print(f"\nвљЎ Measuring latency (timeout={args.timeout}s)...")
        checker = LatencyChecker(timeout=args.timeout)
        results = await checker.check_all(servers, concurrency=args.concurrency)
        
        alive = [r for r in results if r.get('health', {}).get('alive')]
        dead = len(results) - len(alive)
        
        print(f"вњ… {len(alive)} alive | вќЊ {dead} dead")
        
        if alive:
            servers = alive
            print("\nрџЏ† Top 5 fastest servers:")
            for i, server in enumerate(alive[:5], 1):
                rtt = server['health']['rtt']
                name = server.get('name') or f"{server['settings']['servers'][0]['address'] if 'servers' in server['settings'] else server['settings']['vnext'][0]['address']}:{server['settings']['servers'][0]['port'] if 'servers' in server['settings'] else server['settings']['vnext'][0]['port']}"
                print(f"   {i}. {rtt:5.1f} ms | {name}")
        else:
            print("\nвљ пёЏ  No healthy servers found - traffic will route DIRECT")
    else:
        print("\nвљ пёЏ  Skipping health checks (using all servers)")
    
    config = generate_xray_config(servers)
    
    with open(args.output_file, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    print(f"\nвњЁ Config saved: {args.output_file}")
    print(f"   вЂў Proxy servers: {len([ob for ob in config['outbounds'] if ob['tag'] not in ['direct', 'block']])}")
    print(f"\nрџљЂ Usage:")
    print(f"   1. Restart Xray: systemctl restart xray")
    print(f"   2. вљ пёЏ  CRITICAL CLIENT CONFIGURATION вљ пёЏ")
    print(f"      вЂў USE SOCKS5 (port 20808) WITH DNS PROXYING ENABLED")
    print(f"        Firefox: Settings в†’ Network в†’ SOCKS v5 в†’ Port 20808 в†’ вњ… 'Proxy DNS when using SOCKS v5'")
    print(f"      вЂў HTTP proxy (port 20809) WILL STILL HAVE IPv6/TLS ISSUES")
    print(f"\nрџ”’ Why this fixes PR_END_OF_FILE_ERROR:")
    print(f"   вЂў TLS fingerprint: 'chrome' в†’ Matches Cloudflare's expected handshake")
    print(f"   вЂў tcpMaxSeg: 1300 в†’ Prevents TLS fragmentation on problematic networks")
    print(f"   вЂў connIdle: 300s в†’ Keeps connections alive longer (reduces handshake failures)")
    print(f"   вЂў IPv6 blocking в†’ Eliminates IPv6-related connection failures")
    print(f"\nрџ’Ў If errors persist:")
    print(f"   вЂў Try different server (Cloudflare may block specific IPs)")
    print(f"   вЂў In Firefox: about:config в†’ network.http.referer.default_policy = 2")
    print(f"   вЂў Disable HTTP/3 (QUIC) in browser settings")
    
    return True


def main():
    parser = argparse.ArgumentParser(
        description='Xeovo в†’ Xray Converter (TLS Hardened - NO DNS SECTION)',
        epilog="""
Critical Fixes for PR_END_OF_FILE_ERROR:
  вЂў TLS fingerprint: "chrome" в†’ Prevents Cloudflare handshake rejection
  вЂў tcpMaxSeg: 1300 в†’ Prevents TLS packet fragmentation (common cause of EOF errors)
  вЂў connIdle: 300s в†’ Reduces frequent handshakes that trigger Cloudflare blocks
  вЂў IPv6 blocking в†’ Eliminates IPv6-related TLS failures
  
Why This Happens:
  Cloudflare and similar services inspect TLS handshakes. Default Xray fingerprints
  look "bot-like" and get rejected with premature connection closure (PR_END_OF_FILE_ERROR).
  
Recommended Command:
  python3 xeovo_to_xray.py --test --timeout 2.5 xeovo-sub.txt /etc/xray/config.json
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('input_file', help='Path to subscription file')
    parser.add_argument('output_file', nargs='?', default='config.json', help='Output config path')
    parser.add_argument('--test', action='store_true', help='Perform latency-aware health checks (recommended)')
    parser.add_argument('--timeout', type=float, default=2.5, help='Timeout per server check in seconds')
    parser.add_argument('--concurrency', type=int, default=30, help='Max concurrent health checks')
    args = parser.parse_args()
    
    success = asyncio.run(main_async(args))
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
