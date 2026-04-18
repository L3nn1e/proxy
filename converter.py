#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json, base64, urllib.parse, os, sys, argparse

def get_tag(url):
    return urllib.parse.unquote(url.split('#')[-1]) if '#' in url else "unknown_node"

def parse_trojan(url):
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

def parse_vless(url):
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

def parse_vmess(url):
    tag = get_tag(url)
    b64 = url.split('://')[1].strip()
    b64 += '=' * (4 - len(b64) % 4) if len(b64) % 4 != 0 else ''
    data = json.loads(base64.b64decode(b64).decode('utf-8'))
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

def parse_hysteria2_for_xray(url):
    """Парсит hysteria2:// для Xray-core (protocol: hysteria, version: 2)"""
    tag = get_tag(url)
    parsed = urllib.parse.urlparse(url.split('#')[0])
    host, port = parsed.hostname, parsed.port
    auth = urllib.parse.unquote(parsed.username or '')
    query = dict(urllib.parse.parse_qsl(parsed.query))
    sni = query.get('sni', host)
    
    return {
        "tag": tag,
        "protocol": "hysteria",
        "settings": {
            "version": 2,
            "servers": [{"address": host, "port": port, "password": auth}]
        },
        "streamSettings": {
            "network": "hysteria",
            "security": "tls",
            "tlsSettings": {"serverName": sni, "fingerprint": "chrome", "alpn": ["h3"]},
            "hysteriaSettings": {
                "version": 2,
                "up": "100 mbps",
                "down": "100 mbps"
            }
        }
    }

def main():
    parser = argparse.ArgumentParser(description="Xeovo → Xray config converter")
    parser.add_argument("-i", "--input", default="xeovo-any-URL_List_All_Protocols(2).txt")
    parser.add_argument("-o", "--output", default="xray_config.json")
    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print(f"❌ Файл {args.input} не найден"); sys.exit(1)
    
    with open(args.input, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    outbounds, tags = [], []
    
    for line in lines:
        line = line.strip()
        if not line: continue
        tag = get_tag(line).lower()
        host = (urllib.parse.urlparse(line).hostname or "").lower()
        
        # Фильтры
        if 'cn' in tag or 'cn' in host:
            print(f"⏭️ Пропущен CN: {line}"); continue
        if line.startswith('ss://'):
            continue
        
        try:
            if line.startswith('trojan://'):
                outbounds.append(parse_trojan(line))
            elif line.startswith('vless://'):
                outbounds.append(parse_vless(line))
            elif line.startswith('vmess://'):
                outbounds.append(parse_vmess(line))
            elif line.startswith('hysteria2://'):
                outbounds.append(parse_hysteria2_for_xray(line))
                print(f"✅ Hysteria2 добавлен: {get_tag(line)}")
            else:
                continue
            tags.append(outbounds[-1]['tag'])
        except Exception as e:
            print(f"⚠️ Ошибка парсинга: {e}")
    
    # Системные outbounds
    outbounds.append({"tag": "direct", "protocol": "freedom", "settings": {}, 
                      "streamSettings": {"sockopt": {"domainStrategy": "UseIPv4"}}})
    outbounds.append({"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "http"}}})
    
    config = {
        "log": {"loglevel": "debug", "access": "access.log", "error": "error.log"},
        "inbounds": [
            {"tag": "socks-inbound", "port": 20808, "protocol": "socks",
             "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}},
            {"tag": "http-inbound", "port": 20809, "protocol": "http", "settings": {"allowTransparent": False}}
        ],
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "UseIPv4",
            "rules": [
                {"type": "field", "ip": ["::/0"], "outboundTag": "block"},
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
                {"type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block"},
                {"type": "field", "domain": ["domain:local", "regexp:\\.local$"], "outboundTag": "direct"},
                {"type": "field", "inboundTag": ["socks-inbound", "http-inbound"], "balancerTag": "auto-balancer"}
            ],
            "balancers": [{"tag": "auto-balancer", "selector": tags, "strategy": {"type": "random"}}]
        },
        "policy": {"levels": {"0": {"handshake": 4, "connIdle": 300, "uplinkOnly": 2, "downlinkOnly": 4, "bufferSize": 1024}}}
    }
    
    out_dir = os.path.dirname(args.output)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)
    
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ Конфиг создан: {args.output}")
    print(f"📊 Узлов: {len(tags)} | Hysteria2: {sum(1 for o in outbounds if o.get('protocol')=='hysteria')}")

if __name__ == "__main__":
    main()
