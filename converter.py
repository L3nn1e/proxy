#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Конвертер подписки Xeovo в конфиг Xray-core
Поддерживает: hysteria2, trojan, vless, vmess
Фильтрует: CN-серверы, shadowsocks
Безопасность: блокировка IPv6, UseIPv4, debug-лог
"""
import json
import base64
import urllib.parse
import os
import sys
import argparse


def get_tag(url: str) -> str:
    """Извлекает и декодирует название узла из фрагмента URL."""
    if '#' in url:
        return urllib.parse.unquote(url.split('#')[-1])
    return "unknown_node"


def make_unique_tag(base_tag: str, used_tags: set) -> str:
    """Делает тег уникальным, добавляя суффикс при дубликатах."""
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
    """Парсит trojan:// ссылку в формат Xray outbound."""
    tag = get_tag(url)
    parsed = urllib.parse.urlparse(url.split('#')[0])
    host = parsed.hostname
    port = parsed.port
    password = parsed.username
    query = dict(urllib.parse.parse_qsl(parsed.query))
    
    net = query.get('type', 'tcp')
    sni = query.get('sni', host)
    ws_path = query.get('path', '/')
    ws_host = query.get('host', host)
    
    out = {
        "tag": tag,  # Будет заменён на уникальный в main()
        "protocol": "trojan",
        "settings": {
            "servers": [{
                "address": host,
                "port": port,
                "password": password
            }]
        },
        "streamSettings": {
            "network": net,
            "security": "tls",
            "tlsSettings": {
                "serverName": sni,
                "fingerprint": "chrome"
            }
        }
    }
    if net == 'ws':
        out["streamSettings"]["wsSettings"] = {
            "path": ws_path,
            "headers": {"Host": ws_host}
        }
    return out


def parse_vless(url: str) -> dict:
    """Парсит vless:// ссылку в формат Xray outbound."""
    tag = get_tag(url)
    parsed = urllib.parse.urlparse(url.split('#')[0])
    host = parsed.hostname
    port = parsed.port
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
            "vnext": [{
                "address": host,
                "port": port,
                "users": [{
                    "id": uuid,
                    "encryption": "none"
                }]
            }]
        },
        "streamSettings": {
            "network": net,
            "security": security
        }
    }
    if security == 'tls':
        out["streamSettings"]["tlsSettings"] = {
            "serverName": sni,
            "fingerprint": "chrome"
        }
    if net == 'ws':
        out["streamSettings"]["wsSettings"] = {
            "path": ws_path,
            "headers": {"Host": ws_host}
        }
    return out


def parse_vmess(url: str) -> dict:
    """Парсит vmess:// (base64 JSON) ссылку в формат Xray outbound."""
    tag = get_tag(url)
    b64 = url.split('://')[1].strip()
    b64 += '=' * (4 - len(b64) % 4) if len(b64) % 4 != 0 else ''
    
    data = json.loads(base64.b64decode(b64).decode('utf-8'))
    host = data['add']
    port = int(data['port'])
    net = data.get('net', 'tcp')
    tls = data.get('tls', 'none')
    sni = data.get('sni', host)
    ws_path = data.get('path', '/')
    ws_host = data.get('host', host)
    
    out = {
        "tag": tag,
        "protocol": "vmess",
        "settings": {
            "vnext": [{
                "address": host,
                "port": port,
                "users": [{
                    "id": data['id'],
                    "alterId": int(data.get('aid', 0)),
                    "security": data.get('scy', 'auto')
                }]
            }]
        },
        "streamSettings": {
            "network": net,
            "security": tls
        }
    }
    if tls == 'tls':
        out["streamSettings"]["tlsSettings"] = {
            "serverName": sni,
            "fingerprint": "chrome"
        }
    if net == 'ws':
        out["streamSettings"]["wsSettings"] = {
            "path": ws_path,
            "headers": {"Host": ws_host}
        }
    return out


def parse_hysteria2_for_xray(url: str) -> dict:
    """Парсит hysteria2:// ссылку в формат Xray-core outbound."""
    tag = get_tag(url)
    parsed = urllib.parse.urlparse(url.split('#')[0])
    host = parsed.hostname
    port = parsed.port
    auth = urllib.parse.unquote(parsed.username or '')
    query = dict(urllib.parse.parse_qsl(parsed.query))
    sni = query.get('sni', host)
    
    return {
        "tag": tag,
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


def is_cn_node(tag: str, host: str) -> bool:
    """Проверяет, является ли узел заблокированным CN-сервером."""
    tag_lower = tag.lower()
    host_lower = (host or "").lower()
    cn_patterns = ['cn', '-cn-', 'cn-', 'china', 'custom.li']
    return any(p in tag_lower or p in host_lower for p in cn_patterns)


def main():
    parser = argparse.ArgumentParser(description="Конвертация подписки Xeovo в конфиг Xray-core")
    parser.add_argument("-i", "--input", default="xeovo-any-URL_List_All_Protocols(2).txt", help="Входной файл подписки")
    parser.add_argument("-o", "--output", default="xray_config.json", help="Выходной конфиг Xray")
    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print(f"❌ Ошибка: файл {args.input} не найден")
        sys.exit(1)
    
    with open(args.input, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    outbounds, tags, used_tags = [], [], set()
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        tag = get_tag(line)
        parsed = urllib.parse.urlparse(line)
        host = parsed.hostname or ""
        
        # 🔴 Фильтр 1: Пропуск заблокированных CN-серверов
        if is_cn_node(tag, host):
            print(f"⏭️ Пропущен CN-узел: {tag}")
            continue
        
        # 🔴 Фильтр 2: Пропуск Shadowsocks
        if line.startswith('ss://'):
            continue
        
        try:
            if line.startswith('trojan://'):
                outbound = parse_trojan(line)
            elif line.startswith('vless://'):
                outbound = parse_vless(line)
            elif line.startswith('vmess://'):
                outbound = parse_vmess(line)
            elif line.startswith('hysteria2://'):
                outbound = parse_hysteria2_for_xray(line)
                print(f"✅ Hysteria2 добавлен: {tag}")
            else:
                continue
            
            # 🔑 Делаем тег уникальным
            outbound["tag"] = make_unique_tag(outbound["tag"], used_tags)
            outbounds.append(outbound)
            tags.append(outbound["tag"])
            
        except Exception as e:
            print(f"⚠️ Ошибка парсинга [{tag}]: {e}")
    
    # Системные outbounds: direct и block
    outbounds.append({
        "tag": "direct",
        "protocol": "freedom",
        "settings": {},
        "streamSettings": {
            "sockopt": {
                "domainStrategy": "UseIPv4",
                "tcpFastOpen": True
            }
        }
    })
    outbounds.append({
        "tag": "block",
        "protocol": "blackhole",
        "settings": {
            "response": {"type": "http"}
        }
    })
    
    # 🛡️ Сборка финального конфига
    config = {
        "log": {
            "loglevel": "debug",
            "access": "access.log",
            "error": "error.log"
        },
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
                    "destOverride": ["http", "tls", "quic"]
                }
            },
            {
                "tag": "http-inbound",
                "port": 20809,
                "protocol": "http",
                "settings": {"allowTransparent": False}
            }
        ],
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "UseIPv4",
            "rules": [
                {"type": "field", "ip": ["::/0"], "outboundTag": "block"},
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
                {"type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block"},
                {"type": "field", "domain": ["domain:local", r"regexp:\.local$"], "outboundTag": "direct"},
                {"type": "field", "inboundTag": ["socks-inbound", "http-inbound"], "balancerTag": "auto-balancer"}
            ],
            "balancers": [{
                "tag": "auto-balancer",
                "selector": tags,
                "strategy": {"type": "random"}
            }]
        },
        "policy": {
            "levels": {
                "0": {
                    "handshake": 4,
                    "connIdle": 300,
                    "uplinkOnly": 2,
                    "downlinkOnly": 4,
                    "bufferSize": 1024
                }
            }
        }
    }
    
    out_dir = os.path.dirname(args.output)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)
    
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ Конфиг создан: {args.output}")
    print(f"📊 Всего узлов: {len(tags)}")
    print(f"   └─ Уникальных тегов: {len(set(tags))}")


if __name__ == "__main__":
    main()
