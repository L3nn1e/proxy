#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import base64
import urllib.parse
import os
import sys
import argparse

def get_tag(url):
    """Извлекает и декодирует название узла из URL."""
    if '#' in url:
        return urllib.parse.unquote(url.split('#')[-1])
    return "unknown_node"

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
        "tag": tag,
        "protocol": "trojan",
        "settings": {"servers": [{"address": host, "port": port, "password": password}]},
        "streamSettings": {
            "network": net,
            "security": "tls",
            "tlsSettings": {"serverName": sni, "fingerprint": "chrome"}
        }
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
        "tag": tag,
        "protocol": "vless",
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

def parse_hysteria2(url):
    tag = get_tag(url)
    parsed = urllib.parse.urlparse(url.split('#')[0])
    host, port = parsed.hostname, parsed.port
    password = urllib.parse.unquote(parsed.username)
    query = dict(urllib.parse.parse_qsl(parsed.query))
    sni = query.get('sni', host)

    return {
        "tag": tag,
        "protocol": "hysteria2",
        "settings": {"servers": [{"address": host, "port": port, "password": password}]},
        "streamSettings": {
            "network": "hysteria2",
            "security": "tls",
            "tlsSettings": {"serverName": sni, "fingerprint": "chrome"},
            "hysteria2Settings": {"up_mbps": 100, "down_mbps": 100}
        }
    }

def main():
    parser = argparse.ArgumentParser(description="Конвертация подписки Xeovo в конфиг Xray")
    parser.add_argument("-i", "--input", default="xeovo-any-URL_List_All_Protocols(2).txt", 
                        help="Путь к входному файлу подписки (txt)")
    parser.add_argument("-o", "--output", default="xray_config.json", 
                        help="Путь к выходному файлу конфига (json)")
    args = parser.parse_args()

    input_file = args.input
    output_file = args.output

    if not os.path.exists(input_file):
        print(f"❌ Ошибка: файл {input_file} не найден.")
        sys.exit(1)

    with open(input_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    outbounds, tags = [], []

    for line in lines:
        line = line.strip()
        if not line: continue

        tag = get_tag(line).lower()
        host = (urllib.parse.urlparse(line).hostname or "").lower()

        # 1. Пропуск заблокированных CN-серверов
        if 'cn' in tag or 'cn' in host:
            print(f"⏭️ Пропущен CN-узел: {line}")
            continue

        # 2. Пропуск протокола Shadowsocks
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
                outbounds.append(parse_hysteria2(line))
            else:
                continue
            
            tags.append(outbounds[-1]['tag'])
        except Exception as e:
            print(f"⚠️ Ошибка парсинга строки: {e}")

    # Добавляем системные outbounds
    outbounds.append({"tag": "direct", "protocol": "freedom", "settings": {}, "streamSettings": {"sockopt": {"domainStrategy": "UseIPv4"}}})
    outbounds.append({"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "http"}}})

    # Сборка конфига: высокий лог, предотвращение IPv6 утечек (DNS удалён)
    config = {
        "log": {"loglevel": "debug", "access": "access.log", "error": "error.log"},
        "inbounds": [
            {"tag": "socks-inbound", "port": 20808, "protocol": "socks", 
             "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}},
            {"tag": "http-inbound", "port": 20809, "protocol": "http", 
             "settings": {"allowTransparent": False}}
        ],
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "UseIPv4",
            "rules": [
                # Жёсткая блокировка всех IPv6 адресов
                {"type": "field", "ip": ["::/0"], "outboundTag": "block"},
                # Блокировка приватных сетей и рекламы
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
                {"type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block"},
                {"type": "field", "domain": ["domain:local", "regexp:\.local$"], "outboundTag": "direct"},
                # Балансировщик для входящих соединений
                {"type": "field", "inboundTag": ["socks-inbound", "http-inbound"], "balancerTag": "auto-balancer"}
            ],
            "balancers": [{"tag": "auto-balancer", "selector": tags, "strategy": {"type": "random"}}]
        },
        "policy": {"levels": {"0": {"handshake": 4, "connIdle": 300, "uplinkOnly": 2, "downlinkOnly": 4, "bufferSize": 1024}}}
    }

    # Создаём директории для output, если их нет
    out_dir = os.path.dirname(output_file)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ Конфиг успешно создан: {output_file}")
    print(f"📊 Обработано узлов: {len(tags)} (Shadowsocks и CN-серверы исключены)")

if __name__ == "__main__":
    main()
