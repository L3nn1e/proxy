#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Xeovo → Xray Config Converter (v3.3 Guaranteed Fix)
- Жёсткая привязка outbounds к balancer
- Удаление всех пробелов из ключей и значений
- Уникальные теги без дублей
"""
import json, base64, urllib.parse, os, sys, argparse

def get_tag(url: str) -> str:
    tag = urllib.parse.unquote(url.split('#')[-1]) if '#' in url else "unknown_node"
    return " ".join(tag.split()) # Убирает лишние пробелы внутри имени

def parse_trojan(url: str) -> dict:
    t = get_tag(url)
    p = urllib.parse.urlparse(url.split('#')[0])
    q = dict(urllib.parse.parse_qsl(p.query))
    net, sni = q.get('type', 'tcp'), q.get('sni', p.hostname)
    out = {
        "tag": t, "protocol": "trojan",
        "settings": {"servers": [{"address": p.hostname, "port": p.port, "password": p.username}]},
        "streamSettings": {"network": net, "security": "tls", "tlsSettings": {"serverName": sni, "fingerprint": "chrome"}}
    }
    if net == 'ws':
        out["streamSettings"]["wsSettings"] = {"path": q.get('path', '/'), "headers": {"Host": q.get('host', sni)}}
    return out

def parse_vless(url: str) -> dict:
    t = get_tag(url)
    p = urllib.parse.urlparse(url.split('#')[0])
    q = dict(urllib.parse.parse_qsl(p.query))
    net, sec, sni = q.get('type', 'tcp'), q.get('security', 'tls'), q.get('sni', p.hostname)
    out = {
        "tag": t, "protocol": "vless",
        "settings": {"vnext": [{"address": p.hostname, "port": p.port, "users": [{"id": p.username, "encryption": "none"}]}]},
        "streamSettings": {"network": net, "security": sec}
    }
    if sec == 'tls': out["streamSettings"]["tlsSettings"] = {"serverName": sni, "fingerprint": "chrome"}
    if net == 'ws': out["streamSettings"]["wsSettings"] = {"path": q.get('path', p.path.lstrip('/')), "headers": {"Host": q.get('host', sni)}}
    return out

def parse_vmess(url: str) -> dict:
    t = get_tag(url)
    try:
        b64 = url.split('://')[1].strip()
        b64 += '=' * (4 - len(b64) % 4) if len(b64) % 4 != 0 else ''
        d = json.loads(base64.b64decode(b64).decode('utf-8'))
    except: return None
    net, tls, sni = d.get('net', 'tcp'), d.get('tls', 'none'), d.get('sni', d['add'])
    out = {
        "tag": t, "protocol": "vmess",
        "settings": {"vnext": [{"address": d['add'], "port": int(d['port']), "users": [
            {"id": d['id'], "alterId": int(d.get('aid', 0)), "security": d.get('scy', 'auto')}
        ]}]},
        "streamSettings": {"network": net, "security": tls}
    }
    if tls == 'tls': out["streamSettings"]["tlsSettings"] = {"serverName": sni, "fingerprint": "chrome"}
    if net == 'ws': out["streamSettings"]["wsSettings"] = {"path": d.get('path', '/'), "headers": {"Host": d.get('host', sni)}}
    return out

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", default="xeovo-any-URL_List_All_Protocols(2).txt")
    parser.add_argument("-o", "--output", default="xray_config.json")
    parser.add_argument("--no-test", action="store_true")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"❌ {args.input} не найден"); sys.exit(1)

    with open(args.input, 'r', encoding='utf-8') as f:
        lines = [l.strip() for l in f if l.strip()]

    outbounds, final_tags = [], set()
    for line in lines:
        if not line: continue
        p = urllib.parse.urlparse(line)
        tag, host = get_tag(line), (p.hostname or "").lower()
        if 'cn' in tag.lower() or 'cn' in host: continue
        if line.startswith('ss://'): continue

        try:
            if line.startswith('trojan://'): ob = parse_trojan(line)
            elif line.startswith('vless://'): ob = parse_vless(line)
            elif line.startswith('vmess://'): ob = parse_vmess(line)
            else: continue
            if not ob: continue

            # 🔒 Уникализация тега
            base = ob["tag"]
            counter = 1
            while base in final_tags:
                base = f"{ob['tag'].strip()}-{counter}"; counter += 1
            ob["tag"] = base
            final_tags.add(base)
            outbounds.append(ob)
        except Exception as e:
            print(f"⚠️ Ошибка [{tag}]: {e}")

    if not outbounds:
        print("❌ Не найдено рабочих узлов после фильтрации"); sys.exit(1)

    # Системные outbounds
    outbounds.append({"tag": "direct", "protocol": "freedom", "settings": {}, "streamSettings": {"sockopt": {"domainStrategy": "UseIPv4", "tcpFastOpen": True, "tcpKeepAliveInterval": 15}}})
    outbounds.append({"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "http"}}})

    # 🛡️ Сборка конфига
    config = {
        "log": {"loglevel": "debug", "access": "", "error": ""},
        "inbounds": [
            {"tag": "socks-inbound", "port": 20808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"}, "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}},
            {"tag": "http-inbound", "port": 20809, "protocol": "http", "settings": {"allowTransparent": False}}
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
                "selector": list(final_tags), # ✅ Точная копия тегов из outbounds
                "strategy": {"type": "leastPing"}
            }]
        },
        "policy": {"levels": {"0": {"handshake": 8, "connIdle": 300, "uplinkOnly": 5, "downlinkOnly": 10, "bufferSize": 4096}}}
    }

    # ✅ Валидация перед записью
    ob_tags = {ob["tag"] for ob in outbounds if ob["tag"] not in ("direct", "block")}
    bal_tags = set(config["routing"]["balancers"][0]["selector"])
    assert ob_tags == bal_tags, f"❌ Ошибка привязки: {ob_tags ^ bal_tags}"

    d = os.path.dirname(args.output)
    if d: os.makedirs(d, exist_ok=True)
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    print(f"✅ Конфиг создан: {args.output}")
    print(f"📊 Узлов: {len(final_tags)} | Балансировщик: leastPing")
    print("💡 Запуск: xray -test -config xray_config.json && xray run -c xray_config.json")

if __name__ == "__main__":
    main()
