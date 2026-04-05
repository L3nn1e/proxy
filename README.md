# Generate TLS-hardened config (NO DNS section)
python3 converet.py --test --timeout 2.5 \
  xeovo-any-URL_List_All_Protocols.txt /usr/local/etc/xray/config.json

# Restart Xray
systemctl restart xray
