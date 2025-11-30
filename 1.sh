#!/bin/bash

# Установка необходимых пакетов
apt update
apt install -y rsyslog sqlite3 jq python3 iptables-persistent

# Создание директорий
mkdir -p /var/log/security /var/lib/security /opt/security-correlation

# Копирование конфигурационных файлов
cp security-central.conf /etc/rsyslog.d/
cp *.rules /etc/rsyslog.d/

# Копирование скриптов
cp correlation_engine.sh /opt/security-correlation/
cp web_interface.py /opt/security-correlation/

# Настройка прав
chmod +x /opt/security-correlation/*.sh
chmod +x /opt/security-correlation/*.py

# Перезапуск rsyslog
systemctl restart rsyslog

# Создание systemd служб
cat > /etc/systemd/system/security-correlation.service << EOF
[Unit]
Description=Security Correlation Engine
After=network.target

[Service]
Type=simple
ExecStart=/opt/security-correlation/correlation_engine.sh
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/security-dashboard.service << EOF
[Unit]
Description=Security Events Dashboard
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/security-correlation/web_interface.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# Запуск служб
systemctl daemon-reload
systemctl enable security-correlation security-dashboard
systemctl start security-correlation security-dashboard

echo "Security system installed successfully"
echo "Dashboard available at: http://your-server:8080"
