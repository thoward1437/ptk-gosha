#!/bin/bash

echo "Установка SSH Defender..."

# Копирование основного скрипта
cp ssh_defender.sh /usr/local/bin/
chmod +x /usr/local/bin/ssh_defender.sh

# Создание системной службы
cp ssh-defender.service /etc/systemd/system/

# Создание необходимых директорий и файлов
mkdir -p /var/lib/ssh_defender
touch /var/log/ssh_defender.log
touch /etc/ssh_defender_whitelist
touch /etc/ssh_defender_permanent_whitelist

# Установка прав
chmod 644 /etc/ssh_defender_whitelist
chmod 644 /etc/ssh_defender_permanent_whitelist

# Обновление системы и установка зависимостей
apt-get update
apt-get install -y iptables curl jq geoip-bin

# Активация службы
systemctl daemon-reload
systemctl enable ssh-defender.service

echo "Установка завершена!"
echo "Для запуска выполните: systemctl start ssh-defender"
echo "Для просмотра статуса: ssh_defender.sh status"
