#!/bin/bash

# Конфигурация
CONFIG_FILE="/etc/ssh_defender.conf"
LOG_FILE="/var/log/ssh_defender.log"
AUTH_LOG="/var/log/auth.log"
FAILED_THRESHOLD=5
BAN_TIME="3600"  # 1 час в секундах
WHITELIST_FILE="/etc/ssh_defender_whitelist"
PERMANENT_WHITELIST_FILE="/etc/ssh_defender_permanent_whitelist"
BLOCKED_IPS_FILE="/var/lib/ssh_defender/blocked_ips"
REPORT_FILE="/var/log/ssh_defender_report.txt"

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Функция логирования
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
    echo -e "${BLUE}[SSH Defender]${NC} $1"
}

# Функция ошибок
log_error() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: $1" >> "$LOG_FILE"
    echo -e "${RED}[SSH Defender ERROR]${NC} $1"
}

# Функция проверки зависимостей
check_dependencies() {
    local deps=("iptables" "curl" "jq" "geoip-bin")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -ne 0 ]; then
        log_error "Отсутствуют зависимости: ${missing[*]}"
        log_message "Установка недостающих пакетов..."
        apt-get update
        apt-get install -y "${missing[@]}"
    fi
}

# Функция загрузки конфигурации
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
        log_message "Конфигурация загружена из $CONFIG_FILE"
    else
        create_default_config
    fi
}

# Функция создания конфигурации по умолчанию
create_default_config() {
    cat > "$CONFIG_FILE" << EOF
# Конфигурация SSH Defender
FAILED_THRESHOLD=5
BAN_TIME=3600
AUTH_LOG="/var/log/auth.log"
LOG_FILE="/var/log/ssh_defender.log"
WHITELIST_FILE="/etc/ssh_defender_whitelist"
PERMANENT_WHITELIST_FILE="/etc/ssh_defender_permanent_whitelist"
BLOCKED_IPS_FILE="/var/lib/ssh_defender/blocked_ips"
REPORT_FILE="/var/log/ssh_defender_report.txt"
GEOIP_ENABLED=true
AUTO_UNBAN_ENABLED=true
EOF
    log_message "Создан файл конфигурации по умолчанию: $CONFIG_FILE"
}

# Функция инициализации
initialize() {
    mkdir -p /var/lib/ssh_defender
    touch "$LOG_FILE" "$BLOCKED_IPS_FILE"
    
    # Создание whitelist файлов если не существуют
    touch "$WHITELIST_FILE" "$PERMANENT_WHITELIST_FILE"
    
    # Добавление локальных IP в permanent whitelist
    if ! grep -q "127.0.0.1" "$PERMANENT_WHITELIST_FILE"; then
        echo "127.0.0.1" >> "$PERMANENT_WHITELIST_FILE"
    fi
    
    log_message "Инициализация завершена"
}

# Функция проверки whitelist
is_whitelisted() {
    local ip=$1
    
    # Проверка permanent whitelist
    if grep -q "^$ip$" "$PERMANENT_WHITELIST_FILE"; then
        return 0
    fi
    
    # Проверка temporary whitelist
    if grep -q "^$ip$" "$WHITELIST_FILE"; then
        return 0
    fi
    
    return 1
}

# Функция получения информации о IP
get_ip_info() {
    local ip=$1
    local info
    
    if [ "$GEOIP_ENABLED" = "true" ]; then
        info=$(curl -s "http://ip-api.com/json/$ip")
        country=$(echo "$info" | jq -r '.country // "Unknown"')
        city=$(echo "$info" | jq -r '.city // "Unknown"')
        isp=$(echo "$info" | jq -r '.isp // "Unknown"')
        echo "$country|$city|$isp"
    else
        echo "Unknown|Unknown|Unknown"
    fi
}

# Функция блокировки IP
ban_ip() {
    local ip=$1
    local reason=$2
    
    if is_whitelisted "$ip"; then
        log_message "IP $ip находится в whitelist, блокировка пропущена"
        return 1
    fi
    
    if iptables -C INPUT -s "$ip" -p tcp --dport 22 -j DROP 2>/dev/null; then
        log_message "IP $ip уже заблокирован"
        return 1
    fi
    
    iptables -A INPUT -s "$ip" -p tcp --dport 22 -j DROP
    local ip_info=$(get_ip_info "$ip")
    IFS='|' read -r country city isp <<< "$ip_info"
    
    log_message "Заблокирован IP: $ip - Причина: $reason - Страна: $country - Город: $city - Провайдер: $isp"
    
    # Сохранение информации о блокировке
    local ban_time=$(date '+%Y-%m-%d %H:%M:%S')
    local unban_time=$(date -d "+$BAN_TIME seconds" '+%Y-%m-%d %H:%M:%S')
    echo "$ip|$ban_time|$unban_time|$reason|$country|$city|$isp" >> "$BLOCKED_IPS_FILE"
}

# Функция разблокировки IP
unban_ip() {
    local ip=$1
    
    iptables -D INPUT -s "$ip" -p tcp --dport 22 -j DROP 2>/dev/null
    
    # Удаление из файла заблокированных IP
    grep -v "^$ip|" "$BLOCKED_IPS_FILE" > "${BLOCKED_IPS_FILE}.tmp"
    mv "${BLOCKED_IPS_FILE}.tmp" "$BLOCKED_IPS_FILE"
    
    log_message "Разблокирован IP: $ip"
}

# Функция автоматической разблокировки
auto_unban() {
    local current_time=$(date '+%Y-%m-%d %H:%M:%S')
    
    while IFS='|' read -r ip ban_time unban_time reason country city isp; do
        if [[ "$current_time" > "$unban_time" ]]; then
            unban_ip "$ip"
        fi
    done < "$BLOCKED_IPS_FILE"
}

# Функция мониторинга auth.log
monitor_auth_log() {
    log_message "Запуск мониторинга $AUTH_LOG"
    
    tail -Fn0 "$AUTH_LOG" | while read line; do
        # Поиск failed SSH attempts
        if echo "$line" | grep -q "Failed password for"; then
            local ip=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            
            if [ -n "$ip" ] && ! is_whitelisted "$ip"; then
                # Подсчет failed attempts для этого IP
                local count=$(grep "Failed password for.*$ip" "$AUTH_LOG" | wc -l)
                
                if [ "$count" -ge "$FAILED_THRESHOLD" ]; then
                    ban_ip "$ip" "Brute-force attack ($count failed attempts)"
                fi
            fi
        fi
    done
}

# Функция генерации отчета
generate_report() {
    local report_date=$(date '+%Y-%m-%d')
    local total_blocked=$(wc -l < "$BLOCKED_IPS_FILE")
    
    cat > "$REPORT_FILE" << EOF
Отчет SSH Defender - $report_date
================================

Общая статистика:
- Всего заблокированных IP: $total_blocked
- Время генерации отчета: $(date '+%Y-%m-%d %H:%M:%S')

Заблокированные IP:
$(while IFS='|' read -r ip ban_time unban_time reason country city isp; do
echo "IP: $ip"
echo "  Время блокировки: $ban_time"
echo "  Время разблокировки: $unban_time"
echo "  Причина: $reason"
echo "  Страна: $country"
echo "  Город: $city"
echo "  Провайдер: $isp"
echo "----------------------------------------"
done < "$BLOCKED_IPS_FILE")

Статистика по странам:
$(awk -F'|' '{print $5}' "$BLOCKED_IPS_FILE" | sort | uniq -c | sort -nr)

EOF

    log_message "Сгенерирован ежедневный отчет: $REPORT_FILE"
}

# Функция управления whitelist
manage_whitelist() {
    case $1 in
        "add-temp")
            echo "$2" >> "$WHITELIST_FILE"
            log_message "Добавлен временный IP в whitelist: $2"
            ;;
        "add-perm")
            echo "$2" >> "$PERMANENT_WHITELIST_FILE"
            log_message "Добавлен постоянный IP в whitelist: $2"
            ;;
        "remove")
            sed -i "/^$2$/d" "$WHITELIST_FILE" "$PERMANENT_WHITELIST_FILE"
            log_message "Удален IP из whitelist: $2"
            ;;
        "list")
            echo "Постоянные IP:"
            cat "$PERMANENT_WHITELIST_FILE"
            echo -e "\nВременные IP:"
            cat "$WHITELIST_FILE"
            ;;
        *)
            echo "Использование: manage_whitelist {add-temp|add-perm|remove|list} [ip]"
            ;;
    esac
}

# Функция показа статуса
show_status() {
    echo -e "${GREEN}=== Статус SSH Defender ===${NC}"
    echo "Заблокированные IP:"
    iptables -L INPUT -n | grep DROP | grep -E "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" || echo "Нет заблокированных IP"
    echo -e "\nВсего в базе: $(wc -l < "$BLOCKED_IPS_FILE") IP"
}

# Главная функция
main() {
    case $1 in
        "start")
            log_message "Запуск SSH Defender..."
            check_dependencies
            load_config
            initialize
            monitor_auth_log
            ;;
        "stop")
            log_message "Остановка SSH Defender..."
            pkill -f "tail -Fn0 $AUTH_LOG"
            ;;
        "status")
            show_status
            ;;
        "whitelist")
            manage_whitelist "$2" "$3"
            ;;
        "report")
            generate_report
            ;;
        "unban")
            unban_ip "$2"
            ;;
        "auto-unban")
            auto_unban
            ;;
        *)
            echo "Использование: $0 {start|stop|status|whitelist|report|unban|auto-unban}"
            echo "  start              - Запуск мониторинга"
            echo "  stop               - Остановка мониторинга"
            echo "  status             - Показать статус"
            echo "  whitelist add-temp IP - Добавить временный IP в whitelist"
            echo "  whitelist add-perm IP - Добавить постоянный IP в whitelist"
            echo "  whitelist remove IP   - Удалить IP из whitelist"
            echo "  whitelist list        - Показать whitelist"
            echo "  report              - Сгенерировать отчет"
            echo "  unban IP            - Разблокировать IP"
            echo "  auto-unban          - Автоматическая разблокировка"
            ;;
    esac
}

# Запуск главной функции
main "$@"
