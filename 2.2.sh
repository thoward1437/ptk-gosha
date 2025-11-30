#!/bin/bash

# Конфигурация
LOG_FILE="/var/log/suspicious_process_monitor.log"
ALERT_THRESHOLD=10
EVIDENCE_DIR="/var/forensics/evidence_$(date +%Y%m%d_%H%M%S)"
SCORE_FILE="/tmp/threat_scores.txt"

# Проверка поддерживается ли цветной вывод
if [ -t 1 ]; then
    # Цвета для вывода в терминал
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m' # No Color
else
    # Без цветов для systemd/journal
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# Инициализация
init_monitor() {
    mkdir -p "$EVIDENCE_DIR"
    touch "$LOG_FILE" "$SCORE_FILE"
    log_info "Мониторинг запущен"
}

# Логирование информации
log_info() {
    echo -e "${GREEN}$(date): $1${NC}"
    echo "$(date): $1" >> "$LOG_FILE"
}

# Логирование отладочной информации
log_debug() {
    echo -e "${BLUE}$(date): $1${NC}"
    echo "$(date): $1" >> "$LOG_FILE"
}

# Логирование предупреждений
log_warning() {
    echo -e "${YELLOW}$(date): ВНИМАНИЕ: $1${NC}"
    echo "$(date): ВНИМАНИЕ: $1" >> "$LOG_FILE"
}

# Логирование угроз
log_threat() {
    echo -e "${RED}$(date): УГРОЗА: $1${NC}"
    echo "$(date): УГРОЗА: $1" >> "$LOG_FILE"
}

# Система scoring
add_threat_score() {
    local pid=$1
    local score=$2
    local reason=$3
    
    current_score=$(grep "^$pid:" "$SCORE_FILE" | cut -d: -f2 2>/dev/null || echo 0)
    new_score=$((current_score + score))
    
    grep -v "^$pid:" "$SCORE_FILE" > "$SCORE_FILE.tmp" 2>/dev/null
    echo "$pid:$new_score:$reason" >> "$SCORE_FILE.tmp"
    mv "$SCORE_FILE.tmp" "$SCORE_FILE"
    
    log_warning "Процесс $pid: +$score баллов ($reason). Всего: $new_score"
    
    if [ $new_score -ge $ALERT_THRESHOLD ]; then
        log_threat "Процесс $pid достиг порога угрозы: $new_score баллов"
        send_alert "$pid" "$new_score" "$reason"
        collect_evidence "$pid"
    fi
}

# Отправка уведомления
send_alert() {
    local pid=$1
    local score=$2
    local reason=$3
    
    message="ВЫСОКИЙ УРОВЕНЬ УГРОЗЫ: Процесс $pid набрал $score баллов. Причина: $reason"
    log_threat "$message"
    logger -p alert "$message"
}

# Сбор доказательств
collect_evidence() {
    local pid=$1
    
    log_info "Сбор доказательств для процесса $pid"
    
    # lsof
    if lsof -p "$pid" > "$EVIDENCE_DIR/lsof_$pid.txt" 2>/dev/null; then
        log_debug "  - lsof сохранен"
    fi
    
    # process info
    if ps -fp "$pid" > "$EVIDENCE_DIR/ps_$pid.txt" 2>/dev/null; then
        log_debug "  - ps info сохранен"
    fi
    
    if cat /proc/"$pid"/cmdline 2>/dev/null | tr '\0' ' ' > "$EVIDENCE_DIR/cmdline_$pid.txt" 2>/dev/null; then
        log_debug "  - cmdline сохранен"
    fi
    
    # network connections
    if ss -tunp 2>/dev/null | grep "pid=$pid" > "$EVIDENCE_DIR/network_$pid.txt" 2>/dev/null; then
        log_debug "  - network info сохранен"
    fi
    
    # executable info
    if ls -la /proc/"$pid"/exe 2>/dev/null > "$EVIDENCE_DIR/exe_$pid.txt" 2>/dev/null; then
        log_debug "  - exe info сохранен"
    fi
    
    log_info "Доказательства сохранены в $EVIDENCE_DIR"
}

# Проверка скрытых процессов (исправленная - исключаем легитимные kworker)
check_hidden_processes() {
    log_debug "Проверка скрытых процессов..."
    ps -eo pid,comm,args --no-headers | while read -r pid comm args; do
        if [[ "$pid" =~ ^[0-9]+$ ]] && [ "$pid" -gt 1000 ]; then  # Только процессы с PID > 1000
            # Исключаем легитимные kworker процессы
            if [[ "$comm" =~ ^\[.*\]$ ]] && [[ ! "$comm" =~ ^\[kworker ]]; then
                add_threat_score "$pid" 3 "Скрытое имя процесса: $comm (args: $args)"
            elif [[ "$args" =~ ^\[.*\]$ ]] && [[ ! "$args" =~ ^\[kworker ]]; then
                add_threat_score "$pid" 3 "Скрытые аргументы процесса: $args"
            fi
        fi
    done
}

# Проверка необычных сетевых соединений
check_suspicious_connections() {
    log_debug "Проверка сетевых соединений..."
    ss -tunp 2>/dev/null | grep -v "pid=" | while read -r line; do
        # Извлекаем PID из строки
        pid=$(echo "$line" | grep -o 'pid=[0-9]*' | cut -d= -f2)
        
        if [[ "$pid" =~ ^[0-9]+$ ]] && [ "$pid" -gt 1000 ]; then
            # Проверяем подозрительные порты
            if echo "$line" | grep -qE ':(443|80|22|4444|1337|31337)[^0-9]'; then
                add_threat_score "$pid" 2 "Подозрительное сетевое соединение: $line"
            fi
            
            # Проверяем обратные shell (исходящие соединения на нестандартные порты)
            if echo "$line" | grep -q "ESTAB" && echo "$line" | grep -qE ':[0-9]{4,5}->'; then
                remote_port=$(echo "$line" | grep -oE ':[0-9]{4,5}->' | cut -d: -f2 | cut -d- -f1)
                if [ "$remote_port" -gt 1024 ] && [ "$remote_port" -ne 443 ] && [ "$remote_port" -ne 80 ]; then
                    add_threat_score "$pid" 3 "Возможный обратный shell на порт $remote_port"
                fi
            fi
        fi
    done
}

# Проверка использования ресурсов
check_resource_usage() {
    log_debug "Проверка использования ресурсов..."
    ps -eo pid,%cpu,%mem --no-headers | while read -r pid cpu mem; do
        if [[ "$pid" =~ ^[0-9]+$ ]] && [ "$pid" -gt 1000 ]; then
            # Проверяем CPU (используем bc для дробных чисел)
            cpu_check=$(echo "$cpu > 50.0" | bc 2>/dev/null)
            mem_check=$(echo "$mem > 20.0" | bc 2>/dev/null)
            
            if [ "$cpu_check" -eq 1 ] 2>/dev/null; then
                add_threat_score "$pid" 2 "Высокая загрузка CPU: ${cpu}%"
            fi
            
            if [ "$mem_check" -eq 1 ] 2>/dev/null; then
                add_threat_score "$pid" 2 "Высокое использование памяти: ${mem}%"
            fi
        fi
    done
}

# Проверка исполнения из временных директорий
check_temp_execution() {
    log_debug "Проверка исполнения из /tmp и /dev/shm..."
    find /proc -maxdepth 2 -name "exe" -type l 2>/dev/null | while read -r exe_link; do
        pid=$(echo "$exe_link" | cut -d/ -f3)
        if [[ "$pid" =~ ^[0-9]+$ ]] && [ "$pid" -gt 1000 ]; then
            real_exe=$(readlink "$exe_link" 2>/dev/null)
            if [[ "$real_exe" == "/tmp/"* ]] || [[ "$real_exe" == "/dev/shm/"* ]]; then
                add_threat_score "$pid" 5 "Исполнение из временной директории: $real_exe"
            fi
        fi
    done
}

# Проверка скрытых сокетов
check_hidden_sockets() {
    log_debug "Проверка скрытых сокетов..."
    # Поиск LISTEN сокетов без связанных процессов
    ss -lntu 2>/dev/null | grep "LISTEN" | grep -v "pid=" | while read -r line; do
        log_warning "Обнаружен скрытый сокет: $line"
        echo "$line" >> "$EVIDENCE_DIR/hidden_sockets.txt"
    done
}

# Очистка старых записей scoring
cleanup_old_scores() {
    # Удаляем записи процессов, которые уже завершились
    if [ -f "$SCORE_FILE" ]; then
        tmp_file=$(mktemp)
        while IFS=: read -r pid score reason; do
            if [[ "$pid" =~ ^[0-9]+$ ]] && [ -d "/proc/$pid" ]; then
                echo "$pid:$score:$reason" >> "$tmp_file"
            fi
        done < "$SCORE_FILE"
        mv "$tmp_file" "$SCORE_FILE" 2>/dev/null
    fi
}

# Показать текущие оценки угроз
show_threat_scores() {
    if [ -f "$SCORE_FILE" ] && [ -s "$SCORE_FILE" ]; then
        log_info "Текущие оценки угроз:"
        while IFS=: read -r pid score reason; do
            if [ -d "/proc/$pid" ]; then
                process_name=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
                if [ "$score" -ge "$ALERT_THRESHOLD" ]; then
                    echo -e "  ${RED}PID: $pid ($process_name) - $score баллов - $reason${NC}"
                elif [ "$score" -ge 5 ]; then
                    echo -e "  ${YELLOW}PID: $pid ($process_name) - $score баллов - $reason${NC}"
                else
                    echo -e "  ${BLUE}PID: $pid ($process_name) - $score баллов - $reason${NC}"
                fi
            fi
        done < "$SCORE_FILE"
    else
        log_info "Активных угроз не обнаружено"
    fi
}

# Основной цикл мониторинга
main_loop() {
    local iteration=0
    while true; do
        iteration=$((iteration + 1))
        log_info "=== Итерация сканирования #$iteration ==="
        
        cleanup_old_scores
        check_hidden_processes
        check_suspicious_connections
        check_resource_usage
        check_temp_execution
        check_hidden_sockets
        show_threat_scores
        
        log_debug "Следующее сканирование через 30 секунд..."
        sleep 30
    done
}

# Запуск мониторинга
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Требуются права root для полного мониторинга${NC}"
    exit 1
fi

# Проверка наличия bc для вычислений
if ! command -v bc &> /dev/null; then
    echo -e "${RED}Установите bc: apt install bc${NC}"
    exit 1
fi

# Информация о запуске
if [ -t 1 ]; then
    echo -e "${GREEN}Запуск монитора подозрительных процессов...${NC}"
    echo -e "${BLUE}Лог файл: $LOG_FILE${NC}"
    echo -e "${BLUE}Директория доказательств: $EVIDENCE_DIR${NC}"
    echo -e "${BLUE}Для остановки нажмите Ctrl+C${NC}\n"
else
    echo "Запуск монитора подозрительных процессов..."
    echo "Лог файл: $LOG_FILE"
    echo "Директория доказательств: $EVIDENCE_DIR"
fi

init_monitor
main_loop
