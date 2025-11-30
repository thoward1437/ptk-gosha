#!/bin/bash

# Цветовое оформление для экрана
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Переменные
LOG_DIR="/var/log/security_audit"
REPORT_FILE="$LOG_DIR/security_audit_$(date +%Y%m%d).log"
SCORE=100
MAX_SCORE=100

# Создание директории для логов
mkdir -p "$LOG_DIR"

# Функция для удаления цветовых кодов
remove_colors() {
    echo "$1" | sed -E 's/\x1B\[[0-9;]*[mGK]//g'
}

# Функция для добавления в отчет (без цветов)
add_to_report() {
    local clean_output=$(remove_colors "$1")
    echo -e "$clean_output" >> "$REPORT_FILE"
}

# Функция для вывода на экран (с цветами)
print_message() {
    echo -e "$1"
}

# Функция для снижения оценки
deduct_score() {
    SCORE=$((SCORE - $1))
}

# Заголовок отчета
echo "================================================================================
ЕЖЕДНЕВНЫЙ АУДИТ БЕЗОПАСНОСТИ СИСТЕМЫ
Дата: $(date)
Хост: $(hostname)
================================================================================
" > "$REPORT_FILE"

add_to_report "ОТЧЕТ АУДИТА БЕЗОПАСНОСТИ\n"

# Раздел 1: Обновления системы
print_message "${BLUE}=== ОБНОВЛЕНИЯ СИСТЕМЫ ===${NC}"
add_to_report "=== ОБНОВЛЕНИЯ СИСТЕМЫ ==="

# Проверка обновлений безопасности
add_to_report "Проверка доступных обновлений безопасности..."
if command -v apt-get &> /dev/null; then
    apt-get update > /dev/null 2>&1
    security_updates=$(apt list --upgradable 2>/dev/null | grep -i security | wc -l)
    all_updates=$(apt list --upgradable 2>/dev/null | wc -l)
    
    add_to_report "Доступные обновления безопасности: $security_updates"
    add_to_report "Всего доступных обновлений: $((all_updates - 1))"
    
    if [ "$security_updates" -gt 0 ]; then
        add_to_report "ВНИМАНИЕ: Имеются не установленные обновления безопасности!"
        print_message "${YELLOW}ВНИМАНИЕ: Имеются не установленные обновления безопасности!${NC}"
        deduct_score 10
    else
        add_to_report "✓ Все обновления безопасности установлены"
        print_message "${GREEN}✓ Все обновления безопасности установлены${NC}"
    fi
else
    add_to_report "ОШИБКА: Не найден apt-get"
    print_message "${RED}ОШИБКА: Не найден apt-get${NC}"
    deduct_score 5
fi

add_to_report ""

# Раздел 2: Пользователи и права
print_message "${BLUE}=== ПОЛЬЗОВАТЕЛИ И ПРАВА ===${NC}"
add_to_report "=== ПОЛЬЗОВАТЕЛИ И ПРАВА ==="

# Пользователи с UID 0 (кроме root)
add_to_report "Поиск пользователей с UID 0 (кроме root):"
uid0_users=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd)
if [ -z "$uid0_users" ]; then
    add_to_report "✓ Нет пользователей с UID 0 кроме root"
    print_message "${GREEN}✓ Нет пользователей с UID 0 кроме root${NC}"
else
    add_to_report "КРИТИЧЕСКО: Найдены пользователи с UID 0:"
    add_to_report "$uid0_users"
    print_message "${RED}КРИТИЧЕСКО: Найдены пользователи с UID 0:${NC}"
    print_message "$uid0_users"
    deduct_score 20
fi

# Пользователи с пустыми паролями
add_to_report "Проверка пользователей с пустыми паролями:"
empty_password=$(awk -F: '($2 == "") {print $1}' /etc/shadow)
if [ -z "$empty_password" ]; then
    add_to_report "✓ Нет пользователей с пустыми паролями"
    print_message "${GREEN}✓ Нет пользователей с пустыми паролями${NC}"
else
    add_to_report "КРИТИЧЕСКО: Найдены пользователи с пустыми паролями:"
    add_to_report "$empty_password"
    print_message "${RED}КРИТИЧЕСКО: Найдены пользователи с пустыми паролями:${NC}"
    print_message "$empty_password"
    deduct_score 25
fi

# Последние входы
add_to_report "Последние успешные входы:"
last_logins=$(last -n 5)
add_to_report "$last_logins"

add_to_report ""

# Остальные разделы аналогично...

# Раздел 6: Оценка безопасности
print_message "${BLUE}=== ОЦЕНКА БЕЗОПАСНОСТИ ===${NC}"
add_to_report "=== ОЦЕНКА БЕЗОПАСНОСТИ ==="

# Расчет оценки
if [ $SCORE -lt 0 ]; then
    SCORE=0
fi

percentage=$((SCORE * 100 / MAX_SCORE))

# Определение буквенной оценки
if [ $percentage -ge 90 ]; then
    GRADE="A"
    COLOR=$GREEN
    COLOR_TEXT="ОТЛИЧНО"
elif [ $percentage -ge 80 ]; then
    GRADE="B"
    COLOR=$GREEN
    COLOR_TEXT="ХОРОШО"
elif [ $percentage -ge 70 ]; then
    GRADE="C"
    COLOR=$YELLOW
    COLOR_TEXT="УДОВЛЕТВОРИТЕЛЬНО"
elif [ $percentage -ge 60 ]; then
    GRADE="D"
    COLOR=$YELLOW
    COLOR_TEXT="НИЖЕ СРЕДНЕГО"
else
    GRADE="F"
    COLOR=$RED
    COLOR_TEXT="КРИТИЧЕСКИ"
fi

add_to_report "Результаты оценки безопасности:"
add_to_report "Набрано баллов: $SCORE/$MAX_SCORE"
add_to_report "Процент выполнения: $percentage%"
add_to_report "ОЦЕНКА БЕЗОПАСНОСТИ: $GRADE ($COLOR_TEXT)"

print_message "Результаты оценки безопасности:"
print_message "Набрано баллов: $SCORE/$MAX_SCORE"
print_message "Процент выполнения: $percentage%"
print_message "${COLOR}ОЦЕНКА БЕЗОПАСНОСТИ: $GRADE ($COLOR_TEXT)${NC}"

# Завершение отчета
add_to_report "\n================================================================================
Аудит завершен: $(date)
Отчет сохранен в: $REPORT_FILE
================================================================================"

print_message "\n${GREEN}Аудит безопасности завершен.${NC}"
print_message "Отчет сохранен в: $REPORT_FILE"
print_message "${COLOR}Оценка безопасности: $GRADE ($percentage%)${NC}"

# Создание симлинка на последний отчет
ln -sf "$REPORT_FILE" "$LOG_DIR/security_audit_latest.log"

# Установка прав на файлы
chmod 600 "$LOG_DIR"/*.log 2>/dev/null

exit 0
