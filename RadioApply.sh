#!/usr/bin/env bash
# installer.sh — устанавливает apply_rules_from_url и агент автообновления правил с GitHub
# Версия с base64-правилами и декодированием на лету
set -o errexit
set -o nounset
set -o pipefail

# -----------------------
# Настройки
# -----------------------
APPLY_PATH="/usr/local/bin/apply_rules_from_url.sh"
AGENT_PATH="/usr/local/bin/iptables-agent.sh"
SERVICE_PATH="/etc/systemd/system/iptables-agent.service"
VERIFY_PATH="/usr/local/bin/verify_iptables_rules.sh"
RULES_URL="https://raw.githubusercontent.com/KOTBCTAKAHE/MusicBranch/refs/heads/main/radio_rules.b64"
SLEEP_INTERVAL=30
BACKUP_DIR="/var/backups/iptables"
LOG_DIR="/var/log/iptables-agent"

# -----------------------
# Цвета для вывода
# -----------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_step()  { echo -e "${BLUE}[STEP]${NC}  $*"; }

# -----------------------
# Привилегии
# -----------------------
if [ "$(id -u)" -ne 0 ]; then
  log_error "Этот скрипт должен быть запущен от root (sudo)."
  exit 1
fi

# -----------------------
# Создание директорий
# -----------------------
mkdir -p "$BACKUP_DIR" "$LOG_DIR"
chmod 700 "$BACKUP_DIR"

# -----------------------
# Утилиты (best-effort)
# -----------------------
install_pkg() {
  local pkg="$1"
  log_info "Устанавливаю пакет: $pkg"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y -q && apt-get install -y -q "$pkg"
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q "$pkg"
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache "$pkg"
  else
    log_error "Неизвестный пакетный менеджер — установите $pkg вручную."
    return 1
  fi
}

log_step "Проверка и установка зависимостей..."
for p in curl wget iptables; do
  if ! command -v "$p" >/dev/null 2>&1; then
    install_pkg "$p" || log_warn "Установка $p не удалась — проверьте вручную."
  else
    log_info "$p уже установлен: $(command -v "$p")"
  fi
done

# iptables-save и iptables-restore могут быть в iptables или iptables-persistent
for p in iptables-save iptables-restore; do
  if ! command -v "$p" >/dev/null 2>&1; then
    install_pkg "iptables" 2>/dev/null || true
  fi
done

# Попробуем установить iptables-persistent для сохранения правил между перезагрузками
if command -v apt-get >/dev/null 2>&1 && ! dpkg -l iptables-persistent >/dev/null 2>&1; then
  log_info "Устанавливаю iptables-persistent для сохранения правил после перезагрузки..."
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q iptables-persistent 2>/dev/null || \
    log_warn "iptables-persistent недоступен — правила могут слететь после reboot"
fi

# Проверяем модули ядра
log_step "Проверка модулей ядра..."
for mod in ip_tables iptable_filter iptable_nat nf_conntrack; do
  if ! lsmod 2>/dev/null | grep -q "^${mod}\b"; then
    modprobe "$mod" 2>/dev/null && log_info "Загружен модуль: $mod" || \
      log_warn "Не удалось загрузить модуль $mod (может быть встроен в ядро)"
  else
    log_info "Модуль $mod активен"
  fi
done

# -----------------------
# Записываем verify_iptables_rules.sh
# -----------------------
log_step "Записываю скрипт верификации правил..."
cat > "$VERIFY_PATH" <<'VERIFY_EOF'
#!/usr/bin/env bash
# verify_iptables_rules.sh — проверяет что указанные правила реально установлены в iptables
# Использование: verify_iptables_rules.sh <файл_правил> [--verbose]
set -o nounset
set -o pipefail

RULES_FILE="${1:-}"
VERBOSE=false
for arg in "${@:2}"; do
  [ "$arg" = "--verbose" ] && VERBOSE=true
done

if [ -z "$RULES_FILE" ] || [ ! -f "$RULES_FILE" ]; then
  echo "Usage: $0 <rules_file> [--verbose]"
  exit 2
fi

PASS=0
FAIL=0
SKIP=0
FAIL_LINES=()

while IFS= read -r rawline || [ -n "$rawline" ]; do
  line="$(printf '%s\n' "$rawline" | sed -E 's/#.*$//' | sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//')"
  [ -z "$line" ] && continue

  # Проверяем только те правила, для которых имеет смысл iptables -C
  if [[ ! "$line" =~ ^iptables ]]; then
    SKIP=$((SKIP+1))
    $VERBOSE && echo "[SKIP] $line"
    continue
  fi

  if [[ "$line" =~ ^iptables([[:space:]]+-t[[:space:]]+(filter|nat|mangle|raw|security))?[[:space:]]+-(A|I|D)[[:space:]]+ ]]; then
    # Строим команду проверки: -A/-I/-D -> -C
    check_line="$(printf '%s\n' "$line" | sed -E 's/^iptables( -t [a-z]+)? -[AID] /iptables\1 -C /')"

    if eval "$check_line" >/dev/null 2>&1; then
      PASS=$((PASS+1))
      $VERBOSE && echo "[OK]   $line"
    else
      FAIL=$((FAIL+1))
      FAIL_LINES+=("$line")
      $VERBOSE && echo "[MISS] $line"
    fi
  else
    SKIP=$((SKIP+1))
    $VERBOSE && echo "[SKIP] $line"
  fi
done < "$RULES_FILE"

echo "Верификация: OK=$PASS  MISS=$FAIL  SKIP=$SKIP"

if [ "$FAIL" -gt 0 ]; then
  echo "Не найдены следующие правила:"
  for fl in "${FAIL_LINES[@]}"; do
    echo "  - $fl"
  done
  exit 1
fi

exit 0
VERIFY_EOF

chmod 755 "$VERIFY_PATH"
log_info "Записан: $VERIFY_PATH"

# -----------------------
# Записываем apply_rules_from_url.sh
# -----------------------
log_step "Записываю основной скрипт применения правил..."
cat > "$APPLY_PATH" <<APPLY_EOF
#!/usr/bin/env bash
# apply_rules_from_url — robust version with base64 decode
set -o nounset
set -o pipefail

DEFAULT_RULES_URL="${RULES_URL}"
RULES_URL_ARG="\${1:-\$DEFAULT_RULES_URL}"
DRY_RUN=false
CONTINUE_ON_ERROR=false
SKIP_VERIFY=false

for arg in "\${@:2}"; do
  case "\$arg" in
    --dry-run)           DRY_RUN=true ;;
    --continue-on-error)  CONTINUE_ON_ERROR=true ;;
    --skip-verify)       SKIP_VERIFY=true ;;
    *) echo "Unknown option: \$arg"; exit 2 ;;
  esac
done

LOG="${LOG_DIR}/apply_rules.log"
BACKUP_DIR="${BACKUP_DIR}"
VERIFY_SCRIPT="${VERIFY_PATH}"

exec > >(tee -a "\$LOG") 2>&1

TS="\$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo ""
echo "=========================================================="
echo "=== apply_rules_from_url started: \$TS ==="
echo "=== Source: \$RULES_URL_ARG ==="
echo "=== dry-run=\$DRY_RUN continue-on-error=\$CONTINUE_ON_ERROR ==="
echo "=========================================================="

if [ "\$(id -u)" -ne 0 ]; then
  echo "ERROR: This script must be run as root (sudo)."
  exit 3
fi

TMP_DIR="\$(mktemp -d)"
RULES_RAW="\$TMP_DIR/rls.raw"
RULES_DECODED="\$TMP_DIR/rls.decoded"
RULES_FILE="\$TMP_DIR/rls.normalized"
BACKUP_FILE="\$BACKUP_DIR/iptables.backup.\$(date +%s)"

cleanup() {
  rm -rf "\$TMP_DIR"
}
trap cleanup EXIT

decode_base64_if_possible() {
  local src="\$1"
  local dst="\$2"

  if base64 -d < "\$src" > "\$dst" 2>/dev/null; then
    return 0
  fi

  if base64 --decode < "\$src" > "\$dst" 2>/dev/null; then
    return 0
  fi

  return 1
}

# ----------------------------------------------------------
# 1. Определяем основной исходящий интерфейс
# ----------------------------------------------------------
OUT_IF="\$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++){if(\$i=="dev"){print \$(i+1); exit}}}')"
OUT_IF="\${OUT_IF:-eth0}"
echo "[PRE] Исходящий интерфейс: \$OUT_IF"

# ----------------------------------------------------------
# 2. Загружаем правила
# ----------------------------------------------------------
echo "[FETCH] Получаю правила из: \$RULES_URL_ARG"
if [ -f "\$RULES_URL_ARG" ]; then
  echo "[FETCH] Источник — локальный файл"
  cp "\$RULES_URL_ARG" "\$RULES_RAW"
else
  FETCH_OK=0
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --max-time 20 --retry 3 --retry-delay 2 "\$RULES_URL_ARG" -o "\$RULES_RAW" && FETCH_OK=1
  fi
  if [ "\$FETCH_OK" -eq 0 ] && command -v wget >/dev/null 2>&1; then
    wget -qO "\$RULES_RAW" "\$RULES_URL_ARG" && FETCH_OK=1
  fi
  if [ "\$FETCH_OK" -eq 0 ]; then
    echo "[FETCH] ERROR: Не удалось загрузить правила"
    exit 4
  fi
fi

if [ ! -s "\$RULES_RAW" ]; then
  echo "[FETCH] ERROR: Файл правил пустой"
  exit 4
fi

echo "[FETCH] Загружено байт: \$(wc -c < "\$RULES_RAW")"

# ----------------------------------------------------------
# 3. Декодирование base64
# ----------------------------------------------------------
echo "[DECODE] Пытаюсь декодировать base64..."
if decode_base64_if_possible "\$RULES_RAW" "\$RULES_DECODED"; then
  mv "\$RULES_DECODED" "\$RULES_RAW"
  echo "[DECODE] OK: base64 успешно декодирован"
else
  echo "[DECODE] WARN: base64-декодирование не удалось, использую файл как есть"
fi

# ----------------------------------------------------------
# 4. Нормализация правил
# ----------------------------------------------------------
tr -d '\r' < "\$RULES_RAW" > "\$RULES_RAW.nocr"

sed -E 's/[[:space:]]*iptables/\
iptables/g' "\$RULES_RAW.nocr" \
  | sed -E 's/^[[:space:]]+//; s/[[:space:]]+\$//' \
  | awk 'NF{print}' \
  > "\$RULES_FILE"

LINE_COUNT="\$(grep -c . "\$RULES_FILE" 2>/dev/null || echo 0)"
echo "[NORM] Нормализовано строк: \$LINE_COUNT"
echo "[NORM] Предпросмотр (первые 30):"
nl -ba -w3 -s'. ' "\$RULES_FILE" | sed -n '1,30p' || true

# ----------------------------------------------------------
# 5. Pre-flight: простая проверка
# ----------------------------------------------------------
echo ""
echo "[PREFLIGHT] Синтаксическая проверка правил..."
LINE_NO=0
while IFS= read -r rawline || [ -n "\$rawline" ]; do
  LINE_NO=\$((LINE_NO+1))
  line="\$(printf '%s\n' "\$rawline" | sed -E 's/#.*\$//' | sed -E 's/^[[:space:]]+//;s/[[:space:]]+\$//')"
  [ -z "\$line" ] && continue

  if [[ "\$line" =~ ^iptables ]]; then
    if echo "\$line" | grep -qE '[;&|><\`\$\(\)]'; then
      echo "[PREFLIGHT] WARN L\$LINE_NO: подозрительные символы: \$line"
    fi
    if ! echo "\$line" | grep -qE '^iptables( -t (filter|nat|mangle|raw|security))? -(A|I|D|F|P|N|X|Z|L|R|S|C|E)'; then
      echo "[PREFLIGHT] WARN L\$LINE_NO: нестандартная команда iptables: \$line"
    fi
  fi
done < "\$RULES_FILE"
echo "[PREFLIGHT] Проверка пройдена"

# ----------------------------------------------------------
# 6. Backup текущих правил
# ----------------------------------------------------------
echo ""
echo "[BACKUP] Сохраняю текущие правила в \$BACKUP_FILE"
if command -v iptables-save >/dev/null 2>&1; then
  if iptables-save > "\$BACKUP_FILE" 2>/dev/null; then
    echo "[BACKUP] OK: \$(wc -l < "\$BACKUP_FILE") строк"
    chmod 600 "\$BACKUP_FILE"
    ls -t "${BACKUP_DIR}"/iptables.backup.* 2>/dev/null | tail -n +21 | xargs -r rm -f 2>/dev/null || true
  else
    echo "[BACKUP] WARN: iptables-save завершился с ошибкой"
  fi
else
  echo "[BACKUP] WARN: iptables-save не найден, бэкап пропущен"
fi

# ----------------------------------------------------------
# 7. Защитные правила перед применением
# ----------------------------------------------------------
echo ""
echo "[SAFETY] Устанавливаю защитные правила на время применения..."

_safe_insert() {
  local chain="\$1"
  shift
  iptables -C "\$chain" "\$@" >/dev/null 2>&1 || iptables -I "\$chain" 1 "\$@" >/dev/null 2>&1 || true
}

_safe_insert OUTPUT -o lo -j ACCEPT
_safe_insert OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
_safe_insert OUTPUT -p udp --dport 53 -j ACCEPT
_safe_insert OUTPUT -p tcp --dport 53 -j ACCEPT
_safe_insert OUTPUT -p tcp --dport 80 -j ACCEPT
_safe_insert OUTPUT -p tcp --dport 443 -j ACCEPT
_safe_insert OUTPUT -p tcp --dport 22 -j ACCEPT
_safe_insert INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
_safe_insert INPUT -p tcp --dport 22 -j ACCEPT

if ! iptables -t nat -C POSTROUTING -o "\$OUT_IF" -j MASQUERADE >/dev/null 2>&1; then
  iptables -t nat -A POSTROUTING -o "\$OUT_IF" -j MASQUERADE 2>/dev/null || true
fi
echo "[SAFETY] Защитные правила установлены"

# ----------------------------------------------------------
# 8. Применяем правила построчно
# ----------------------------------------------------------
echo ""
echo "[APPLY] Применяю правила..."
LINE_NO=0
APPLY_FAIL=0
APPLIED=0
SKIPPED=0

while IFS= read -r rawline || [ -n "\$rawline" ]; do
  LINE_NO=\$((LINE_NO+1))
  line="\$(printf '%s\n' "\$rawline" | sed -E 's/#.*\$//' | sed -E 's/^[[:space:]]+//;s/[[:space:]]+\$//')"
  [ -z "\$line" ] && continue

  if \$DRY_RUN; then
    echo "[DRY L\$LINE_NO] \$line"
    APPLIED=\$((APPLIED+1))
    continue
  fi

  if [[ "\$line" =~ ^iptables || "\$line" =~ ^ip[[:space:]] ]]; then
    if eval "\$line"; then
      echo "[OK  L\$LINE_NO] \$line"
      APPLIED=\$((APPLIED+1))
    else
      EXIT_CODE=\$?
      echo "[ERR L\$LINE_NO] exit=\$EXIT_CODE cmd=\$line"
      APPLY_FAIL=1
      if [ "\$CONTINUE_ON_ERROR" = true ]; then
        echo "[ERR L\$LINE_NO] Пропускаю (--continue-on-error)"
        continue
      else
        echo "[ERR] Прерываю применение, запускаю rollback..."
        break
      fi
    fi
  else
    echo "[SKP L\$LINE_NO] \$line"
    SKIPPED=\$((SKIPPED+1))
  fi
done < "\$RULES_FILE"

echo ""
echo "[APPLY] Итого: применено=\$APPLIED  пропущено=\$SKIPPED  ошибок=\$APPLY_FAIL"

# ----------------------------------------------------------
# 9. Rollback при ошибке применения
# ----------------------------------------------------------
if [ "\$APPLY_FAIL" -eq 1 ]; then
  echo "[ROLLBACK] Ошибка применения — восстанавливаю из \$BACKUP_FILE"
  if [ -f "\$BACKUP_FILE" ]; then
    if iptables-restore < "\$BACKUP_FILE"; then
      echo "[ROLLBACK] OK: правила восстановлены"
    else
      echo "[ROLLBACK] ERROR: iptables-restore завершился с ошибкой!"
    fi
  else
    echo "[ROLLBACK] ERROR: Файл бэкапа не найден!"
  fi
  exit 5
fi

# ----------------------------------------------------------
# 10. Проверяем MASQUERADE и ip_forward
# ----------------------------------------------------------
echo ""
echo "[POST] Проверяю MASQUERADE и ip_forward..."

if ! iptables -t nat -C POSTROUTING -o "\$OUT_IF" -j MASQUERADE >/dev/null 2>&1; then
  if \$DRY_RUN; then
    echo "[POST] (dry-run) Добавил бы MASQUERADE для \$OUT_IF"
  else
    iptables -t nat -A POSTROUTING -o "\$OUT_IF" -j MASQUERADE && \
      echo "[POST] MASQUERADE добавлен" || echo "[POST] WARN: MASQUERADE не добавился"
  fi
else
  echo "[POST] MASQUERADE уже присутствует"
fi

if ! \$DRY_RUN; then
  if [ "\$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)" != "1" ]; then
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
    echo "[POST] ip_forward включён"
  else
    echo "[POST] ip_forward уже включён"
  fi

  SYSCTL_D="/etc/sysctl.d/99-iptables-agent.conf"
  cat > "\$SYSCTL_D" <<SYSCTL
net.ipv4.ip_forward = 1
net.netfilter.nf_conntrack_max = 1048576
SYSCTL
  sysctl --system >/dev/null 2>&1 || sysctl -p >/dev/null 2>&1 || true
  echo "[POST] sysctl применён"
fi

# ----------------------------------------------------------
# 11. Post-apply верификация
# ----------------------------------------------------------
if ! \$DRY_RUN && ! \$SKIP_VERIFY; then
  echo ""
  echo "[VERIFY] Верифицирую установленные правила..."
  if [ -x "\$VERIFY_SCRIPT" ]; then
    if "\$VERIFY_SCRIPT" "\$RULES_FILE" --verbose; then
      echo "[VERIFY] OK: все правила подтверждены в iptables"
    else
      echo "[VERIFY] WARN: Некоторые правила не найдены в iptables после применения"
      echo "[VERIFY] Текущее состояние iptables:"
      iptables -L -n -v --line-numbers 2>/dev/null | head -60 || true
      echo "[VERIFY] NAT таблица:"
      iptables -t nat -L -n -v --line-numbers 2>/dev/null | head -30 || true
    fi
  else
    echo "[VERIFY] Скрипт верификации недоступен: \$VERIFY_SCRIPT"
  fi
fi

# ----------------------------------------------------------
# 12. Сетевые тесты
# ----------------------------------------------------------
if ! \$DRY_RUN; then
  echo ""
  echo "[CHECK] Тестирую сетевое подключение..."
  CONN_OK=1

  if ping -c1 -W3 8.8.8.8 >/dev/null 2>&1; then
    echo "[CHECK] ping 8.8.8.8: OK"
  else
    echo "[CHECK] ping 8.8.8.8: FAIL"
    CONN_OK=0
  fi

  if curl -fsSL --max-time 10 https://raw.githubusercontent.com/ >/dev/null 2>&1; then
    echo "[CHECK] HTTPS raw.githubusercontent.com: OK"
  else
    echo "[CHECK] HTTPS raw.githubusercontent.com: FAIL"
    CONN_OK=0
  fi

  if [ "\$CONN_OK" -ne 1 ]; then
    echo "[CHECK] FAIL: Связь потеряна после применения правил — rollback!"
    if [ -f "\$BACKUP_FILE" ]; then
      iptables-restore < "\$BACKUP_FILE" && echo "[ROLLBACK] OK" || echo "[ROLLBACK] ERROR"
    fi
    exit 6
  fi

  echo "[CHECK] Все сетевые тесты пройдены"
fi

# ----------------------------------------------------------
# 13. Persistent сохранение
# ----------------------------------------------------------
if ! \$DRY_RUN; then
  echo ""
  echo "[PERSIST] Сохраняю правила для выживания после reboot..."
  PERSIST_OK=0

  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 && \
      echo "[PERSIST] netfilter-persistent save OK" && PERSIST_OK=1
  fi

  if [ "\$PERSIST_OK" -eq 0 ] && command -v iptables-save >/dev/null 2>&1; then
    RULES4_FILE="/etc/iptables/rules.v4"
    RULES6_FILE="/etc/iptables/rules.v6"
    mkdir -p /etc/iptables
    if iptables-save > "\$RULES4_FILE"; then
      echo "[PERSIST] Сохранено в \$RULES4_FILE"
      PERSIST_OK=1
    fi
    ip6tables-save > "\$RULES6_FILE" 2>/dev/null || true
  fi

  if [ "\$PERSIST_OK" -eq 0 ]; then
    RC_LOCAL="/etc/rc.local"
    if [ -f "\$RC_LOCAL" ]; then
      RESTORE_CMD="iptables-restore < /etc/iptables/rules.v4"
      if ! grep -qF "\$RESTORE_CMD" "\$RC_LOCAL"; then
        sed -i '/^exit 0/i '"\\\$RESTORE_CMD" "\$RC_LOCAL" || true
        echo "[PERSIST] Добавлено в rc.local"
      fi
    fi
    echo "[PERSIST] WARN: iptables-persistent не найден, правила могут слететь после reboot"
  fi
fi

# ----------------------------------------------------------
# Итог
# ----------------------------------------------------------
echo ""
echo "=========================================================="
echo "=== УСПЕШНО завершено: \$(date -u +"%Y-%m-%dT%H:%M:%SZ") ==="
echo "=== Бэкап: \$BACKUP_FILE ==="
echo "=== Лог: \$LOG ==="
echo "=========================================================="
APPLY_EOF

chmod 755 "$APPLY_PATH"
log_info "Записан: $APPLY_PATH"

# -----------------------
# Записываем агент
# -----------------------
log_step "Записываю агент автообновления..."
cat > "$AGENT_PATH" <<AGENT_EOF
#!/usr/bin/env bash
# iptables-agent — скачивает radio_rules.b64 и применяет при изменениях
set -o nounset
set -o pipefail

RULES_URL="${RULES_URL}"
LOCAL_RULES="/etc/iptables-rls.txt"
LOCAL_HASH_FILE="/etc/iptables-rls.hash"
APPLY_SCRIPT="${APPLY_PATH}"
VERIFY_SCRIPT="${VERIFY_PATH}"
TMP_RULES="/tmp/iptables-new.b64"
TMP_DECODED="/tmp/iptables-new.decoded"
SLEEP_INTERVAL=${SLEEP_INTERVAL}
LOG="${LOG_DIR}/agent.log"
RECHECK_INTERVAL=300   # каждые 5 минут проверяем что правила на месте

exec > >(tee -a "\$LOG") 2>&1

echo "[agent] Запуск: \$(date -u)"
LAST_RECHECK=0

decode_base64_if_possible() {
  local src="\$1"
  local dst="\$2"

  if base64 -d < "\$src" > "\$dst" 2>/dev/null; then
    return 0
  fi

  if base64 --decode < "\$src" > "\$dst" 2>/dev/null; then
    return 0
  fi

  return 1
}

while true; do
  NOW=\$(date +%s)

  # --- Загружаем свежий список правил ---
  FETCH_OK=0
  if curl --retry 3 --retry-delay 2 -fsSL "\$RULES_URL" -o "\$TMP_RULES" 2>/dev/null; then
    FETCH_OK=1
  elif wget -qO "\$TMP_RULES" "\$RULES_URL" 2>/dev/null; then
    FETCH_OK=1
  fi

  if [ "\$FETCH_OK" -eq 0 ]; then
    echo "[agent] WARN: Не удалось скачать правила (\$(date -u))"
    sleep "\$SLEEP_INTERVAL"
    continue
  fi

  if [ ! -s "\$TMP_RULES" ]; then
    echo "[agent] WARN: Скачанный файл пуст, пропускаю (\$(date -u))"
    sleep "\$SLEEP_INTERVAL"
    continue
  fi

  # --- base64 decode ---
  if decode_base64_if_possible "\$TMP_RULES" "\$TMP_DECODED"; then
    mv "\$TMP_DECODED" "\$TMP_RULES"
    echo "[agent] base64 decoded rules"
  else
    echo "[agent] WARN: base64 decode failed, using raw file as-is"
  fi

  NEW_HASH=\$(sha256sum "\$TMP_RULES" | awk '{print \$1}')
  OLD_HASH=\$(cat "\$LOCAL_HASH_FILE" 2>/dev/null || echo "")

  NEED_APPLY=0

  # Применяем если правила изменились
  if [ "\$NEW_HASH" != "\$OLD_HASH" ]; then
    echo "[agent] Обнаружены новые правила (\$(date -u)), применяю..."
    NEED_APPLY=1
  fi

  # Периодически проверяем что правила по-прежнему "живые" в iptables
  if [ \$((NOW - LAST_RECHECK)) -ge "\$RECHECK_INTERVAL" ] && [ -f "\$LOCAL_RULES" ]; then
    if [ -x "\$VERIFY_SCRIPT" ] && ! "\$VERIFY_SCRIPT" "\$LOCAL_RULES" >/dev/null 2>&1; then
      echo "[agent] WARN: Правила исчезли из iptables! Переприменяю... (\$(date -u))"
      NEED_APPLY=1
    fi
    LAST_RECHECK="\$NOW"
  fi

  if [ "\$NEED_APPLY" -eq 1 ]; then
    cp "\$TMP_RULES" "\$LOCAL_RULES"
    if bash "\$APPLY_SCRIPT" "\$LOCAL_RULES" --continue-on-error; then
      echo "\$NEW_HASH" > "\$LOCAL_HASH_FILE"
      echo "[agent] Правила успешно применены и верифицированы (\$(date -u))"
    else
      echo "[agent] WARN: apply script завершился с ошибкой, откат применён (\$(date -u))"
    fi
  fi

  sleep "\$SLEEP_INTERVAL"
done
AGENT_EOF

chmod 755 "$AGENT_PATH"
log_info "Записан: $AGENT_PATH"

# -----------------------
# Systemd unit
# -----------------------
log_step "Записываю systemd unit..."
cat > "$SERVICE_PATH" <<UNIT_EOF
[Unit]
Description=Auto-updater for iptables rules (github -> apply_rules_from_url)
Documentation=https://github.com/KOTBCTAKAHE/MusicBranch
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
ExecStart=${AGENT_PATH}
Restart=always
RestartSec=15
StandardOutput=journal+console
StandardError=journal+console
User=root
Group=root

[Install]
WantedBy=multi-user.target
UNIT_EOF

log_info "Записан: $SERVICE_PATH"

# -----------------------
# Перезагружаем и запускаем
# -----------------------
log_step "Настраиваю и запускаю сервис..."
systemctl daemon-reload
systemctl enable iptables-agent.service
systemctl restart iptables-agent.service

sleep 2
if systemctl is-active --quiet iptables-agent.service; then
  log_info "Сервис iptables-agent запущен и активен"
else
  log_warn "Сервис не запустился. Проверьте: journalctl -u iptables-agent.service -n 50"
fi

# -----------------------
# Первый запуск apply_rules немедленно
# -----------------------
log_step "Применяю правила немедленно (первый запуск)..."
if bash "$APPLY_PATH" "$RULES_URL" --continue-on-error; then
  log_info "Первичное применение правил успешно"
else
  log_warn "Первичное применение завершилось с ошибками (см. лог)"
fi

# -----------------------
# Итог
# -----------------------
echo ""
echo "============================================================"
log_info "Установка завершена успешно!"
echo "============================================================"
echo ""
echo "  Скрипты:"
echo "    apply:    $APPLY_PATH"
echo "    agent:    $AGENT_PATH"
echo "    verify:   $VERIFY_PATH"
echo "    service:  $SERVICE_PATH"
echo ""
echo "  Логи:"
echo "    Применение правил: ${LOG_DIR}/apply_rules.log"
echo "    Агент:             ${LOG_DIR}/agent.log"
echo "    Systemd:           journalctl -u iptables-agent.service -f"
echo ""
echo "  Бэкапы правил: ${BACKUP_DIR}/"
echo ""
echo "  Команды:"
echo "    Статус:     systemctl status iptables-agent.service"
echo "    Тест сухой: bash $APPLY_PATH $RULES_URL --dry-run"
echo "    Верифик.:   bash $VERIFY_PATH /etc/iptables-rls.txt --verbose"
echo "    Ручной:     bash $APPLY_PATH $RULES_URL"
echo "============================================================"
