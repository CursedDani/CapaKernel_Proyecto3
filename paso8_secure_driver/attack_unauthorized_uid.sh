#!/usr/bin/env bash
# ==============================================================================
# attack_unauthorized_uid.sh
# PoC de "acceso no autorizado" contra el Componente A del parcial (kmod_secure)
#
# Objetivo: demostrar que el control de acceso por UID implementado en
# dev_open()/dev_mmap() de kmod_secure.c efectivamente bloquea a procesos cuyo
# UID no coincide con el parametro de modulo `allowed_uid` (y que un proceso
# con CAP_SYS_ADMIN, o el propio UID autorizado, sí puede acceder).
#
# Uso:
#   ./attack_unauthorized_uid.sh
# Requisitos:
#   - El modulo kmod_secure debe estar cargado (make load).
#   - Se usara sudo puntualmente para alternar de UID con setpriv (si existe).
# ==============================================================================
set -u

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEVICE="/dev/secure_mmap"
TEST_BIN="$DIR/test_secure"

BOLD='\033[1m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'
GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'

echo -e "${CYAN}${BOLD}=== PoC: Intento de acceso no autorizado sobre ${DEVICE} ===${NC}"

if ! lsmod | grep -q "kmod_secure"; then
    echo -e "${RED}[-] El modulo kmod_secure no esta cargado.${NC}"
    echo -e "    Cárguelo primero con: ${BOLD}cd $DIR && make load${NC}"
    exit 1
fi

if [ ! -x "$TEST_BIN" ]; then
    echo -e "${RED}[-] No se encontro el binario compilado test_secure. Ejecute 'make' primero.${NC}"
    exit 1
fi

PARAM_FILE="/sys/module/kmod_secure/parameters/allowed_uid"
if [ -r "$PARAM_FILE" ]; then
    ALLOWED_UID="$(cat "$PARAM_FILE")"
else
    ALLOWED_UID="desconocido (no se pudo leer $PARAM_FILE)"
fi
echo -e "${CYAN}[i] UID autorizado configurado en el modulo (allowed_uid): ${BOLD}${ALLOWED_UID}${NC}"
echo ""

# ------------------------------------------------------------------
# Prueba 1: acceso con el UID actual del usuario que invoca el script
# ------------------------------------------------------------------
echo -e "${YELLOW}--- Prueba 1: acceso como usuario actual (UID=$(id -u), $(whoami)) ---${NC}"
"$TEST_BIN" >/tmp/secure_test1.log 2>&1
RC1=$?
if [ $RC1 -eq 0 ]; then
    echo -e "${GREEN}[+] Acceso PERMITIDO (coincide con allowed_uid o tiene CAP_SYS_ADMIN).${NC}"
else
    echo -e "${RED}[-] Acceso DENEGADO (comportamiento esperado si el UID no coincide).${NC}"
fi
tail -n 5 /tmp/secure_test1.log | sed 's/^/    /'
echo ""

# ------------------------------------------------------------------
# Prueba 2: acceso explicito como root (debe permitirse via CAP_SYS_ADMIN)
# ------------------------------------------------------------------
echo -e "${YELLOW}--- Prueba 2: acceso como root (sudo) ---${NC}"
if command -v sudo >/dev/null 2>&1; then
    sudo "$TEST_BIN" >/tmp/secure_test2.log 2>&1
    RC2=$?
    if [ $RC2 -eq 0 ]; then
        echo -e "${GREEN}[+] Acceso PERMITIDO como root (CAP_SYS_ADMIN bypass funcionando).${NC}"
    else
        echo -e "${RED}[-] Acceso DENEGADO incluso como root (revisar el modulo).${NC}"
    fi
    tail -n 5 /tmp/secure_test2.log | sed 's/^/    /'
else
    echo -e "${YELLOW}[i] 'sudo' no disponible, se omite esta prueba.${NC}"
fi
echo ""

# ------------------------------------------------------------------
# Prueba 3 (opcional): acceso como un UID claramente distinto y no autorizado
# ------------------------------------------------------------------
echo -e "${YELLOW}--- Prueba 3: acceso forzado desde un UID distinto (nobody) ---${NC}"
if command -v setpriv >/dev/null 2>&1 && id nobody >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
    NOBODY_UID="$(id -u nobody)"
    NOBODY_GID="$(id -g nobody)"
    sudo setpriv --reuid="$NOBODY_UID" --regid="$NOBODY_GID" --clear-groups -- "$TEST_BIN" \
        >/tmp/secure_test3.log 2>&1
    RC3=$?
    if [ "$NOBODY_UID" = "$ALLOWED_UID" ]; then
        echo -e "${CYAN}[i] 'nobody' (UID=$NOBODY_UID) coincide con allowed_uid; se espera acceso PERMITIDO.${NC}"
    else
        echo -e "${CYAN}[i] 'nobody' (UID=$NOBODY_UID) NO coincide con allowed_uid=$ALLOWED_UID; se espera DENEGADO.${NC}"
    fi
    if [ $RC3 -eq 0 ]; then
        echo -e "${GREEN}[+] Resultado: acceso PERMITIDO.${NC}"
    else
        echo -e "${RED}[-] Resultado: acceso DENEGADO.${NC}"
    fi
    tail -n 5 /tmp/secure_test3.log | sed 's/^/    /'
else
    echo -e "${YELLOW}[i] 'setpriv' y/o usuario 'nobody' no disponibles; se omite esta prueba.${NC}"
fi
echo ""

echo -e "${CYAN}${BOLD}=== Ultimas entradas de auditoria en el kernel (dmesg) ===${NC}"
sudo dmesg 2>/dev/null | grep -i "kmod_secure" | tail -n 20 || \
    dmesg 2>/dev/null | grep -i "kmod_secure" | tail -n 20

echo ""
echo -e "${CYAN}${BOLD}=== Estado final de integridad/auditoria (read() sobre el dispositivo) ===${NC}"
cat "$DEVICE" 2>/dev/null || echo -e "${YELLOW}[i] No se pudo leer $DEVICE con el usuario actual.${NC}"
