#!/usr/bin/env bash
# ==============================================================================
# Script para cargar los módulos de kernel demostrativos con Salida a Color
# ==============================================================================
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Colores ANSI
BOLD='\033[1m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}${BOLD}=== CARGANDO MÓDULOS DE KERNEL DOCENTES ===${NC}"

# Compilar los módulos
echo -e "${CYAN}[*] Compilando módulo Paso 3 (kmod_copy_user)...${NC}"
make -C "$DIR/paso3_driver_copy_user" modules > /dev/null

echo -e "${CYAN}[*] Compilando módulo Paso 4 (kmod_mmap)...${NC}"
make -C "$DIR/paso4_driver_mmap_kernel" modules > /dev/null

echo -e "${CYAN}[*] Compilando módulo Paso 6 (kmod_demand_paging)...${NC}"
make -C "$DIR/paso6_demand_paging_fault" modules > /dev/null

echo -e "${CYAN}[*] Compilando módulo Paso 8 (kmod_secure)...${NC}"
make -C "$DIR/paso8_secure_driver" modules > /dev/null

echo -e "${CYAN}[*] Compilando Paso 9 (kmod_auditor) y Paso 10 (secure_vault)...${NC}"
make -C "$DIR/paso9_kprobe_auditor" modules > /dev/null
make -C "$DIR/paso10_secure_mmap" modules > /dev/null

# 1. Cargar Paso 3 (copy_to_user)
if lsmod | grep -q "kmod_copy_user"; then
    echo -e "${YELLOW}[i] kmod_copy_user ya estaba cargado.${NC}"
else
    echo -e "${GREEN}[+] Cargando kmod_copy_user.ko...${NC}"
    sudo insmod "$DIR/paso3_driver_copy_user/kmod_copy_user.ko"
    sudo chmod 666 /dev/demo_copy_user 2>/dev/null || true
fi

# 2. Cargar Paso 4 (mmap con remap_pfn_range)
if lsmod | grep -q "kmod_mmap"; then
    echo -e "${YELLOW}[i] kmod_mmap ya estaba cargado.${NC}"
else
    echo -e "${GREEN}[+] Cargando kmod_mmap.ko...${NC}"
    sudo insmod "$DIR/paso4_driver_mmap_kernel/kmod_mmap.ko"
    sudo chmod 666 /dev/demo_mmap 2>/dev/null || true
fi

# 3. Cargar Paso 6 (demand paging con vm_ops->fault)
if lsmod | grep -q "kmod_demand_paging"; then
    echo -e "${YELLOW}[i] kmod_demand_paging ya estaba cargado.${NC}"
else
    echo -e "${GREEN}[+] Cargando kmod_demand_paging.ko...${NC}"
    sudo insmod "$DIR/paso6_demand_paging_fault/kmod_demand_paging.ko"
    sudo chmod 666 /dev/demo_demand_fault 2>/dev/null || true
fi

# 4. Cargar Paso 8 (control de acceso + integridad + auditoria sobre mmap)
if lsmod | grep -q "kmod_secure"; then
    echo -e "${YELLOW}[i] kmod_secure ya estaba cargado.${NC}"
else
    echo -e "${GREEN}[+] Cargando kmod_secure.ko (allowed_uid=0 por defecto)...${NC}"
    sudo insmod "$DIR/paso8_secure_driver/kmod_secure.ko"
    sudo chmod 666 /dev/secure_mmap 2>/dev/null || true
fi

# 5. Paso 9: auditor global de mmap() con kprobes (Componente B del parcial)
if lsmod | grep -q "kmod_auditor"; then
    echo -e "${YELLOW}[i] kmod_auditor ya estaba cargado.${NC}"
else
    echo -e "${GREEN}[+] Cargando kmod_auditor.ko (lectura en /proc/mmap_audit)...${NC}"
    sudo insmod "$DIR/paso9_kprobe_auditor/kmod_auditor.ko"
fi

# 6. Paso 10: boveda segura (UID autorizado = ALLOWED_UID, o el usuario que invoco sudo, o 1000)
VAULT_UID="${ALLOWED_UID:-${SUDO_UID:-1000}}"
if lsmod | grep -q "secure_vault"; then
    echo -e "${YELLOW}[i] secure_vault ya estaba cargado.${NC}"
else
    echo -e "${GREEN}[+] Cargando secure_vault.ko (allowed_uid=${VAULT_UID})...${NC}"
    sudo insmod "$DIR/paso10_secure_mmap/secure_vault.ko" allowed_uid="$VAULT_UID"
    sudo chmod 666 /dev/secure_vault 2>/dev/null || true
fi

echo ""
echo -e "${BLUE}${BOLD}=== ESTADO DE DISPOSITIVOS REGISTRADOS ===${NC}"
ls -l /dev/demo_copy_user /dev/demo_mmap /dev/demo_demand_fault /dev/secure_mmap /dev/secure_vault 2>/dev/null || true
echo ""
echo -e "${GREEN}${BOLD}¡Módulos cargados exitosamente! Puede ejecutar las pruebas:${NC}"
echo -e "  - ${CYAN}./paso3_driver_copy_user/test_copy_user${NC}"
echo -e "  - ${CYAN}./paso4_driver_mmap_kernel/test_mmap${NC}"
echo -e "  - ${CYAN}./paso6_demand_paging_fault/test_demand_paging${NC}"
echo -e "  - ${CYAN}./paso8_secure_driver/test_secure${NC}"
echo -e "  - ${CYAN}./paso8_secure_driver/attack_unauthorized_uid.sh${NC}"
echo -e "  - ${CYAN}./paso10_secure_mmap/tests/run_tests.sh${NC}   (bateria del parcial; requiere allowed_uid=1000)"
echo -e "  - ${CYAN}cat /proc/mmap_audit | head${NC}              (auditor global kprobes)"
