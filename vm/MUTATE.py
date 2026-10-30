#!/usr/bin/env python3
"""Aplica UN mutante (M1..M8) a kmod_secure_mmap.c. Uso: MUTATE.py <archivo.c> <Mn>"""
import sys

MUTANTS = {
    "M1": ("\tif (vma->vm_pgoff >= VAULT_NUM_PAGES ||\n"
           "\t    vma_pages(vma) > VAULT_NUM_PAGES - vma->vm_pgoff) {",
           "\tif (vma->vm_pgoff > (1UL << 60)) {"),
    "M2": ("\tvault_vm_flags_clear(vma, VM_MAYEXEC);", "\t/* mutado */"),
    "M3": ("\t/* 1. Re-verificar identidad: el fd pudo heredarse/pasarse a otro UID */\n"
           "\tif (!vault_caller_authorized()) {",
           "\t/* mutado */\n\tif (0) {"),
    "M4": ("if (!(vma->vm_flags & VM_MAYSHARE)) {", "if (0) {"),
    "M5": ("\tvault_vm_flags_set(vma, VAULT_ISOLATION_FLAGS);", "\t/* mutado */"),
    "M6": ("\tif (!s->writable)\n\t\tvault_vm_flags_clear(vma, VM_WRITE | VM_MAYWRITE);", "\t(void)s;"),
    "M7": ("\tif (!ret && crypto_memneq(mac, vault.mac[idx], VAULT_MAC_LEN))\n\t\tret = -EBADMSG;",
           "\t(void)mac;"),
    "M8": ("if (!(vma->vm_flags & VM_MAYSHARE)) {", "if (!(vma->vm_flags & VM_SHARED)) {"),
}

path, name = sys.argv[1], sys.argv[2]
src = open(path).read()
old, new = MUTANTS[name]
if old not in src:
    sys.exit(1)
open(path, "w").write(src.replace(old, new, 1))
