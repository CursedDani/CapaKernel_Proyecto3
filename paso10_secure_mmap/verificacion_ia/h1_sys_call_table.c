// Afirmacion de IA (tipica): "puedes leer/parchear sys_call_table[__NR_mmap] desde un modulo".
#include <linux/module.h>
#include <asm/syscall.h>
static int __init m_init(void) { pr_info("syscall 9 = %px\n", sys_call_table[9]); return 0; }
static void __exit m_exit(void) {}
module_init(m_init); module_exit(m_exit); MODULE_LICENSE("GPL");
