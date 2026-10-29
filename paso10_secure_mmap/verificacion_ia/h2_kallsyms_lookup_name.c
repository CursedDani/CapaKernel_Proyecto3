// Afirmacion de IA (tipica): "usa kallsyms_lookup_name() para encontrar sys_call_table".
#include <linux/module.h>
#include <linux/kallsyms.h>
static int __init m_init(void) { pr_info("sct = %lx\n", kallsyms_lookup_name("sys_call_table")); return 0; }
static void __exit m_exit(void) {}
module_init(m_init); module_exit(m_exit); MODULE_LICENSE("GPL");
