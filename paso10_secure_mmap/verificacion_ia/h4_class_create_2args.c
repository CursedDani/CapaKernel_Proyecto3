// Firma antigua de class_create(owner, name) (Linux < 6.4) usada en un kernel moderno.
#include <linux/module.h>
#include <linux/device.h>
static struct class *c;
static int __init m_init(void) { c = class_create(THIS_MODULE, "h4"); return IS_ERR(c) ? PTR_ERR(c) : 0; }
static void __exit m_exit(void) { class_destroy(c); }
module_init(m_init); module_exit(m_exit); MODULE_LICENSE("GPL");
