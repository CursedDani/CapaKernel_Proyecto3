// Codigo "clasico" que la IA suele generar: modificar vm_flags directamente.
#include <linux/module.h>
#include <linux/mm.h>
static int dev_mmap(struct file *f, struct vm_area_struct *vma)
{ vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP; return 0; }
static int __init m_init(void) { return dev_mmap(NULL, NULL); }
static void __exit m_exit(void) {}
module_init(m_init); module_exit(m_exit); MODULE_LICENSE("GPL");
