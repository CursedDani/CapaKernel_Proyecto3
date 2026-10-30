// Afirmacion: "kmap_atomic() fue reemplazada por kmap_local_page() y ya no existe".
#include <linux/module.h>
#include <linux/highmem.h>
static int __init m_init(void) { struct page *p = alloc_page(GFP_KERNEL); void *a; if (!p) return -ENOMEM;
  a = kmap_atomic(p); memset(a, 0, 8); kunmap_atomic(a); __free_page(p); return 0; }
static void __exit m_exit(void) {}
module_init(m_init); module_exit(m_exit); MODULE_LICENSE("GPL");
