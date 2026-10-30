// Practica insegura sugerida por IA: "desactiva CR0.WP para poder escribir en la syscall table".
// Se EJECUTA SOLO EN LA VM DE PRUEBAS: comprueba si el bit WP realmente puede apagarse.
#include <linux/module.h>
#include <asm/special_insns.h>
#include <asm/processor-flags.h>
static int __init m_init(void)
{
	unsigned long before = read_cr0(), after;

	write_cr0(before & ~X86_CR0_WP);
	after = read_cr0();
	pr_info("h5: CR0 antes=%#lx despues_de_apagar_WP=%#lx => WP %s\n", before, after,
		(after & X86_CR0_WP) ? "SIGUE ENCENDIDO (CR pinning: la tecnica ya no funciona)" : "APAGADO");
	write_cr0(before);   /* restaurar por si acaso */
	return 0;
}
static void __exit m_exit(void) {}
module_init(m_init); module_exit(m_exit); MODULE_LICENSE("GPL");
