#include "init.h"
#include "gdt.h"
#include "tss.h"

static TSSEntry tss;
static GlobalDescriptor g_gdt[N_GDT_ENTRIES];

void init_tss() {
	// The TSS is referenced by a TSSDescriptor in the GDT. The selector of this
	// TSSDescriptor is loaded into the TSR when loading the GDT.
	static_assert(sizeof(TSSEntry) == 104);

	// Stack used when switching from ring3 to ring0 because of an interruption
	tss.rsp0 = (uint64_t)kmalloc(0x2000) + 0x2000;

	// Stack used when an exception occurs in ring 0
	// (requires ist field in IDT to be 1) TODO
	tss.ist1 = (uint64_t)kmalloc(0x2000) + 0x2000;
	tss.iopb = sizeof(TSSEntry);
}

void init_gdt() {
	static_assert(sizeof(GlobalDescriptor) == 0x8);
	static_assert(sizeof(TSSDescriptor) == 0x10);

	// Null descriptor is at offset 0x00
	// Kernel code, offset 0x08
	g_gdt[1].set_code();
	g_gdt[1].set_dpl(0);

	// Kernel data, offset 0x10
	g_gdt[2].set_data();
	g_gdt[2].set_dpl(0);

	// User data, offset 0x18
	g_gdt[3].set_data();
	g_gdt[3].set_dpl(3);

	// User code, offset 0x20
	g_gdt[4].set_code();
	g_gdt[4].set_dpl(3);

	// TSS, offset 0x28. Ugly memcpy because TSSDescriptor is twice the size of
	// GlobalDescriptor
	TSSDescriptor tss_descriptor;
	tss_descriptor.set_base((uint64_t)&tss);
	memcpy(&g_gdt[5], &tss_descriptor, sizeof(tss_descriptor));

	GDTPtr gdt_ptr = {
		.size = sizeof(g_gdt) - 1,
		.offset = (uint64_t)g_gdt
	};
	gdt_ptr.load();

	printf("GDT set\n");
}
