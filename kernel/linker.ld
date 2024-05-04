SECTIONS {
	. = 0xffffffff80200000;

	.text ALIGN(4K) : {
		*(.text*)
	}

	.rodata ALIGN(4K) : {
		*(.rodata*)
	}

	.got ALIGN(4K) : {
		*(.got*)
	}

	.data ALIGN(4K) : {
		*(.data*)
	}

	.bss ALIGN(4K) : {
		*(COMMON)
		*(.bss*)
	}
}
