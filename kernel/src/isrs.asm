BITS 64

; This is ugly. I'm sorry.
%define exception_handler _ZN6Kernel16handle_exceptionEiP14InterruptFramem
%define interrupt_handler _ZN6Kernel16handle_interruptEiP14InterruptFrame
extern exception_handler
extern interrupt_handler

; Exception handlers
%assign i 0
%rep 32
isr %+ i:
	mov rdi, i
	pop rdx
	mov rsi, rsp
	call exception_handler
	hlt
%assign i i+1
%endrep

; Interrupt handlers
%rep 256-32
isr %+ i:
	mov rdi, i
	mov rsi, rsp
	call interrupt_handler
	hlt
%assign i i+1
%endrep

; Vector of ISRS
global _isrs
_isrs:
%assign i 0
%rep 256
	dq isr %+ i
%assign i i+1
%endrep
