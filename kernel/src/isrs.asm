BITS 64

; This is ugly. I'm sorry.
%define handle_interrupt  _ZN6Kernel16handle_interruptEiP14InterruptFrame
%define handle_page_fault _ZN6Kernel17handle_page_faultEP14InterruptFramem
%define handle_breakpoint _ZN6Kernel17handle_breakpointEP14InterruptFrame
extern handle_interrupt
extern handle_page_fault
extern handle_breakpoint

; Default handlers
%assign i 0
%rep 256
defaultISR %+ i:
	mov rdi, i
	mov rsi, rsp
	call handle_interrupt
	hlt
%assign i i+1
%endrep

; Vector of defaultISRS
global _defaultISRS
_defaultISRS:
%assign i 0
%rep 256
	dq defaultISR %+ i
%assign i i+1
%endrep

; Specific handlers
global _handle_page_fault
_handle_page_fault:
	pop rsi
	mov rdi, rsp
	call handle_page_fault
	hlt

global _handle_breakpoint
_handle_breakpoint:
	mov rdi, rsp
	call handle_breakpoint
	hlt
