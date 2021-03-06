BITS 64

extern handle_interrupt

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

; Vector of defaultISRs
global _defaultISRs
_defaultISRs:
%assign i 0
%rep 256
	dq defaultISR %+ i
%assign i i+1
%endrep