#ifndef _INTERRUPTS_H
#define _INTERRUPTS_H

// Entry point of interrupts
void _handle_page_fault();
void _handle_breakpoint();
void _handle_general_protection_fault();

#endif