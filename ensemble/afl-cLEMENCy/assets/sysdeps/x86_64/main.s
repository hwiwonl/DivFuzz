.intel_syntax noprefix
.globl trampoline
.globl trampoline_end

trampoline:

	backup_regs:
    push rsp
	push rax
	push rbx
	push rcx
	push rdx
	push rbp
	push rsi
	push rdi
	push r15
	push r14
	push r13
	push r12
	push r11
	push r10
	push r9
	push r8
    lahf
    seto al
    push rax

	call_handler:
	mov rdi, rsp
    lea rax, [rip+trampoline_end_here]
    call [rax]
    pop rax
    add al, 127 # recover overflow flag (idea from afl)
    sahf
	pop r8
	pop r9
	pop r10
	pop r11
	pop r12
	pop r13
	pop r14
	pop r15
	pop rdi
	pop rsi
	pop rbp
	pop rdx
	pop rcx
	pop rbx
	pop rax
    pop rsp
	ret

trampoline_end:
trampoline_end_here:
# handler pointer here
    .long 0, 0
