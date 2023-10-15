.intel_syntax noprefix
.globl trampoline, trampoline_end

trampoline:
	push esp
	pushad
	pushfd
	call [trampoline_end]
	popfd
	popad
    pop esp
	ret

trampoline_end:
.long 0
