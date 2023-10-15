#pragma once

// Definitions for some useful registers
// Let's add some of useful registers!
#if defined(__i386)
#define PC eip
#define SP esp
// LAHF + SETO trick from afl.
// It's different from eflags register. lower 8bits are in ah, of is al & 1.
// Each flag is 1 bit. This method is 3x+ faster than pushf/popf.
// | 15 14 13 12 11 10  9  8 |  7  6  5  4  3  2  1  0 |
// | SF ZF    AF    PF    CF |                      OF |
#define ZF (1 << (6 + 8))
#define SF (1 << (7 + 8))
#define CF (1 << (0 + 8))
#define AF (1 << (4 + 8))
#define PF (1 << (2 + 8))
#define OF (1 << (0 + 0))
typedef unsigned long addrint;
typedef signed long addrdiff;
typedef unsigned long u32;
typedef unsigned long long u64;
typedef struct {
	u32 eflags, edi, esi, ebp, edx, ecx, ebx, eax, esp, eip;
} context;
#elif defined(__x86_64)
#define PC rip
#define SP rsp
// Used same trick with i386. For description, see i386 part.
#define ZF (1 << (6 + 8))
#define SF (1 << (7 + 8))
#define CF (1 << (0 + 8))
#define AF (1 << (4 + 8))
#define PF (1 << (2 + 8))
#define OF (1 << (0 + 0))
typedef unsigned long long addrint;
typedef signed long long addrdiff;
typedef unsigned long u32;
typedef unsigned long long u64;
typedef struct {
	u64 rflags, r8, r9, r10, r11, r12, r13, r14, r15, rdi, rsi, rbp, rdx, rcx, rbx, rax, rsp, rip;
} context;
#elif defined(__arm__)
#define PC arm_pc
#define SP arm_sp
typedef unsigned long addrint;
typedef signed long addrdiff;
#endif

typedef struct _lib {
    char *name;
    addrint base;
    struct _lib *next;
} lib;

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"
#define KPNK  "\x1B[91m"

void logger(int level, char *format, ...);
void install_one_trampoline(char *library, addrint where, addrint function_ptr);
void install_trampoline_by_name(char *library, char *name, addrint function_ptr);
void install_exception(char *library, addrint where);
lib *query_lib(char *name);

// Expanding __COUNTER__ via expanding macros
#define CONCAT1(x, y) x##y
#define CONCAT(x, y) CONCAT1(x, y)
#define HOOK_WITH_LIB(lib, addr, func) __attribute__((constructor)) void CONCAT(install_##func##_, __COUNTER__)() { \
    logger(1, "Hooking %s"#addr"%s with %s"#func"%s\n", KRED, KNRM, KGRN, KNRM); \
    install_one_trampoline(lib, addr, (addrint)func); \
}
#define HOOK_WITH_NOLIB(addr, func) HOOK_WITH_LIB("", addr, func)

#define SELECTOR(_1, _2, _3, NAME, ...) NAME
#define HOOK(...) SELECTOR(__VA_ARGS__, HOOK_WITH_LIB, HOOK_WITH_NOLIB)(__VA_ARGS__)

#define SYMHOOK_WITH_LIB(lib, name, func) __attribute__((constructor)) void CONCAT(install_##func##_, __COUNTER__)() { \
    logger(1, "Hooking %s"#name"%s with %s"#func"%s\n", KRED, KNRM, KGRN, KNRM); \
    install_trampoline_by_name(lib, name, (addrint)func); \
}

#define SYMHOOK_WITH_NOLIB(name, func) SYMHOOK_WITH_LIB("", name, func)

#define SYMHOOK(...) SELECTOR(__VA_ARGS__, SYMHOOK_WITH_LIB, SYMHOOK_WITH_NOLIB)(__VA_ARGS__)

#define RAISE_WITH_LIB(lib, addr) __attribute__((constructor)) void CONCAT(install_##func##_, __COUNTER__)() { \
    logger(1, "Crash on %s"#addr"%s\n", KPNK, KNRM); \
    install_exception(lib, addr); \
}

#define RAISE_WITH_NOLIB(addr) RAISE_WITH_LIB("", addr)

#define RAISE(...) SELECTOR(__VA_ARGS__, XXX, RAISE_WITH_LIB, RAISE_WITH_NOLIB)(__VA_ARGS__)

// LOGLEVEL
// 0: error
// 1: hooking log
#define LOGLEVEL 1

