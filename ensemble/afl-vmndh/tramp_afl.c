#include <handler.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/shm.h>
#include <signal.h>

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"
#define KPNK  "\x1B[91m"

/* Map size for the traced binary (2^MAP_SIZE_POW2). Must be greater than
   2; you probably want to keep it under 18 or so for performance reasons
   (adjusting AFL_INST_RATIO when compiling is probably a better way to solve
   problems with complex programs). You need to recompile the target binary
   after changing this - otherwise, SEGVs may ensue. */

#define MAP_SIZE_POW2       16
#define MAP_SIZE            (1 << MAP_SIZE_POW2)

/* Environment variable used to pass SHM ID to the called program. */

#define SHM_ENV_VAR         "__AFL_SHM_ID"

/* Other less interesting, internal-only variables. */

#define PERSIST_ENV_VAR     "__AFL_PERSISTENT"
#define DEFER_ENV_VAR       "__AFL_DEFER_FORKSRV"

#define MAP_SIZE_POW2       16
#define MAP_SIZE            (1 << MAP_SIZE_POW2)
#define FORKSRV_FD 198

// binary base
char *base = NULL;

typedef struct {
    int op;
    void (*handler)();
} handler;

char *vm_flags = NULL;
char **vm_base = NULL;

unsigned short *vm_pc = NULL;

unsigned short *vm_r0 = NULL;
unsigned short *vm_r1 = NULL;
unsigned short *vm_r2 = NULL;
unsigned short *vm_r3 = NULL;
unsigned short *vm_r4 = NULL;
unsigned short *vm_r5 = NULL;
unsigned short *vm_r6 = NULL;
unsigned short *vm_r7 = NULL;
unsigned short *vm_bp = NULL;
unsigned short *vm_sp = NULL;
unsigned short *vm_zf = NULL;
unsigned short *vm_af = NULL;
unsigned short *vm_bf = NULL;

unsigned long *vm_src = NULL;
handler *handlers = NULL;

/* Globals needed by the injected instrumentation. The __afl_area_initial region
   is used for instrumentation output before __afl_map_shm() has a chance to run.
   It will end up as .comm, so it shouldn't be too wasteful. */

uint8_t  __afl_area_initial[MAP_SIZE];
uint8_t* __afl_area_ptr = __afl_area_initial;

__thread u32 __afl_prev_loc;
__thread u32 __afl_key;


/* Running in persistent mode? */

static uint8_t is_persistent;


/* SHM setup. */

static void __afl_map_shm(void) {

  uint8_t *id_str = getenv(SHM_ENV_VAR);

  /* If we're running under AFL, attach to the appropriate region, replacing the
     early-stage __afl_area_initial region that is needed to allow some really
     hacky .init code to work correctly in projects such as OpenSSL. */

  if (id_str) {

    u32 shm_id = atoi(id_str);

    __afl_area_ptr = shmat(shm_id, NULL, 0);

    /* Whooooops. */

    if (__afl_area_ptr == (void *)-1) _exit(1);

    /* Write something into the bitmap so that even with low AFL_INST_RATIO,
       our parent doesn't give up on us. */

    __afl_area_ptr[0] = 1;

  }

}


/* Fork server logic. */

static void __afl_start_forkserver(void) {

  static uint8_t tmp[4];
  int32_t  child_pid;

  uint8_t  child_stopped = 0;

  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  while (1) {

    u32 was_killed;
    int status;

    /* Wait for parent by reading from the pipe. Abort if read fails. */

    if (read(FORKSRV_FD, &was_killed, 4) != 4) _exit(1);

    /* If we stopped the child in persistent mode, but there was a race
       condition and afl-fuzz already issued SIGKILL, write off the old
       process. */

    if (child_stopped && was_killed) {
      child_stopped = 0;
      if (waitpid(child_pid, &status, 0) < 0) _exit(1);
    }

    if (!child_stopped) {

      /* Once woken up, create a clone of our process. */

      child_pid = fork();
      if (child_pid < 0) _exit(1);

      /* In child process: close fds, resume execution. */

      if (!child_pid) {

        close(FORKSRV_FD);
        close(FORKSRV_FD + 1);
        return;
  
      }

    } else {

      /* Special handling for persistent mode: if the child is alive but
         currently stopped, simply restart it with SIGCONT. */

      kill(child_pid, SIGCONT);
      child_stopped = 0;

    }

    /* In parent process: write PID to pipe, then wait for child. */

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) _exit(1);

    if (waitpid(child_pid, &status, is_persistent ? WUNTRACED : 0) < 0)
      _exit(1);

    /* In persistent mode, the child stops itself with SIGSTOP to indicate
       a successful run. In this case, we want to wake it up without forking
       again. */

    if (WIFSTOPPED(status)) child_stopped = 1;

    /* Relay wait status to pipe, then loop back. */

    if (write(FORKSRV_FD + 1, &status, 4) != 4) _exit(1);

  }

}


/* A simplified persistent mode handler, used as explained in README.llvm. */

int __afl_persistent_loop(unsigned int max_cnt) {

  static uint8_t  first_pass = 1;
  static u32 cycle_cnt;

  if (first_pass) {

    /* Make sure that every iteration of __AFL_LOOP() starts with a clean slate.
       On subsequent calls, the parent will take care of that, but on the first
       iteration, it's our job to erase any trace of whatever happened
       before the loop. */

    if (is_persistent) {

      memset(__afl_area_ptr, 0, MAP_SIZE);
      __afl_area_ptr[0] = 1;
      __afl_prev_loc = 0;
    }

    cycle_cnt  = max_cnt;
    first_pass = 0;
    return 1;

  }

  if (is_persistent) {

    if (--cycle_cnt) {

      raise(SIGSTOP);

      __afl_area_ptr[0] = 1;
      __afl_prev_loc = 0;

      return 1;

    } else {

      /* When exiting __AFL_LOOP(), make sure that the subsequent code that
         follows the loop is not traced. We do that by pivoting back to the
         dummy output region. */

      __afl_area_ptr = __afl_area_initial;

    }

  }

  return 0;

}


/* This one can be called from user code when deferred forkserver mode
    is enabled. */

void __afl_manual_init(void) {

  static uint8_t init_done;

  if (!init_done) {

    __afl_map_shm();
    __afl_start_forkserver();
    init_done = 1;

  }

}


/* Proper initialization routine. */

__attribute__((constructor)) void __afl_auto_init(void) {

  is_persistent = !!getenv(PERSIST_ENV_VAR);

  if (getenv(DEFER_ENV_VAR)) return;

  __afl_manual_init();

}

__attribute__((constructor))
void obtain_bases() {
    base = (char *)query_lib("")->base;
    vm_flags = base + 0x20f8d0;
    
    vm_r0 = (unsigned short *)(base + 0x20f8c0);
    vm_r1 = (unsigned short *)(base + 0x20f8c2);
    vm_r2 = (unsigned short *)(base + 0x20f8c4);
    vm_r3 = (unsigned short *)(base + 0x20f8c6);
    vm_r4 = (unsigned short *)(base + 0x20f8c8);
    vm_r5 = (unsigned short *)(base + 0x20f8ca); 
    vm_r6 = (unsigned short *)(base + 0x20f8cc);
    vm_r7 = (unsigned short *)(base + 0x20f8ce);
    vm_bp = (unsigned short *)(base + 0x20f8ac);
    vm_sp = (unsigned short *)(base + 0x20f8a8);
    vm_pc = (unsigned short *)(base + 0x20f8ae);
    vm_zf = (unsigned short *)(base + 0x20f8d0);
    vm_af = (unsigned short *)(base + 0x20f8d1);
    vm_bf = (unsigned short *)(base + 0x20f8d2);

    vm_src = (unsigned long *)(base + 0x2080a0 + 0x7800);
    vm_base = (char **)(base + 0x20f8b8);
    handlers = (handler *)(base + 0x20f020);
}

void afl_store() {
    // Sends coverage to afl
    unsigned short cur_location = *vm_pc;
//    printf("branch: %p\n", (void *)(addrint)cur_location);
    __afl_key = cur_location ^ __afl_prev_loc;
    __afl_area_ptr[__afl_key]++;
    __afl_prev_loc = cur_location >> 1;
}

// segfault_handler
//RAISE(0x5d38);

void _return(context *ctx) {
    ctx->rsp += 8;
}

unsigned short uint16_at(uint16_t where) {
    uint16_t *ptr = (uint16_t *)((*vm_base) + where);
    return *ptr;
}

/* handler functions */
void trace_branch_handler(context *ctx) {
    addrint op = ctx->rdx;
    int trace = 0;
    switch(op) {
        case 0x16: // jmps
        case 0x1b: // jmpl
        case 0x19: // call
        case 0x10: // jz
        case 0x11: // jnz
        case 0x1e: // ja
        case 0x1f: // jb
        case 0x1a: // ret
            trace = 1;
            break;
    }
    handlers[ctx->rax].handler();
    if(trace) afl_store();
    ctx->PC = (addrint)base + 0x3e3d;
}

void convert_file_to_contents(context *ctx) {
  printf("%sarguments : %s\n", KGRN, ctx->rax);
  printf("(%p)%s\n", ctx->rax, KNRM);
  FILE * fp = fopen(ctx->rax, "r");
  if(fp == NULL) {
    fputs("fopen error", stderr);
    ctx->PC = (addrint)base + 0x2707;
    return;
  }

  fseek(fp , 0 , SEEK_END);
  int size = ftell(fp);
  rewind(fp);

  char * buffer = (char*) malloc(sizeof(char)*size);
  if(buffer == NULL) {
    fputs("memory error", stderr);
    ctx->PC = (addrint)base + 0x2707;
    return;
  }
  int result = fread(buffer, 1, size, fp);
  if(result != size) {
    fputs("fread error", stderr);
    ctx->PC = (addrint)base + 0x2707;
    return;
  }
  printf("%scontents : %s(%p)%s\n", KYEL, buffer, buffer, KNRM);

  *vm_src = (unsigned long)buffer;
  ctx->PC = (addrint)base + 0x2707;
}

void segfault_opcode_unknown(context *ctx) {
  __afl_area_ptr[__afl_key]--; // catch unique crashes
  printf("%s", KPNK);
  printf("Segmentation fault at %04x (opcode unknown)\n", *vm_pc);
  printf("%s", KNRM);
  printf("[%sr0%s] : %04x\t[%sr4%s] : %04x\n", KPNK, KNRM, *vm_r0, KPNK, KNRM, *vm_r4);
  printf("[%sr1%s] : %04x\t[%sr5%s] : %04x\n", KPNK, KNRM, *vm_r1, KPNK, KNRM, *vm_r5);
  printf("[%sr2%s] : %04x\t[%sr6%s] : %04x\n", KPNK, KNRM, *vm_r2, KPNK, KNRM, *vm_r6);
  printf("[%sr3%s] : %04x\t[%sr7%s] : %04x\n", KPNK, KNRM, *vm_r3, KPNK, KNRM, *vm_r7);
  printf("[%sbp%s] : %04x\t[%szf%s] : %04x\n", KPNK, KNRM, *vm_bp, KPNK, KNRM, *vm_zf);
  printf("[%ssp%s] : %04x\t[%saf%s] : %04x\n", KPNK, KNRM, *vm_sp, KPNK, KNRM, *vm_af);
  printf("[%spc%s] : %04x\t[%sbf%s] : %04x\n", KPNK, KNRM, *vm_pc, KPNK, KNRM, *vm_bf);
  raise(SIGSEGV);
  ctx->PC = (addrint)base + 0x5dc4;
}

HOOK(0x3e29, trace_branch_handler);
HOOK(0x26a7, convert_file_to_contents);
HOOK(0x5d8f, segfault_opcode_unknown);

