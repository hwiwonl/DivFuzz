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
#define FORKSRV_FD 198

/* Environment variable used to pass SHM ID to the called program. */

#define SHM_ENV_VAR         "__AFL_SHM_ID"

/* Other less interesting, internal-only variables. */

#define PERSIST_ENV_VAR     "__AFL_PERSISTENT"
#define DEFER_ENV_VAR       "__AFL_DEFER_FORKSRV"

// binary base
char *base = NULL;

typedef struct {
    int op;
    void (*handler)();
} handler;

uint32_t * vm_R00 = NULL;
uint32_t * vm_R01 = NULL;
uint32_t * vm_R02 = NULL;
uint32_t * vm_R03 = NULL;
uint32_t * vm_R04 = NULL;
uint32_t * vm_R05 = NULL;
uint32_t * vm_R06 = NULL;
uint32_t * vm_R07 = NULL;
uint32_t * vm_R08 = NULL;
uint32_t * vm_R09 = NULL;
uint32_t * vm_R10 = NULL;
uint32_t * vm_R11 = NULL;
uint32_t * vm_R12 = NULL;
uint32_t * vm_R13 = NULL;
uint32_t * vm_R14 = NULL;
uint32_t * vm_R15 = NULL;
uint32_t * vm_R16 = NULL;
uint32_t * vm_R17 = NULL;
uint32_t * vm_R18 = NULL;
uint32_t * vm_R19 = NULL;
uint32_t * vm_R20 = NULL;
uint32_t * vm_R21 = NULL;
uint32_t * vm_R22 = NULL;
uint32_t * vm_R23 = NULL; 
uint32_t * vm_R24 = NULL;
uint32_t * vm_R25 = NULL;
uint32_t * vm_R26 = NULL;
uint32_t * vm_R27 = NULL;
uint32_t * vm_R28 = NULL;
uint32_t * vm_ST = NULL;
uint32_t * vm_RA = NULL;             
uint32_t * vm_PC = NULL;  // Program counter

handler *handlers = NULL;

/* Globals needed by the injected instrumentation. The __afl_area_initial region
   is used for instrumentation output before __afl_map_shm() has a chance to run.
   It will end up as .comm, so it shouldn't be too wasteful. */

//uint8_t  __afl_area_initial[MAP_SIZE];
//uint8_t* __afl_area_ptr = __afl_area_initial;

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
void obtain_base()
{
    base = (char *)query_lib("")->base;
    vm_R00 = (uint32_t *)(base + 0x614310 + 0x00);
    vm_R01 = (uint32_t *)(base + 0x614310 + 0x04);
    vm_R02 = (uint32_t *)(base + 0x614310 + 0x08);
    vm_R03 = (uint32_t *)(base + 0x614310 + 0x0c);
    vm_R04 = (uint32_t *)(base + 0x614310 + 0x10);
    vm_R05 = (uint32_t *)(base + 0x614310 + 0x14);
    vm_R06 = (uint32_t *)(base + 0x614310 + 0x18);
    vm_R07 = (uint32_t *)(base + 0x614310 + 0x1c);
    vm_R08 = (uint32_t *)(base + 0x614310 + 0x20);
    vm_R09 = (uint32_t *)(base + 0x614310 + 0x24);
    vm_R10 = (uint32_t *)(base + 0x614310 + 0x28);
    vm_R11 = (uint32_t *)(base + 0x614310 + 0x2c);
    vm_R12 = (uint32_t *)(base + 0x614310 + 0x30);
    vm_R13 = (uint32_t *)(base + 0x614310 + 0x34);
    vm_R14 = (uint32_t *)(base + 0x614310 + 0x38);
    vm_R15 = (uint32_t *)(base + 0x614310 + 0x3c);
    vm_R16 = (uint32_t *)(base + 0x614310 + 0x40);
    vm_R17 = (uint32_t *)(base + 0x614310 + 0x44);
    vm_R18 = (uint32_t *)(base + 0x614310 + 0x48);
    vm_R19 = (uint32_t *)(base + 0x614310 + 0x4c);
    vm_R20 = (uint32_t *)(base + 0x614310 + 0x50);
    vm_R21 = (uint32_t *)(base + 0x614310 + 0x54);
    vm_R22 = (uint32_t *)(base + 0x614310 + 0x58);
    vm_R23 = (uint32_t *)(base + 0x614310 + 0x5c); 
    vm_R24 = (uint32_t *)(base + 0x614310 + 0x60);
    vm_R25 = (uint32_t *)(base + 0x614310 + 0x64);
    vm_R26 = (uint32_t *)(base + 0x614310 + 0x68);
    vm_R27 = (uint32_t *)(base + 0x614310 + 0x6c);
    vm_R28 = (uint32_t *)(base + 0x614310 + 0x70);
    vm_ST =  (uint32_t *)(base + 0x614310 + 0x74);
    vm_RA =  (uint32_t *)(base + 0x614310 + 0x78);            
    vm_PC =  (uint32_t *)(base + 0x614310 + 0x7c);
}

void afl_store(uint32_t * vm_pc)
{
    uint32_t cur_location = * vm_pc;
    cur_location = (cur_location << 3) ^ (cur_location >> 3);
    __afl_key = (cur_location ^ __afl_prev_loc) % MAP_SIZE;
    __afl_area_ptr[__afl_key]++;
    __afl_prev_loc = cur_location >> 1;
}

void print_registers()
{
    printf("R00 : %07x\tR01 : %07x\tR02 : %07x\tR03 : %07x\n", *vm_R00, *vm_R01, *vm_R02, *vm_R03);
    printf("R04 : %07x\tR05 : %07x\tR06 : %07x\tR07 : %07x\n", *vm_R04, *vm_R05, *vm_R06, *vm_R07);
    printf("R08 : %07x\tR09 : %07x\tR10 : %07x\tR11 : %07x\n", *vm_R08, *vm_R09, *vm_R10, *vm_R11);
    printf("R12 : %07x\tR13 : %07x\tR14 : %07x\tR15 : %07x\n", *vm_R12, *vm_R13, *vm_R14, *vm_R15);
    printf("R16 : %07x\tR17 : %07x\tR18 : %07x\tR19 : %07x\n", *vm_R16, *vm_R17, *vm_R18, *vm_R19);
    printf("R20 : %07x\tR21 : %07x\tR22 : %07x\tR23 : %07x\n", *vm_R20, *vm_R21, *vm_R22, *vm_R23);
    printf("R24 : %07x\tR25 : %07x\tR26 : %07x\tR27 : %07x\n", *vm_R24, *vm_R25, *vm_R26, *vm_R27);
    printf("R28 : %07x\t ST : %07x\t RA : %07x\t %sPC : %07x%s\n", *vm_R28, *vm_ST, *vm_RA, KPNK, *vm_PC, KNRM);
}

/* handler functions */

void step_handler(context * ctx)
{
    //print_registers();
    addrint instr = ctx->rax;
    //printf("%spc : %07x%s\tinstruction : %llx\n", KYEL, *vm_PC, KNRM, instr);
    uint32_t header = (instr >> 22) & 0x1f;
    int32_t trace = 0;

    switch(header)
    {
        case 0x1c:    // CAR | CAA
        case 0x1a:    // Call Conditional
        case 0x18:    // B (branch)
          trace = 1;
          break;
    }

    if(trace) afl_store(vm_PC);

    ctx->rsi = *(uint32_t *)(base + 0x6143e0);
    ctx->PC = (addrint)base + 0x406d1f;
}

void exception_handler(context * ctx)
{
    printf("%scLEMENCy Exceptions%s\n", KPNK, KNRM);
    print_registers();
    raise(SIGSEGV);
    ctx->rdi = 0x14;
    ctx->PC = (addrint)base + 0x406966;
}

HOOK(0x406d19, step_handler);
HOOK(0x406961, exception_handler);
