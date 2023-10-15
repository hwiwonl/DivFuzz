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

char *vm_flags = NULL;
char **vm_base = NULL;

uint32_t m_regs[32];                // Miscellaneous registers
uint32_t * m_pc = NULL;               // Program counter
uint32_t * m_instr = NULL;            // The current instruction
uint32_t * m_hi = NULL, * m_lo = NULL;  // Division and multiplication results
uint32_t * m_nextEpc = NULL;          // Next exception PC
uint32_t * m_lastEpc = NULL;          // The last exception PC

uint32_t * m_errnoAddress = NULL;  // The address of errno

char * m_exceptionPending;
char * m_optBigendian;

uint32_t * m_instrCount;

// Delay slot handling.
int * m_delayState; // State of delay slot
uint32_t * m_delayPC;    // Delay slot program counter

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
void obtain_bases()
{
  base = (char *)query_lib("")->base;
}

void afl_store(uint32_t * vm_pc) {

  // Sends coverage to afl
  uint32_t cur_location = *vm_pc;
  cur_location = (cur_location << 3) ^ (cur_location >> 3);    
  __afl_key = (cur_location ^ __afl_prev_loc) % MAP_SIZE;
  __afl_area_ptr[__afl_key]++;
  __afl_prev_loc = cur_location >> 1;
  
  /*
    unsigned short cur_location = *vm_pc;
    __afl_area_ptr[cur_location]++;
  */
  /*
	unsigned short cur_location = *vm_pc;
    __afl_key = cur_location ^ __afl_prev_loc;
    __afl_area_ptr[__afl_key]++;
    __afl_prev_loc = cur_location >> 1;  
  */
}

void _return(context *ctx) {
    ctx->rsp += 8;
}

unsigned short uint16_at(uint16_t where) {
    uint16_t *ptr = (uint16_t *)((*vm_base) + where);
    return *ptr;
}

/* handler functions */

/*
.data.rel.ro:00000000002088C0 ; const tEmulateFptr CCPU::step(void)::opcodeJumpTable[64]
.data.rel.ro:00000000002088C0 _ZZN4CCPU4stepEvE15opcodeJumpTable dq offset _ZN4CCPU13funct_emulateEjj
.data.rel.ro:00000000002088C0                                         ; DATA XREF: CCPU::step(void)+4Bo
.data.rel.ro:00000000002088C0                                         ; CCPU::funct_emulate(uint,uint)
.data.rel.ro:00000000002088C8                 align 10h
.data.rel.ro:00000000002088D0                 dq offset _ZN4CCPU14regimm_emulateEjj ; CCPU::regimm_emulate(uint,uint)
.data.rel.ro:00000000002088D8                 align 20h
.data.rel.ro:00000000002088E0                 dq offset _ZN4CCPU9j_emulateEjj ; CCPU::j_emulate(uint,uint)
.data.rel.ro:00000000002088E8                 align 10h
.data.rel.ro:00000000002088F0                 dq offset _ZN4CCPU11jal_emulateEjj ; CCPU::jal_emulate(uint,uint)
.data.rel.ro:00000000002088F8                 align 20h
.data.rel.ro:0000000000208900                 dq offset _ZN4CCPU11beq_emulateEjj ; CCPU::beq_emulate(uint,uint)
.data.rel.ro:0000000000208908                 align 10h
.data.rel.ro:0000000000208910                 dq offset _ZN4CCPU11bne_emulateEjj ; CCPU::bne_emulate(uint,uint)
.data.rel.ro:0000000000208918                 align 20h
.data.rel.ro:0000000000208920                 dq offset _ZN4CCPU12blez_emulateEjj ; CCPU::blez_emulate(uint,uint)
.data.rel.ro:0000000000208928                 align 10h
.data.rel.ro:0000000000208930                 dq offset _ZN4CCPU12bgtz_emulateEjj ; CCPU::bgtz_emulate(uint,uint)
.data.rel.ro:0000000000208938                 align 20h
*/

void step_handler(context * ctx)
{
  addrint curinstr = ctx->rax;
  addrint this = ctx->rbx;

  uint32_t offset = curinstr >> 26;
  offset = offset << 4;

  m_pc = (uint32_t *)(this+0x490);
  m_instr = (uint32_t *)(this+0x494);
  m_hi = (uint32_t *)(this+0x498);
  m_lo = (uint32_t *)(this+0x49c);
  m_nextEpc = (uint32_t *)(this+0x4a0);
  m_lastEpc = (uint32_t *)(this+0x4a4);
  m_delayState = (int *)(this+0x4b4);
  m_delayPC = (uint32_t *)(this+0x4b8);
  m_instrCount = (uint32_t *)(this+0x4b0);
  m_exceptionPending = (char *)(this+0x4ac);
  
  //printf("m_pc : 0x%x\n", *m_pc);
  //printf("m_exceptionPending : %d\n", *m_exceptionPending);

  int32_t trace = 0;

  switch(offset)
  {
    case 0x20:  // j
    case 0x30:  // jal
    case 0x40:  // beq
    case 0x50:  // bne
    case 0x60:  // blez
    case 0x70:  // bgtz
        trace = 1;
        break;
  }

  if(trace) afl_store(m_pc);
  
  /*
  if(offset == 0x20){
    printf("%s[j_emulate] called%s\n", KPNK, KNRM);
    //afl_store(m_pc);
  }
  if(offset == 0x30){
    //afl_store(m_pc);
    printf("%s[jal_emulate] called%s\n", KPNK, KNRM);
  }
  if(offset == 0x40){
    //afl_store(m_pc);
    printf("%s[beq_emulate] called%s\n", KPNK, KNRM);
  }
  if(offset == 0x50){
    //afl_store(m_pc);
    printf("%s[bne_emulate] called%s\n", KPNK, KNRM);
  }
  if(offset == 0x60){
    //afl_store(m_pc);
    printf("%s[blez_emulate] called%s\n", KPNK, KNRM);
  }
  if(offset == 0x70){
    //afl_store(m_pc);
    printf("%s[bgtz_emulate] called%s\n", KPNK, KNRM);
  }
  */
  if(!*m_exceptionPending)
    ctx->PC = (addrint)base + 0x32e1;
  else
    ctx->PC = (addrint)base + 0x3346;
}

void exception_handler(context *ctx)
{
  addrint this = ctx->rdi;
  addrint code = ctx->rsi;

  int32_t exeCode = (int32_t)code;
  m_nextEpc = (uint32_t *)(this+0x4a0);

  printf("exeCode : %d\n", exeCode);
  //printf("next PC : 0x%x\n", * m_nextEpc);
  if(!exeCode){
    printf("%sException PC on xxxx%s\n", KRED, KNRM);
    raise(SIGSEGV);
    ctx->PC = (addrint)base + 0x327c;
  }else{
    printf("%sException:%s\n", KRED, KNRM);
    raise(SIGSEGV);
    ctx->PC = (addrint)base + 0x32a1;
  }
}

HOOK(0x32d8, step_handler);
HOOK(0x3214, exception_handler);

