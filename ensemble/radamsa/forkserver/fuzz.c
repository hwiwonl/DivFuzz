#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <dlfcn.h>
#include <string.h>
#include "forkserver.h"

#define SAYF(x...)    fprintf(stderr, x)
#define MAX(_a, _b) ((_a) > (_b) ? (_a) : (_b))

void log_(char *str) {
    SAYF("%s\n", str);
}

typedef int (*rad_main)(int, char *[]);

static pid_t child_pid;
static pid_t forksrv_pid;
static volatile unsigned char child_timed_out; // Tracd procdess timed out?
static struct itimerval it;
static int stop_soon;

static void handle_stop_sig() {

    stop_soon = 1;

    if (child_pid > 0)
        kill(child_pid, SIGKILL);
    if (forksrv_pid > 0)
        kill(forksrv_pid, SIGKILL);

}

static void handle_timeout() {

    if (child_pid > 0) {
        child_timed_out = 1;
        kill(child_pid, SIGKILL);

    } else if (child_pid == -1 && forksrv_pid > 0) {
        child_timed_out = 1;
        kill(forksrv_pid, SIGKILL);
    }
}

void setup_signal_handlers() {
    struct sigaction sa;

    sa.sa_handler = NULL;
    sa.sa_flags = SA_RESTART;
    sa.sa_sigaction = NULL;

    sa.sa_handler = (void (*)(int)) handle_stop_sig;
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    sa.sa_handler = (void (*)(int)) handle_timeout;
    sigaction(SIGALRM, &sa, NULL);
}

int run_target(int rd_fd, int wr_fd) {
    int parent_alive = PARENT_ALIVE;
    int status = 0;

    if ((write(wr_fd, &parent_alive, 4)) != 4) {
        if (stop_soon) return 0;
        SAYF("[fuzz] parent_alive write error\n");
        exit(0);
    }
    SAYF("[fuzz] parent_alive write success \n");

    if ((read_all(rd_fd, &child_pid, 4)) != 4) {
        if (stop_soon) return 0;
        SAYF("[fuzz] child_pid read error\n");
    }
    SAYF("[fuzz] child_pid read success\n");

    if (child_pid <= 0) {
        SAYF("[fuzz] Fork server is misbehaving (OOM?)\n");
        exit(0);
    }
    SAYF("[fuzz] Fork server works right!\n");
    // settimer

    it.it_value.tv_sec = (MAX(1000 + 50, 1000 * 125 / 100) / 1000);
    it.it_value.tv_usec = ((MAX(1000 + 50, 1000 * 125 / 100)) % 1000) * 1000;
    setitimer(ITIMER_REAL, &it, NULL);

    if ((read(rd_fd, &status, 4)) != 4) {
        if (stop_soon) return 0;
        SAYF("[fuzz] Unable to communicate with fork server (OOM?)\n");
        exit(0);
    }
    SAYF("[fuzz] Success to communicate with Forkserver\n");

    if (!WIFSTOPPED(status)) child_pid = 0;
    SAYF("[fuzz] child status: %d \n", status);

    it.it_value.tv_sec = 0;
    it.it_value.tv_usec = 0;
    setitimer(ITIMER_REAL, &it, NULL);

    return status;
}

int main() {
    ssize_t ret = 0;
    int inp[2];
    int outp[2];
    //static struct itimerval it;

    setup_signal_handlers();

    int i = 0;
    static char name[] = "/tmp/myfileXXXXXX";
    char fname[20] = {0x00,};
    int file_fd;
    void *handle = 0;
    rad_main func = NULL;
    strcpy(fname, name);
    file_fd = mkstemp(fname);
    SAYF("filename: %s \n", fname);

    handle = dlopen("./radamsa.so", RTLD_NOW | RTLD_GLOBAL);
    if (handle == NULL) {
        SAYF("Unable to open lib: %s\n", dlerror());
        return -1;
    }
    func = (rad_main) dlsym(handle, "main");

    if (func == NULL) {
        SAYF("Unable to get symbol\n");
        return -1;
    }

    char *rad_arg[] = {"./radamsa", "./test", NULL};
    int save_out;
    int fd_backup = dup(fileno(stdout));

    save_out = fd_backup;
    dup2(file_fd, fileno(stdout));
    func(2, rad_arg);
    fflush(stdout);
    dup2(save_out, fileno(stdout)); // back to normal
    close(save_out);
    lseek(file_fd, 0L, SEEK_SET);


    pipe(inp);
    pipe(outp);
    forksrv_pid = fork();


    if (forksrv_pid == 0) {
        SAYF("child\n");

        close(inp[1]);
        close(outp[0]);

        dup2(inp[0], FORKSRV_FD);
        dup2(outp[1], FORKSRV_FD + 1);

        dup2(file_fd, 0);
        close(file_fd);

        setsid();
        setenv("LD_BIND_NOW", "1", 0);
        char *arg[] = {"./out/in.new", NULL};

        // run forkserver
        SAYF("[fuzz] starting execv\n");
        execv("./out/in.new", arg);

        // should not reach here
        return 0;
    } else {
        SAYF("parent\n");
        close(outp[1]);
        close(inp[0]);

        it.it_value.tv_sec = ((1000 * 10) / 1000);
        it.it_value.tv_usec = ((1000 * 10) % 1000) * 1000;
        setitimer(ITIMER_REAL, &it, NULL);

        //char buf[4096]={0x00,};
        //char status[5] = {0x00,};
        int child_start = 0;

        ret = read(outp[0], &child_start, 4);

        it.it_value.tv_sec = 0;
        it.it_value.tv_usec = 0;
        setitimer(ITIMER_REAL, &it, NULL);

        SAYF("child_start: %x \n", child_start);
        if (ret == 4 && child_start == CHILD_START) {
            SAYF("[fuzz] forkserver is up\n");
        } else {
            SAYF("[fuzz - parent] error while read \n");
            exit(0);
        }

        //static char name[] = "/tmp/testXXXXXX";
        //char fname[20] = {0x00,};
        //  int file_fd;
        strcpy(fname, name);
        //file_fd = mkstemp(fname);
        SAYF("filename: %s \n", fname);

        handle = dlopen("./radamsa.so", RTLD_NOW | RTLD_GLOBAL);
        if (handle == NULL) {
            SAYF("Unable to open lib: %s\n", dlerror());
            return -1;
        }
        func = (rad_main) dlsym(handle, "main");

        if (func == NULL) {
            SAYF("Unable to get symbol\n");
            return -1;
        }

//    char *rad_arg[] ={"./radamsa","./test", NULL};
//    int save_out = dup(fileno(stdout));
//    int fd_backup = dup(fileno(stdout));
        //dup2(file_fd, fileno(stdout));
        //  func(2, rad_arg);

        for (i = 0; i < FUZZ_ITERATION; i++) {

            ftruncate(file_fd, 0);
            save_out = fd_backup;
            dup2(file_fd, fileno(stdout));
            func(2, rad_arg);
            fflush(stdout);
            dup2(save_out, fileno(stdout)); // back to normal
            close(save_out);
            lseek(file_fd, 0L, SEEK_SET);
//      SAYF("child status: %d \n",run_target(outp[0], inp[1]));
            ret = run_target(outp[0], inp[1]);
            SAYF("child status: %ld \n", ret);
            if (stop_soon) {
                log_("stop_error triggered");
                return 0;
            }
        }

/*
    read(log[0], buf, sizeof(buf));
    SAYF("buf: %s \n",buf);
*/
        //setitimer
    } //else

    return 0;
}
