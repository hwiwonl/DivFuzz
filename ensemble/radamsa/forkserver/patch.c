#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <handler.h>
#include "forkserver.h"

void log(char *str) {
    fprintf(stderr, "%s \n", str);
}

__attribute__((constructor))
void forkserver(context *ctx) {
    int child_pid = 0;
    int status = 0;
    int fd[2];
    ssize_t ret = 0;
    int i = 0;
    int child_start = CHILD_START;
    unsigned char child_stopped = 0;

    //pipe(fd);
    //dup2(fd[0], FORKSRV_FD);
    //dup2(fd[1], FORKSRV_FD+1);
    //printf("[forksrv] start forkserver\n");
    log("[forksrv] start forkserver");
    //  send parent i'm starting
    if (write(FORKSRV_FD + 1, &child_start, 4) != 4)
        log("[forksrv] write child alive error");
    log("[forksrv] child alive write success");
    //printf("[forksrv] FORKSRV_FD+1 write success\n");

    for (i = 0; i < FUZZ_ITERATION; i++) {
        unsigned int was_killed;

        // check parent is alive
        //if(read(FORKSRV_FD, &was_killed, 4) != 4 && was_killed == 0x42424242){
        ret = read_all(FORKSRV_FD, &was_killed, 4);
        if (ret == 4 && was_killed == PARENT_ALIVE) {
            log("[forksrv] Parent is alive!");
        } else {
            log("[forksrv] - read parent check error");
            exit(1);
        }

        if (child_stopped != 0 && was_killed != 0) {
            child_stopped = 0;
            if (waitpid(child_pid, &status, 0) < 0) {
                log("[forksrv] waiting yet stopped child error");
                exit(1);
            }
        }

        if (child_stopped == 0) {
            child_pid = fork();
            if (child_pid < 0) {
                log("[forksrv] fork error");
                exit(1);
            }
            // child
            if (child_pid == 0) {
                close(FORKSRV_FD);
                close(FORKSRV_FD + 1);
                // return and execute phrase
                return;
//        return;
            }
        } else {
            kill(child_pid, SIGCONT);
            child_stopped = 0;
        }

        //
        if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) {
            log("[forksrv] write child_pid error");
            exit(1);
        }

        if (waitpid(child_pid, &status, 0) < 0) {
            log("[forksrv] waitchild_pid error");
            exit(1);
        }

        if (WIFSTOPPED(status)) child_stopped = 1;
        if (write(FORKSRV_FD + 1, &status, 4) != 4) {
            log("[forksrv] write status error");
            exit(1);
        }
    }
}
