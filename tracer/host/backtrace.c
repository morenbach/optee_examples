#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libunwind-ptrace.h>
#include "tracer_interface.h"

#define MAX_CFA_RESPONSE_SIZE (1024*1024) // 1MB

enum WaitResult
{
      STOPPED     = 0
    , TERMINATED  = 1
};

enum WaitResult ptrace_wait_syscall(pid_t pid) {
    int  status;

    for(;;) {
        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        waitpid(pid, &status, 0);	

        // This predicate holds when the monitored process
        // has terminated.
        if (WIFEXITED(status)) {
            return TERMINATED; 
        }

        // Credits and further reading:  
        //   => https://ops.tips/gists/using-c-to-inspect-linux-syscalls
        if (WIFSTOPPED(status) && (WSTOPSIG(status) == (SIGTRAP | 0x80))) { 
            return STOPPED; 
        }
    }
}

void do_backtrace (int pid)
{
    // int verbose = 1;
    // int print_names = 1;
    // int status,p;

    unw_addr_space_t as;	
    struct UPT_info *ui;
    // unw_word_t ip, sp, start_ip = 0, off;

    int ret;
    // unw_proc_info_t pi;
    unw_cursor_t c;
    // char buf[512];
    // size_t len;

    if (ptrace(PTRACE_ATTACH, pid, 0, 0) != 0) {
        printf("ERROR: cannot attach to %d\n", pid);
        return;
    }

    waitpid(pid, NULL, 0);

    int stack_frame_idx = 0;
    uint64_t* stack_frames = (uint64_t*)malloc(1000 * sizeof(uint64_t)); // enough to capture all possible stack frames

    as = unw_create_addr_space (&_UPT_accessors, 0);
    ui = _UPT_create (pid);
    //ptrace( PTRACE_SETOPTIONS, pid, NULL, (void*) PTRACE_O_TRACECLONE);
    ptrace( PTRACE_SETOPTIONS, pid, NULL, (void*) PTRACE_O_TRACESYSGOOD);

    ptrace_wait_syscall(pid);

    ret = unw_init_remote (&c, as, ui);
    if (ret < 0) {
        printf("unw_init_remote() failed: ret=%d\n", ret);
        return;
    }

    do {
        // unw_word_t offset;
        unw_word_t pc;
        // char sym[4096];
        if (unw_get_reg(&c, UNW_REG_IP, &pc)) {
            printf("ERROR: cannot read program counter\n");
            break;
        }

        stack_frames[stack_frame_idx++] = pc;

        // if (unw_get_proc_name(&c, sym, sizeof(sym), &offset) == 0) {
        //     printf("(%s+0x%lx)\n", sym, offset);
        // } else {
        //     printf("-- no symbol name found\n");
        // }
    } while (unw_step(&c) > 0);
    
    char* buffer = (char*)malloc(MAX_CFA_RESPONSE_SIZE);
    if (!buffer) {
        return; // failed to allocate memory
    }

    int num_stack_frames = stack_frame_idx;
    trace_cfa(pid, stack_frames, num_stack_frames, buffer, MAX_CFA_RESPONSE_SIZE);
    puts(buffer);
    printf("\n");
    free(buffer);

    _UPT_destroy (ui);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    unw_destroy_addr_space (as);
}