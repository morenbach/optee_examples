#ifndef __TRACER_BACKTRACE_H
#define __TRACER_BACKTRACE_H

#ifdef __cplusplus
extern "C" {
#endif

void do_backtrace (int pid, char* buf, unsigned int buflen);

#ifdef __cplusplus
}
#endif

#endif