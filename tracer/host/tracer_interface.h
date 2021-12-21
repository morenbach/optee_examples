#ifndef __TRACER_INTERFACE_H
#define __TRACER_INTERFACE_H

#include <stdio.h>
#include <inttypes.h>


#ifdef __cplusplus
extern "C" {
#endif

void create_tracer();
void trace_cfa(int req_pid, uint64_t* stack_frames, int num_stack_frames, char* buffer, unsigned int buflen);
void trace_civ(char* buffer, unsigned int buflen);
void trace_pslist();

#ifdef __cplusplus
}
#endif

#endif