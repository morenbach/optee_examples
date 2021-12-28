/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include "tracer_interface.h"
#include "server.h"
#include "backtrace.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main(int argc, const char * argv[]) {
    uid_t uid=getuid();
    uid_t euid=geteuid();
    if (uid>0 && uid==euid) {
	    printf("Tracer must be run as root!\n");
	    exit(-1);
    }    

    create_tracer();

    // A simple test to debug tracer functionality
    // 
    if (argc > 1 && strcmp(argv[1], "test") == 0) {
    	trace_pslist();
	    return 0;
    }

    if (argc > 1 && strcmp(argv[1], "test_attestation") == 0) {
      unsigned int buflen = 1*1024*1024;
      char* b = (char*)malloc(buflen);
      if (!b) {
        return -1;
      }

      if (argc < 2) {
        printf("Invalid attestation option to test\n");
        return -1;
      }

      if (strcmp(argv[2], "civ") == 0) {
        trace_civ(b, buflen);    
        return 0;
      }

      if (strcmp(argv[2], "cfa") != 0) {
        printf("Invalid attestation option recieved\n");
        return -1;
      }

      if (argc < 3) {
        printf("CFA attestation requires PID to test with\n");
        return -1;
      }

      do_backtrace(atoi(argv[3]), b, buflen);

      printf(b);
      printf("\n");
      free(b);
	    return 0;
    }

    start_server();
    return 0;
}
