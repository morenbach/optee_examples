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
#include "cfa_server.h"
#include "backtrace.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>

// #define VIRT_BUILD

#define FILE_REQ_PATH "/home/ubuntu/dev/shmem"

pthread_mutex_t cfa_mutex = PTHREAD_MUTEX_INITIALIZER;

volatile char virt_host_mem_started = 0;

void* virt_host_mem(void* arg) {  
  char* req_buffer = (char*)arg;

  int req_fd;
  do {
      req_fd = open(FILE_REQ_PATH, O_RDWR);
  } while (req_fd == -1 && errno == EINTR);

  if (req_fd == -1) {
    printf("Cannot get access to the request file to the host\n");
    exit(-1);
  }

  virt_host_mem_started = 1;

  while (1) {
      while (*req_buffer == 0) {  
        asm volatile("yield\n": : :"memory");
      }

      // forward request to the host server
      uintptr_t pa;
      size_t read_len;
      memcpy(&pa, &req_buffer[1], sizeof(uintptr_t));
      memcpy(&read_len, &req_buffer[1+sizeof(uintptr_t)], sizeof(size_t));
      char* response_buf = &req_buffer[1];
      req_buffer[1+sizeof(uintptr_t)+sizeof(size_t)]=0;

      int nwrite = pwrite(req_fd, req_buffer, 2+sizeof(uintptr_t)+sizeof(size_t),0);
      assert(nwrite == 2+sizeof(uintptr_t)+sizeof(size_t));

      char resp_available = 0;        
      do {
          pread(req_fd, &resp_available, 1, 1+sizeof(uintptr_t)+sizeof(size_t));
      } while(resp_available == 0);

      int left = read_len;
      do {
        int nread = pread(req_fd, response_buf, read_len, 2+sizeof(uintptr_t)+sizeof(size_t));      
        if (nread > 0) {
          left -= nread;
        }
      } while (left > 0);
      assert(left == 0);

      // mark response as ready 
      asm volatile("": : :"memory"); // Compile read-write barrier 
      *req_buffer = 0;
  }
}


int main(int argc, const char * argv[]) {
    uid_t uid=getuid();
    uid_t euid=geteuid();
    if (uid>0 && uid==euid) {
	    printf("Tracer must be run as root!\n");
	    exit(-1);
    }    

#ifdef VIRT_BUILD
    char* host_buffer = malloc(8192);
    assert(host_buffer);
    memset(host_buffer, 0, 8192);
    pthread_t host_mem_thread;
    if(pthread_create(&host_mem_thread, NULL, virt_host_mem, host_buffer)) {
      printf("ERROR creating the host memory serving thread...exiting\n");
      exit(-1);
    }

    while (!virt_host_mem_started) {
      asm volatile("yield\n": : :"memory");
    }

    create_tracer(host_buffer, 8192);
#else
    create_tracer(NULL, 0);
#endif

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
        puts(b);
	printf("\n");
	free(b);
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

      puts(b);
      printf("\n");
      free(b);
	    return 0;
    }

    pthread_t thread_cfa_server;
    pthread_create(&thread_cfa_server, NULL, *start_cfa_server, NULL);

    start_rest_server();
    return 0;
}
