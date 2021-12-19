// #include "tracer.h"
#include "tracer_interface.h"
#include "server.h"
#include <stdlib.h>

// TODO: folder structure - trusted, untrusted.


/* File purpose: Untrusted section in OP-TEE */


/* TODO:
 * + 1. Server to post tracing requests
   + 2. Ptrace enablement 
   3. JSON format - output the traces in agreed format correctly.
   4. Integration with op-tee-qemu
   5. Sign traces (and step 4 again)   
*/

int main(int argc, const char * argv[]) {
    create_tracer();
    // start_server();
    // do_backtrace(114341);
    unsigned int buflen = 10*1024*1024;
    char* b = (char*)malloc(buflen);
    if (!b) {
      return -1;
    }

    trace_civ(b, buflen);

    printf(b);
    printf("\n");
    free(b);
    return 0;
}