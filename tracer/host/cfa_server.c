#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h> 
#include <stdlib.h>
#include <errno.h>  
#include <pthread.h>
#include "tracer_interface.h"

#define MAX 80
#define PORT 65432
#define SA struct sockaddr

extern pthread_mutex_t cfa_mutex; // = PTHREAD_MUTEX_INITIALIZER;
   
// Driver function
void* start_cfa_server(void* unused)
{
    (void)unused;

    int sockfd, connfd;
    socklen_t len;
    struct sockaddr_in servaddr, cli;
    char data[100];

    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    bzero(&servaddr, sizeof(servaddr));
   
    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);

    int yes = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
   
    // Binding newly created socket to given IP and verification
    if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) {
        printf("socket bind failed...\n");
        exit(0);
    }

    // Now server is ready to listen and verification
    if ((listen(sockfd, 5)) != 0) {
        printf("Listen failed...\n");
        exit(0);
    }

    len = sizeof(cli);

    while (1) {
	    // Accept the data packet from client and verification
	    connfd = accept(sockfd, (SA*)&cli, &len);
	    if (connfd < 0) {
		    printf("server accept failed...\n");
		    exit(0);
	    }

        // printf("new program trace started...\n");

	    // Function for getting instructions
	    while (1) {
		    memset(data,0,100);
            int payload_size;
		    unsigned int n = read(connfd, &payload_size, 4);
            if (n > 0) {
                int left = payload_size;
                do {
                    int r = read(connfd, data, left);
                    if (r > 0)
                        left -= r;
                } while (left > 0);
		        
                if (strcmp(data, "DONE") == 0) {
                    // printf("program trace done...\n");
                    break;
                }                

                //printf("RECV: %s\n", data);            

                pthread_mutex_lock( &cfa_mutex );
                trace_control_flow(data);    
                pthread_mutex_unlock( &cfa_mutex );
            }
	    }

	    close(connfd);
    }   
    // After chatting close the socket
    close(sockfd);

    return 0;
}
