#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define THREAD_COUNT 3

char server_ip[16];
int port;

void *client_thr(void *arg) {
    //create a normal connect socket
    while(1) {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            perror("Failed to create socket");
            exit(EXIT_FAILURE);
        }
        
        struct sockaddr_in server;
        server.sin_family = AF_INET;
        server.sin_port = htons(port);
        server.sin_addr.s_addr = inet_addr(server_ip);

        //connect to the server
        if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
            perror("Failed to connect to server");
        }

        int randomnum = rand() % 10+10;
        sleep(randomnum);

    }
    
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    
    if (argc != 3) {
        printf("Usage: %s <server_ip> <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    strcpy(server_ip, argv[1]);
    port = atoi(argv[2]);

    pthread_t threads[THREAD_COUNT];
    for (int i = 0; i < THREAD_COUNT; i++) {
        if (pthread_create(&threads[i], NULL, client_thr, NULL) != 0) {
            perror("Failed to create SYN handler thread");
            exit(EXIT_FAILURE);
        }
    }

    for (int i = 0; i < THREAD_COUNT; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}