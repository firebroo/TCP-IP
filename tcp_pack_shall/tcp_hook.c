#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>        
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/tcp.h>

#define BUFFER_SIZE 4096

int
main(void) {
    int sock_raw, data_size;
    struct iphdr *iph;
    struct  sockaddr saddr;
    unsigned int saddr_size;
    unsigned short iphdrlen;
    char buffer[BUFFER_SIZE], source_ip[20], dest_ip[20];
    struct sockaddr_in source,dest;

    saddr_size = sizeof(saddr);
    sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    if(sock_raw < 0) {
        perror("create socket");
        exit(-1);
    }
    for( ; ; ) {
        data_size = recvfrom(sock_raw , buffer , sizeof(buffer) , 0 , &saddr , &saddr_size);
        if (data_size < 0) {
            perror("revcfrom");
            exit(-1);
        }


        inet_ntop(AF_INET, &(iph->saddr), source_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(iph->daddr), dest_ip, INET_ADDRSTRLEN);
        iph = (struct iphdr*)buffer;
        if(iph->protocol == 6)
        {
            struct iphdr *iph = (struct iphdr *)buffer;
            iphdrlen = iph->ihl*4;

            struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);
            printf("saddr: %s:%d->daddr: %s:%d\ntotal_len: %d bytes\n", 
                source_ip,
                ntohs(tcph->source), 
                dest_ip,
                ntohs(tcph->dest),
                ntohs(iph->tot_len)
                /*ntohl(iph->check)>> 16*/
                );
            //if(tcph->syn) {
            //    printf("seq number: %d\n", ntohl(tcph->seq));
            //}
            //if(tcph->ack) {
            //    printf("ack number: %d\n", ntohl(tcph->ack_seq));
            //}

            //memset(&source, 0, sizeof(source));
            //source.sin_addr.s_addr = iph->saddr;

            //memset(&dest, 0, sizeof(dest));
            //dest.sin_addr.s_addr = iph->daddr;

            printf("FIN: %d\tSYN: %d\tACK: %d\tRST: %d\tPSH: %d\tURG: %d\n", 
                    tcph->fin,
                    tcph->syn,
                    tcph->ack,
                    tcph->rst,
                    tcph->psh,
                    tcph->urg);
            printf("\n\n");
        }
    }
    exit(0);
}
