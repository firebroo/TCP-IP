#include <stdio.h>	
#include <stdlib.h>	
#include <string.h>	
#include <unistd.h>
#include <netinet/tcp.h>	
#include <netinet/ip.h>	
#include <sys/socket.h>
#include <arpa/inet.h>

void ProcessPacket(unsigned char* , int);
void print_tcp_packet(unsigned char* , int);
void PrintData (unsigned char* , int);

int sock_raw;
struct sockaddr_in source,dest;

int main()
{
    int             sockfd, data_size;
    unsigned int    saddr_size; 
    struct sockaddr saddr;

    unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!

    printf("Starting...\n");
    /*Create a raw socket that shall sniff*/
    sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    if(sock_raw < 0)
    {
        printf("Socket Error\n");
        return 1;
    }
    saddr_size = sizeof(saddr);
    while(1)
    {
        /*Receive a packet*/
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
        if(data_size <= 0)
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        if ( (sockfd = fork()) < 0) {
            perror("fork");
            return 1;
        }
        if (sockfd == 0) {
            /*Now process the packet*/
            close(sock_raw);
            ProcessPacket(buffer , data_size);
            exit(0);
        }
    }
    close(sock_raw);
    printf("Finished");
    return 0;
}

void ProcessPacket(unsigned char* buffer, int size)
{
    //Get the IP Header part of this packet
    struct iphdr *iph = (struct iphdr*)buffer;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
        case 2:  //IGMP Protocol
            break;

        case 6:  //TCP Protocol
            print_tcp_packet(buffer , size);
            break;

        case 17: //UDP Protocol
            break;

        default: //Some Other Protocol like ARP etc.
            //PrintData(buffer, size);
            break;
    }
}

void print_tcp_packet(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
    char *buffer;

    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = (iph->ihl) * 4;

    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen);

    buffer = Buffer + iphdrlen + tcph->doff * 4;

    if (/*buffer[0] == 0x24*/ 
            (buffer[1] == 0x00 
             && buffer[2]  == 0x00
             && buffer[3] == 0x00
             && buffer[4] == 0x03) 
            || (/*buffer[0] == 0x47*/
                /*buffer[1] == 0x01*/
                buffer[2] == 0x00
                && buffer[3] == 0x00
                && buffer[4] == 0x16)
            && ntohs(tcph->dest) == 3306) {
        PrintData(Buffer + iphdrlen + (tcph->doff) * 4 + 5 , (Size - ((tcph->doff) * 4 - iphdrlen) - 45 ));
    }else {
        return;
    }
}

void PrintData (unsigned char* data , int size)
{
    int     i,j;

    for(i=0 ; i < size ; i++)
    {
        if( i != 0 && i % 16 == 0)   //if one line of hex printing is complete...
        {
            fprintf(stdout,"         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(stdout,"%c",(unsigned char)data[j]); //if its a number or alphabet

                else fprintf(stdout,"."); //otherwise print a dot
            }
            fprintf(stdout,"\n");
        } 

        if(i % 16 == 0) fprintf(stdout, "   ");
        fprintf(stdout, " %02X", (unsigned int)data[i]);

        if( i == size - 1)  //print the last spaces
        {
            for(j = 0; j< 15 - i % 16; j++) fprintf(stdout,"   "); //extra spaces

            fprintf(stdout,"         ");

            for(j = i - i % 16; j <= i; j++)
            {
                if(data[j] >= 32 && data[j] <= 128) fprintf(stdout, "%c", (unsigned char)data[j]);
                else fprintf(stdout,".");
            }
            fprintf(stdout,"\n");
        }
    }
}
