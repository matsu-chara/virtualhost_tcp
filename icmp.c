#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <pthread.h>

#include "param.h"
#include "sock.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"

extern PARAM Param;

#define ECHO_HDR_SIZE (8) // echo header size
#define PING_SEND_NO (4)  // ping送信コマンドでのパケット送信数

typedef struct
{
    struct timeval sendTime; // pingのRTT計算用
} PING_DATA;

PING_DATA PingData[PING_SEND_NO];

int print_icmp(struct icmp *icmp)
{
    static char *icmp_type[] = {
        "Echo Reply",
        "undefined",
        "undefined",
        "Destination Unreachable",
        "Source Quench",
        "Redirect",
        "undefined",
        "undefined",
        "Echo Request",
        "Router Advertisement",
        "Router Selection",
        "Time Exceeded for Datagram",
        "Parameter Problem on Datagram",
        "Timestamp Request",
        "Timestamp Reply",
        "Information Request",
        "Information Reply",
        "Address Mask Request",
        "Address Mask Reply"};

    printf("icmp------------------------------------\n");

    printf("icmp_type=%u", icmp->icmp_type);
    if (icmp->icmp_type <= 18)
    {
        printf("(%s),", icmp_type[icmp->icmp_type]);
    }
    else
    {
        printf("(undefined),");
    }
    printf("icmp_code=%u,", icmp->icmp_code); // icmp_typeのサブコード(bad hostなど)
    printf("icmp_cksum=%u\n", ntohs(icmp->icmp_cksum));

    // echo reply か echo requestの場合はid, seqをprint
    if (icmp->icmp_type == ICMP_ECHOREPLY || icmp->icmp_type == ICMP_ECHO)
    {
        printf("icmp_id=%u,", ntohs(icmp->icmp_id));
        printf("icmp_seq=%u\n", ntohs(icmp->icmp_seq));
    }
    printf("icmp------------------------------------\n");
    return 0;
}

int IcmpSendEchoReply(int soc, struct ip *r_ip, struct icmp *r_icmp, u_int8_t *data, int len, int ip_ttl)
{
    uint8_t *ptr;
    uint8_t sbuf[64 * 1024];
    struct icmp *icmp;

    ptr = sbuf;
    icmp = (struct icmp *)ptr;
    memset(icmp, 0, sizeof(struct icmp));
    icmp->icmp_type = ICMP_ECHOREPLY;
    icmp->icmp_code = 0;
    icmp->icmp_hun.ih_idseq.icd_id = r_icmp->icmp_hun.ih_idseq.icd_id; // hun は Header UNion の略っぽい。
    icmp->icmp_hun.ih_idseq.icd_seq = r_icmp->icmp_hun.ih_idseq.icd_seq;
    icmp->icmp_cksum = 0;

    ptr += ECHO_HDR_SIZE;

    memcpy(ptr, data, len);
    ptr += len;

    icmp->icmp_cksum = checksum(sbuf, ptr - sbuf);

    printf("=== ICMP reply ===[\n]");
    IpSend(soc, &r_ip->ip_dst, &r_ip->ip_src, IPPROTO_ICMP, 0, ip_ttl, sbuf, ptr - sbuf);
    print_icmp(icmp);
    printf("]\n");

    return 0;
}

int IcmpSendEcho(int soc, struct in_addr *daddr, int seqNo, int size)
{
    int psize;
    uint8_t *ptr;
    uint8_t sbuf[64 * 1024];
    struct icmp *icmp;

    ptr = sbuf;
    icmp = (struct icmp *)ptr;
    memset(icmp, 0, sizeof(struct icmp));
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_hun.ih_idseq.icd_id = htons((uint16_t)getpid());
    icmp->icmp_hun.ih_idseq.icd_seq = htons((uint16_t)seqNo);
    icmp->icmp_cksum = 0;

    ptr += ECHO_HDR_SIZE;

    // pingの大きさを決めてFFで埋める
    psize = size - ECHO_HDR_SIZE;
    for (int i = 0; i < psize; i++)
    {
        *ptr = (i & 0xFF);
        ptr++;
    }

    icmp->icmp_cksum = checksum((uint8_t *)sbuf, ptr - sbuf);

    printf("=== ICMP echo ===[\n");
    IpSend(soc, &Param.vip, daddr, IPPROTO_ICMP, 0, Param.IpTTL, sbuf, ptr - sbuf);
    print_icmp(icmp);
    printf("]\n");

    gettimeofday(&PingData[seqNo - 1].sendTime, NULL);

    return 0;
}

int IcmpSendDestinationUnreachable(int soc, struct in_addr *daddr, struct ip *ip, u_int8_t *data, int len)
{
    uint8_t *ptr;
    uint8_t sbuf[64 * 1024];
    struct icmp *icmp;

    ptr = sbuf;
    icmp = (struct icmp *)ptr;
    memset(icmp, 0, sizeof(struct icmp));
    icmp->icmp_type = ICMP_DEST_UNREACH;
    icmp->icmp_code = ICMP_PORT_UNREACH;
    icmp->icmp_cksum = 0;

    ptr += ECHO_HDR_SIZE;

    memcpy(ptr, ip, sizeof(struct ip));
    ptr += sizeof(struct ip);

    if (len >= 64)
    {
        memcpy(ptr, data, 64);
        ptr += 64;
    }
    else
    {
        memcpy(ptr, data, len);
        ptr += len;
    }

    icmp->icmp_cksum = checksum((uint8_t *)sbuf, ptr - sbuf);

    printf("=== ICMP Destination Unreachable ==[\n");
    IpSend(soc, &Param.vip, daddr, IPPROTO_ICMP, 0, Param.IpTTL, sbuf, ptr - sbuf);
    print_icmp(icmp);
    printf("]\n");

    return 0;
}

int PingSend(int soc, struct in_addr *daddr, int size)
{
    for (int i = 0; i < PING_SEND_NO; i++)
    {
        IcmpSendEcho(soc, daddr, i + 1, size);
        sleep(1);
    }

    return 0;
}

int PingCheckReply(struct ip *ip, struct icmp *icmp)
{
    char buf1[80];

    if (ntohs(icmp->icmp_id) == getpid())
    {
        int seqNo = ntohs(icmp->icmp_seq);
        if (seqNo > 0 && seqNo <= PING_SEND_NO)
        {
            struct timeval tv;
            gettimeofday(&tv, NULL);
            int sec = tv.tv_sec - PingData[seqNo - 1].sendTime.tv_sec;
            int usec = tv.tv_usec - PingData[seqNo - 1].sendTime.tv_usec;
            // システムクロックに誤差がある場合マイクロ秒が負になることがある。（システムクロックが正しく設定されていない場合も負になることがある）
            if (usec < 0)
            {
                sec--;
                usec = 10000 - usec;
            }
            printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%d.%03d ms\n",
                   ntohs(ip->ip_len),
                   inet_ntop(AF_INET, &ip->ip_src, buf1, sizeof(buf1)),
                   ntohs(icmp->icmp_seq),
                   ip->ip_ttl,
                   sec,
                   usec);
        }
    }

    return 0;
}

int IcmpRecv(int soc, u_int8_t *raw, int raw_len, struct ether_header *eh, struct ip *ip, u_int8_t *data, int len)
{
    struct icmp *icmp;
    u_int16_t sum;
    int icmpSize;
    uint8_t *ptr = data;

    icmpSize = len;
    icmp = (struct icmp *)ptr;
    ptr += ECHO_HDR_SIZE;
    len -= ECHO_HDR_SIZE;

    sum = checksum((uint8_t *)icmp, icmpSize);
    if (sum != 0 && sum != 0xFFFF)
    {
        printf("bad icmp checksum(%x, %x)\n", sum, icmp->icmp_cksum);
        return -1;
    }

    if (isTargetIPAddr(&ip->ip_dst))
    {
        printf("--- recv ---[\n");
        print_ether_header(eh);
        print_ip(ip);
        print_icmp(icmp);
        printf("]\n");
        if (icmp->icmp_type == ICMP_ECHO)
        {
            IcmpSendEchoReply(soc, ip, icmp, ptr, len, Param.IpTTL);
        }
        else if (icmp->icmp_type == ICMP_ECHOREPLY)
        {
            PingCheckReply(ip, icmp);
        }
    }

    return 0;
}
