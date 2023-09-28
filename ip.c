#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <pthread.h>

#include "param.h"
#include "sock.h"
#include "ether.h"
#include "arp.h"

extern PARAM Param;

#define IP_RECV_BUF_NO (16)

typedef struct
{
    time_t timestamp;
    int id; // IPヘッダのid
    u_int8_t data[64 * 1024];
    int len;
} IP_RECV_BUF;

IP_RECV_BUF IpRecvBuf[IP_RECV_BUF_NO]; // フラグメントがあってもいいように１データ分が揃うまで受信パケットをバッファにためておく

void print_ip(struct ip *ip)
{
    static char *proto[] = {
        "undefined",
        "ICMP",
        "IGMP",
        "undefined",
        "IPIP",
        "undefined",
        "TCP",
        "undefined",
        "EGP",
        "undefined",
        "undefined",
        "undefined",
        "PUP",
        "undefined",
        "undefined",
        "undefined",
        "undefined",
        "UDP"};

    char buf1[80];

    printf("ip------------------------------------------------------------------------------\n");
    printf("ip_v=%u", ip->ip_v);              // version
    printf("ip_hl=%u", ip->ip_hl);            // header length
    printf("ip_tos=%x", ip->ip_tos);          // type of service
    printf("ip_len=%d\n", ntohs(ip->ip_len)); // total length
    printf("ip_id=%u", ntohs(ip->ip_id));     // id

    // fragment offset field
    // フラグオフセットフィールドは13bit。 値が1なら8byte目, 2なら16byte目のデータが入っている。
    // ip_off はshort = 16bit
    // IP_OFFMSK = mask for fragmenting bits (値は0x1fff = 下位13bit分取れるマスク)
    // ip_offの先頭3bitを表示しているがこれはflagフィールド。(データが分割されているかどうか)
    printf("ip_off=%x,%d\n", (ntohs(ip->ip_off)) >> 13 & 0x07, ntohs(ip->ip_off) & IP_OFFMASK);

    printf("ip_ttl=%u", ip->ip_ttl); // ttl
    printf("ip_p=%u", ip->ip_p);     // protocol
    if (ip->ip_p <= 17)
    {
        printf("(%s)", proto[ip->ip_p]);
    }
    else
    {
        printf("(undefined),");
    }
    printf("ip_sum=%04x\n", ntohs(ip->ip_sum));                                 // checksum
    printf("ip_src=%s\n", inet_ntop(AF_INET, &ip->ip_src, buf1, sizeof(buf1))); // source address
    printf("ip_dst=%s\n", inet_ntop(AF_INET, &ip->ip_dst, buf1, sizeof(buf1))); // destination address

    return;
}

int IpRecvBufInit()
{
    for (int i = 0; i < IP_RECV_BUF_NO; i++)
    {
        IpRecvBuf[i].id = 1;
    }
    return 0;
}

int IpRecvBufAdd(u_int16_t id)
{
    int freeNo, oldestNo, intoNo;
    time_t oldestTime;

    freeNo = -1;
    oldestTime = ULONG_MAX;
    oldestNo = -1;
    for (int i = 0; i < IP_RECV_BUF_NO; i++)
    {
        if (IpRecvBuf[i].id == -1)
        {
            freeNo = i;
        }
        else
        {
            if (IpRecvBuf[i].id == id)
            {
                return i;
            }
            if (IpRecvBuf[i].timestamp < oldestTime)
            {
                oldestTime = IpRecvBuf[i].timestamp;
                oldestNo = i;
            }
        }
    }

    if (freeNo == -1)
    {
        intoNo = oldestNo;
    }
    else
    {
        intoNo = freeNo;
    }

    // 受信スレッドは１スレッドのみの仕様なのでlockは不要
    IpRecvBuf[intoNo].timestamp = time(NULL);
    IpRecvBuf[intoNo].id = id;
    IpRecvBuf[intoNo].len = 0;

    return intoNo;
}

int IpRecvBufDel(u_int16_t id)
{
    for (int i = 0; i < IP_RECV_BUF_NO; i++)
    {
        if (IpRecvBuf[i].id == id)
        {
            IpRecvBuf[i].id = -1;
            return 1;
        }
    }

    return 0;
}

int IpRecvBufSearch(u_int16_t id)
{
    for (int i = 0; IP_RECV_BUF_NO; i++)
    {
        if (IpRecvBuf[i].id == id)
        {
            return i;
        }
    }

    return -1;
}

int IpRecv(int soc, u_int8_t *raw, int raw_len, struct ether_header *eh, u_int8_t *data, int len)
{
    struct ip *ip;
    uint8_t option[1500];
    uint16_t sum;
    int optionLen, no, off, plen;
    uint8_t *ptr = data;

    if (len < (int)sizeof(struct ip))
    {
        printf("len(%d)<sizeof(struct ip)\n", len);
        return -1;
    }
    ip = (struct ip *)ptr;
    ptr += sizeof(struct ip);
    len -= sizeof(struct ip);

    optionLen = ip->ip_hl * 4 - sizeof(struct ip); // ip header lengthはヘッダ長/4が入っている。ここから必須ヘッダ長を除くとoption length(可変長)になる。
    if (optionLen > 0)
    {
        if (optionLen > 1500)
        {
            printf("IP optionLen(%d) too big\n", optionLen);
            return -1;
        }
        memcpy(option, ptr, optionLen);
        ptr += optionLen;
        len -= optionLen;
    }

    if (optionLen == 0)
    {
        sum = checksum((uint8_t *)ip, sizeof(struct ip));
    }
    else
    {
        sum = checksum2((uint8_t *)ip, sizeof(struct ip), option, optionLen);
    }
    if (sum != 0 && sum != 0xFFFF)
    {
        printf("bad ip chcksum\n");
        return -1;
    }

    plen = ntohs(ip->ip_len) - ip->ip_hl * 4; // packet length
    no = IpRecvBufAdd(ntohs(ip->ip_id));
    off = n(ntohs(ip->ip_off) & IP_OFFMASK) * 8; // offsetの8倍が実際のオフセットバイト数
    memcpy(IpRecvBuf[no].data + off, ptr, plen);
    if (!(ntohs(ip->ip_off) & IP_MF)) // IP_MF = more fragments flag。これがONならまだフラグメントされたデータが届く
    {
        // IP_MFがfalseであることを確認しているが、パケットが入れ替わっている場合にはデータが揃っているとは限らないが確認処理を省略している
        // 理由1: IPフラグメントはそもそもあまり使われない（TCPで通信する）
        // 理由2: 届いてないことがわかっても再送要求する仕組みがIPにはないので待つしかない
        IpRecvBuf[no].len = off + plen;
        if (ip->ip_p == IPPROTO_ICMP)
        {
            IcmpRecv(soc, raw, raw_len, eh, ip, IpRecvBuf[no].data, IpRecvBuf[no].len);
        }
        IpRecvBufDel(ntohs(ip->ip_id));
    }

    return 0;
}

int IpSendLink(int soc, u_int8_t smac[6], u_int8_t dmac[6], struct in_addr *saddr, struct in_addr *daddr, u_int8_t proto, int dontFlagment, int ttl, u_int8_t *data, int len)
{
    struct ip *ip;
    uint8_t *dptr, *ptr, sbuf[ETHERMTU];
    uint16_t id;
    int lest, sndLen, off, flagment;

    if (dontFlagment && len > Param.MTU - sizeof(struct ip))
    {
        printf("IpSend:data too long:%d\n", len);
        return -1;
    }

    id = random();

    dptr = data;
    lest = len;

    while (lest > 0)
    {
        if (lest > Param.MTU - sizeof(struct ip)) // MTU (基本1500byte) - ヘッダ 以上の残りバイト数があるなら
        {
            sndLen = (Param.MTU - sizeof(struct ip)) / 8 * 8; // lengthが8の倍数になるように調整 (余る部分は切り捨て)
            flagment = 1;
        }
        else
        {
            sndLen = lest;
            flagment = 0;
        }

        ptr = sbuf;
        ip = (struct ip *)ptr;
        memset(ip, 0, sizeof(struct ip));
        ip->ip_v = 4;
        ip->ip_hl = 5;                                  // header length (4byte単位なので20byte)
        ip->ip_len = htons(sizeof(struct ip) + sndLen); // length = header length + data length
        ip->ip_id = htons(id);
        off = (dptr - data) / 8; // 事実上は sndLen * N / 8 になっている。
        if (dontFlagment)
        {
            ip->ip_off = htons(IP_DF); // IP_DF = dont fragment flag
        }
        else if (flagment)
        {
            // IP_MF = IP_MF more fragments flag 0x2000
            // IP_OFFMASK = mask for fragmenting bits 0x1fff
            ip->ip_off = htons((IP_MF) | (off & IP_OFFMASK));
        }
        else
        {
            ip->ip_off = htons((0) | (off & IP_OFFMASK));
        }
        ip->ip_ttl = ttl;
        ip->ip_p = proto;
        ip->ip_src.s_addr = saddr->s_addr;
        ip->ip_dst.s_addr = daddr->s_addr;
        ip->ip_sum = 0;
        ip->ip_sum = checksum((uint8_t *)ip, sizeof(struct ip));
        ptr += sizeof(struct ip);

        memcpy(ptr, dptr, sndLen);
        ptr += sndLen;

        EtherSend(soc, smac, dmac, ETHERTYPE_IP, sbuf, ptr - sbuf); // len = ptr - sbuf (ptrはsbuf[0]から諸々書き込んだ終点をさすので引き算すればlenになる)
        print_ip(ip);
        dptr += sndLen;
        lest -= sndLen;
    }

    return 0;
}

int IpSend(int soc, struct in_addr *saddr, struct in_addr *daddr, u_int8_t proto, int dontFlagment, int ttl, u_int8_t *data, int len)
{
    uint8_t dmac[6];
    char buf1[80];
    int ret;

    // Arpでマックアドレスを取得
    if (GetTargetMac(soc, daddr, dmac, 0))
    {
        ret = IpSendLink(soc, Param.vmac, dmac, saddr, daddr, proto, dontFlagment, ttl, data, len);
    }
    else
    {
        printf("IpSend:%s Destination Host Unreachable\n", inet_ntop(AF_INET, daddr, buf1, sizeof(buf1)));
        ret = -1;
    }

    return ret;
}
