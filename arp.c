#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <pthread.h>

#include "param.h"

extern PARAM Param;

#define ARP_TABLE_NO (16)

typedef struct
{
    time_t timestamp;
    u_int8_t mac[6];
    struct in_addr ipaddr;
} ARP_TABLE; // IPアドレスからMACアドレスを引いたときの結果を保存するARPテーブル

ARP_TABLE ArpTable[ARP_TABLE_NO];

pthread_rwlock_t ArpTableLock = PTHREAD_RWLOCK_INITIALIZER;

extern u_int8_t AllZeroMac[6];
extern u_int8_t BcastMac[6];

char *my_arp_ip_ntoa_r(u_int8_t ip[4], char *buf)
{
    // arpヘッダのIPアドレスはin_addr_t(32bit数値)ではなく4個の8bit数値
    sprintf(buf, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    return buf;
}

void print_ether_arp(struct ether_arp *ether_arp)
{
    static char *hrd[] = {
        "From KA9Q: NET/ROM pseudo.",
        "Ethernet 10/100Mbps.",
        "Experimental Ethernet.",
        "AX.25 Level 2.",
        "PROnet token ring",
        "Chaosnet.",
        "IEEE 802.2 Ethernet/TR/TB."
        "ARCnet.",
        "APPLEtalk",
        "undefine",
        "undefine",
        "undefine",
        "undefine",
        "undefine",
        "undefine",
        "Frame Relay DLCI.",
        "undefine",
        "undefine",
        "undefine",
        "ATM."
        "undefine",
        "undefine",
        "undefine",
        "Metricom STRIP (new IANA id)."};

    static char *op[] = {
        "undefined",
        "ARP request.",
        "ARP reply.",
        "RARP request.",
        "RARP reply.",
        "undefined",
        "undefined",
        "undefined",
        "InARP request."
        "InARP reply."
        "(ATM)ARP NAK."};
    char buf1[80];

    printf("---ether_arp---\n");

    printf("arp_hrd=%u", ntohs(ether_arp->arp_hrd)); // arp_hrd = arp hardware address
    if (ntohs(ether_arp->arp_hrd) <= 23)
    {
        printf("(%s),", hrd[ntohs(ether_arp->arp_hrd)]);
    }
    else
    {
        printf("(undefine),");
    }
    printf("arp_pro=%u", ntohs(ether_arp->arp_pro)); // arp_pro = arp protocol address
    switch (ntohs(ether_arp->arp_pro))
    {
    case ETHERTYPE_PUP:
        printf("(Xerox PUP)\n");
        break;
    case ETHERTYPE_IP:
        printf("(IP)\n");
        break;
    case ETHERTYPE_ARP:
        printf("(Address resolution)\n");
        break;
    case ETHERTYPE_REVARP:
        print("(Reverse ARP)\n");
        break;
    default:
        printf("(unknown)\n");
        break;
    }
    printf("arp_hln=%u", ether_arp->arp_hln);      // arp_hln = arp hardware address length
    printf("arp_pln=%u", ether_arp->arp_pln);      // arp_pln = arp protocol address length
    printf("arp_op=%u", ntohs(ether_arp->arp_op)); // arp_op = ARP opcode (command)
    if (ntohs(ether_arp->arp_op) <= 10)
    {
        printf("(%s)\n", op[ntohs(ether_arp->arp_op)]);
    }
    else
    {
        printf("(undefined)\n");
    }
    printf("arp_sha=%s\n", my_ether_ntoa_r(ether_arp->arp_sha, buf1));  // arp_sha = arp sender hardware address
    printf("arp_spa=%s\n", my_arp_ip_ntoa_r(ether_arp->arp_spa, buf1)); // arp_spa = arp sender protocol address
    printf("arp_tha=%s\n", my_ether_ntoa_r(ether_arp->arp_tha, buf1));  // arp_tha = arp target hardware address
    printf("arp_tpa=%s\n", my_arp_ip_ntoa_r(ether_arp->arp_tpa, buf1)); // arp_tpa = arp target protocol address

    return;
}

int ArpAddTable(u_int8_t mac[6], struct in_addr *ipaddr)
{
    int freeNo, oldestNo, intoNo;
    time_t oldestTime;

    pthread_rwlock_wrlock(&ArpTableLock);

    freeNo = -1;
    oldestTime = ULONG_MAX;
    oldestNo = -1;
    for (int i = 0; i < ARP_TABLE_NO; i++)
    {
        if (memcmp(ArpTable[i].mac, AllZeroMac, 6) == 0)
        {
            if (freeNo == -1)
            {
                freeNo = i;
            }
        }
        else
        {
            if (ArpTable[i].ipaddr.s_addr == ipaddr->s_addr)
            {
                if (memcmp(ArpTable[i].mac, AllZeroMac, 6) != 0 && memcmp(ArpTable[i].mac, mac, 6) != 0)
                {
                    char buf1[80], buf2[80], buf3[80];
                    // inet_ntop: convert internet address to text format
                    printf("ArpAddTable:%s:receive different mac:(%s):(^s)\n", inet_ntop(AF_INET, ipaddr, buf1, sizeof(buf1)), my_ether_ntoa_r(ArpTable[i].mac, buf2), my_ether_ntoa_r(mac, buf3));
                }
                memcpy(ArpTable[i].mac, mac, 6);
                ArpTable[i].timestamp = time(NULL);
                pthred_rwlock_unlock(&ArpTableLock);
                return i;
            }
            if (ArpTable[i].timestamp < oldestTime)
            {
                oldestTime = ArpTable[i].timestamp;
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

    memcpy(ArpTable[intoNo].mac, mac, 6);
    ArpTable[intoNo].ipaddr.s_addr = ipaddr->s_addr;
    ArpTable[intoNo].timestamp = time(NULL);

    pthread_rwlock_unlock(&ArpTableLock);

    return intoNo;
}

int ArpDelTable(struct in_addr *ipaddr)
{
    pthread_rwlock_wrlock(&ArpTableLock);

    for (int i = 0; i < ARP_TABLE_NO; i++)
    {
        if (memcmp(ArpTable[i].mac, AllZeroMac, 6) != 0)
        {
            if (ArpTable[i].ipaddr.s_addr == ipaddr->s_addr)
            {
                memcpy(ArpTable[i].mac, AllZeroMac, 6);
                ArpTable[i].ipaddr.s_addr = 0;
                ArpTable[i].timestamp = 0;
                pthread_rwlock_unlock(&ArpTableLock);
                return 1;
            }
        }
    }

    pthread_rwlock_unlock(&ArpTableLock);
    return 0;
}

int ArpSearchTable(struct in_addr *ipaddr, u_int8_t mac[6])
{
    pthread_rwlock_rdlock(&ArpTableLock);

    for (int i = 0; i < ARP_TABLE_NO; i++)
    {
        if (memcmp(ArpTable[i].mac, AllZeroMac, 6) != 0)
        {
            if (ArpTable[i].ipaddr.s_addr == ipaddr->s_addr)
            {
                memcpy(mac, ArpTable[i].mac, 6);
                pthread_rwlock_unlock(&ArpTableLock);
                return 1;
            }
        }
    }

    pthread_rwlock_unlock(&ArpTableLock);
    return 0;
}

int ArpShowTable()
{
    char buf1[80], buf2[80];

    pthread_rwlock_rdlock(&ArpTableLock);

    for (int i = 0; i < ARP_TABLE_NO; i++)
    {
        if (memcmp(ArpTable[i].mac, AllZeroMac, 6) != 0)
        {
            printf("(%s) at %s\n", inet_ntop(AF_INET, &ArpTable[i].ipaddr, buf1, sizeof(buf1)), my_ether_ntoa_r(ArpTable[i].mac, buf2));
        }
    }

    pthread_rwlock_unlock(&ArpTableLock);
    return 0;
}

// 受信リクエストを受けたときに、そのスレッドでこの関数を呼ぶとブロックしてしまってArpReplyを処理できないので永遠にARPが解決できない問題がある
int GetTargetMac(int soc, struct in_addr *daddr, u_int8_t dmac[6], int gratuitous)
{
    int count;
    struct in_addr addr;

    if (isSameSubnet(daddr))
    {
        addr.s_addr = daddr->s_addr;
    }
    else
    {
        addr.s_addr = Param.gateway.s_addr;
    }

    count = 0;

    while (!ArpSearchTable(&addr, dmac))
    {
        if (gratuitous)
        {
            // 自分自身に設定するIPアドレスが重複していないかどうかを検出するためのリクエスト
            ArpSendRequestGratuitous(soc, &addr);
        }
        else
        {
            ArpSendRequest(soc, &addr);
        }
        DummyWait(DUMMY_WAIT_MS * (count + 1));
        count++;
        if (count > RETRY_COUNT)
        {
            return 0;
        }
    }
    return 1;
}

int ArpSend(int soc, u_int16_t op, u_int8_t e_smac[6], u_int8_t e_dmac[6], u_int8_t smac[6], u_int8_t dmac[6], u_int8_t saddr[4], u_int8_t daddr[4])
{
    struct ether_arp arp;

    memset(&arp, 0, sizeof(struct ether_arp));
    arp.arp_hrd = htons(ARPHRD_ETHER); // ARP protocol HARDWARE identifiers, Ethernet 10/100Mbps.
    arp.arp_pro = htons(ETHERTYPE_IP);
    arp.arp_hln = 6;
    arp.arp_pln = 4;
    arp.arp_op = htons(op);

    memcpy(arp.arp_sha, smac, 6);
    memcpy(arp.arp_tha, dmac, 6);
    memcpy(arp.arp_spa, saddr, 4);
    memcpy(arp.arp_tpa, daddr, 4);

    printf("=== ARP ===[\n]");
    EtherSend(soc, e_smac, e_dmac, ETHERTYPE_ARP, (uint8_t *)&arp, sizeof(struct ether_arp));
    print_ether_arp(&arp);
    printf("]\n");

    return 0;
}

int ArpSendRequestGratuitous(int soc, struct in_addr *targetIp)
{
    union
    {
        u_int32_t l;
        uint8_t c[4];
    } saddr, daddr;

    saddr.l = 0; // ソースIPアドレスは０にして受信した相手のARPテーブルに影響を与えないようにする。
    daddr.l = targetIp->s_addr;
    ArpSend(soc, ARPOP_REQUEST, Param.vmac, BcastMac, Param.vmac, AllZeroMac, saddr.c, daddr.c);

    return 0;
}

int ArpSendRequest(int soc, struct in_addr *targetIp)
{
    union
    {
        uint32_t l;
        uint8_t c[4];
    } saddr, daddr;

    saddr.l = Param.vip.s_addr;
    daddr.l = targetIp->s_addr;
    ArpSend(soc, ARPOP_REQUEST, Param.vmac, BcastMac, Param.vmac, AllZeroMac, saddr.c, daddr.c);

    return 0;
}

int ArpCheckGArp(int soc)
{
    uint8_t dmac[6];
    char buf1[80], buf2[80];

    if (GetTargetMac(soc, &Param.vip, dmac, 1)) // gratuitousフラグ=1
    {
        printf("ArpCheckGArp:%s use %s\n", inet_ntop(AF_INET, &Param.vip, buf1, sizeof(buf1)), my_ether_ntoa_r(dmac, buf2));
        return 0;
    }

    return 1;
}

int ArpRecv(int soc, struct ether_header *eh, u_int8_t *data, int len)
{
    struct ether_arp *arp;
    uint8_t *ptr = data;

    // ARPヘッダがarpに入る
    arp = (struct ether_arp *)ptr;
    ptr += sizeof(struct ether_arp);
    len -= sizeof(struct ether_arp);

    if (ntohs(arp->arp_op) == ARPOP_REQUEST) // 他所からのARPリクエスト
    {
        struct in_addr addr;
        addr.s_addr = (arp->arp_tpa[3] << 24) | (arp->arp_tpa[2] << 16) | (arp->arp_tpa[1] << 8) | (arp->arp_tpa[0]);
        if (isTargetIPAddr(&addr))
        {
            printf("--- recv ---[\n");
            print_ether_header(eh);
            print_ether_arp(arp);
            printf(")\n");

            addr.s_addr=(arp->arp_spa[3]<<24)|(arp->arp_spa[2]<<16)|(arp->arp_spa[1]<<8)|(arp->arp_spa[0]);
            ArpAddTable(arp->arp_sha,&addr);
            ArpSend(soc, ARPOP_REPLY, Param.vmac, eh->ether_shost, Param.vmac, arp->arp_sha, arp->arp_tpa, arp->arp_spa);
        }
    }
    if (ntohs(arp->arp_op) == ARPOP_REPLY)
    {
        struct in_addr addr;
        addr.s_addr = (arp->arp_tpa[3] << 24) | (arp->arp_tpa[2] << 16) | (arp->arp_tpa[1] << 8) | (arp->arp_tpa[0]);
        if (addr.s_addr == 0 || isTargetIPAddr(&addr))
        {
            printf("--- recv ---[\n");
            print_ether_header(eh);
            print_ether_arp(arp);
            printf("]\n");
            addr.s_addr = (arp->arp_spa[3] << 24) | (arp->arp_spa[2] << 16) | (arp->arp_spa[1] << 8) | (arp->arp_spa[0]);
            ArpAddTable(arp->arp_sha, &addr);
        }
    }

    return 0;
}
