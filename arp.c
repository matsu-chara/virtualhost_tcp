#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
// #include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <pthread.h>

#include "param.h"
#include "ether.c"

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

    printf("arp_hrd=%u, ntohs(ether_arp->arp_hrd)");
    if (ntohs(ether_arp->arp_hrd) <= 23)
    {
        printf("(%s),", hrd[ntohs(ether_arp->arp_hrd)]);
    }
    else
    {
        printf("(undefined),");
    }
    printf("arp_pro=%u", ntohs(ether_arp->arp_pro));
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
    printf("arp_hln=%u", ether_arp->arp_hln);
    printf("arp_pln=%u", ether_arp->arp_pln);
    printf("arp_op=%u", ntohs(ether_arp->arp_op));
    if (ntohs(ether_arp->arp_op) <= 10)
    {
        printf("(%s)\n", op]ntohs(ether_arp->arp_op)]);
    }
    else
    {
        printf("(undefined)\n");
    }
    printf("arp_sha=%s\n", my_ether_ntoa_r(ether_arp->arp_sha, buf1));
    printf("arp_spa=%s\n", my_arp_ip_ntoa_r(ether_arp->arp_spa, buf1));
    printf("arp_taa=%s\n", my_ether_ntoa_r(ether_arp->arp_tha, buf1));
    printf("arp_tpa=%s\n", my_arp_ip_ntoa_r(ether_arp->arp_tpa, buf1));

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

int ArpDelTable(struct in_addr *ipaddr);
int ArpSearchTable(struct in_addr *ipaddr, u_int8_t mac[6]);
int ArpShowTable();
int GetTargetMac(int soc, struct in_addr *daddr, u_int8_t dmac[6], int gratuitous);
int ArpSend(int soc, u_int16_t op, u_int8_t e_smac[6], u_int8_t e_dmac[6], u_int8_t smac[6], u_int8_t dmac[6], u_int8_t saddr[4], u_int8_t daddr[4]);
// int ArpSendRequestGratuitous(int soc, struct in_addr *targetIp);
// int ArpSendRequest(int soc, struct in_addr *targetIp);
// int ArpCheckGArp(int soc);
// int ArpRecv(int soc, struct ether_header *eh, u_int8_t *data, int len);
