#include <stdio.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>

#include "param.h"
#include "sock.h"
#include "tcp.h"

extern PARAM Param;

struct pseudo_ip
{
    struct in_addr ip_src;
    struct in_addr ip_dst;
    u_int8_t dummy;
    u_int8_t ip_p;
    u_int16_t ip_len;
};

#define TCP_TABLE_NO (16)

typedef struct
{
    u_int16_t myPort, dstPort;
    struct in_addr dstAddr;
    struct
    {
        u_int32_t una; // 未確認の送信 (unacknowledged segmentの略かな？)
        u_int32_t nxt; // 次の送信
        u_int32_t wnd; // 送信ウィンドウ
        u_int32_t iss; // 初期送信シーケンス番号
    } snd;
    struct
    {
        u_int32_t nxt; // 次の受信
        u_int32_t wnd; // 受信ウィンドウ
        u_int32_t irs; // 初期送信シーケンス番号
    } rcv;
    int status;
} TCP_TABLE; // TCB相当の構造体 (Transmission Control Block)

TCP_TABLE TcpTable[TCP_TABLE_NO];

enum
{
    // see https://support.eforce.co.jp/viewtopic.php?t=354
    TCP_ESTABLISHED = 1, // TCPハンドシェークが成立し、TCP接続済の状態
    TCP_SYN_SENT,        // TCPクライアントとして、SYN要求を送ってTCPサーバからの応答を待っている状態
    TCP_SYN_RECV,        // TCPサーバとしてSYN要求を受信し、SYN/ACKを送信してTCPクライアントからのACKを待っている状態
    TCP_FIN_WAIT1,       // ESTABLISHED状態の時、FINを送信して、対向からのFINまたはACKを待っている状態
    TCP_FIN_WAIT2,       // FIN-WAIT1状態の時、送信したFINに対するACKを受信した状態
    TCP_TIME_WAIT,       // FIN-WAIT2からの遷移の場合、FIN受信のACKを送信した状態。CLOSINGからの遷移の場合、送信FINのACKを受信した状態
    TCP_CLOSE,           // TCP接続無しの状態
    TCP_CLOSE_WAIT,      // ESTABLISHED状態の時、対向からのFINを受信した状態
    TCP_LAST_ACK,        // CLOSE-WAIT状態の時、FINを送信して、ACKを待っている状態
    TCP_LISTEN,          // TCPサーバとしてSYN要求を待っている状態
    TCP_CLOSING          // FIN-WAIT1状態の時、FINを受信後そのFINに対するACKを送信した状態
};

pthread_rwlock_t TcpTableLock = PTHREAD_RWLOCK_INITIALIZER;

int print_tcp(struct tcphdr *tcp)
{
    printf("tcp-----------------------------------------------------------------------------\n");
    printf("source=%u,", ntohs(tcp->source));
    printf("dest=%u,", ntohs(tcp->dest));
    printf("seq=%u,", ntohl(tcp->seq));
    printf("ack_seq=%u,", ntohl(tcp->ack_seq));
    printf("doff=%u,", tcp->doff);
    printf("urg=%u,", tcp->urg);
    printf("ack=%u,", tcp->ack);
    printf("psh=%u,", tcp->psh);
    printf("rst=%u,", tcp->rst);
    printf("syn=%u,", tcp->syn);
    printf("fin=%u,", tcp->fin);
    printf("window=%u,", ntohs(tcp->window));
    printf("check=%04x,", ntohs(tcp->check));
    printf("urg_ptr=%u\n", ntohs(tcp->urg_ptr));

    return 0;
}

int print_tcp_optpad(unsigned char *data, int size)
{
    printf("option,pad(%d)=", size);
    for (int i = 0; i < size; i++)
    {
        if (i != 0)
        {
            printf(",");
        }
        printf("%02x", *data);
        data++;
    }
    printf("\n");

    return 0;
}

char *TcpStatusStr(int status)
{
    switch (status)
    {
    case TCP_ESTABLISHED:
        return ("ESTABLISHED");
    case TCP_SYN_SENT:
        return ("SYN_SENT");
    case TCP_SYN_RECV:
        return ("SYN_RECV");
    case TCP_FIN_WAIT1:
        return ("FIN_WAIT1");
    case TCP_FIN_WAIT2:
        return ("FIN_WAIT2");
    case TCP_TIME_WAIT:
        return ("TIME_WAIT");
    case TCP_CLOSE:
        return ("CLOSE");
    case TCP_CLOSE_WAIT:
        return ("CLOSE_WAIT");
    case TCP_LAST_ACK:
        return ("LAST_ACK");
    case TCP_LISTEN:
        return ("LISTEN");
    case TCP_CLOSING:
        return ("CLOSING");
    default:
        return ("undefine");
    }
}

u_int16_t TcpChecksum(struct in_addr *saddr, struct in_addr *daddr, u_int8_t proto, u_int8_t *data, int len)
{
    struct pseudo_ip p_ip;
    u_int16_t sum;

    memset(&p_ip, 0, sizeof(struct pseudo_ip));
    p_ip.ip_src.s_addr = saddr->s_addr;
    p_ip.ip_dst.s_addr = daddr->s_addr;
    p_ip.ip_p = proto;
    p_ip.ip_len = htons(len);

    sum = checksum2((u_int8_t *)&p_ip, sizeof(struct pseudo_ip), data, len);
    return sum;
}

int TcpAddTable(u_int16_t port)
{
    int freeNo;

    pthread_rwlock_wrlock(&TcpTableLock);

    freeNo = -1;
    for (int i = 0; i < TCP_TABLE_NO; i++)
    {
        if (TcpTable[i].myPort == port)
        {
            printf("TcpAddTable:port %d:alredy exist\n", port);
            pthread_rwlock_unlock(&TcpTableLock);
        }
        else if (TcpTable[i].myPort == 0)
        {
            if (freeNo == -1)
            {
                freeNo = i;
            }
        }
    }
    if (freeNo == -1)
    {
        printf("TcpAddTable:no free table\n");
        pthread_rwlock_unlock(&TcpTableLock);
        return -1;
    }

    memset(&TcpTable[freeNo], 0, sizeof(TCP_TABLE));
    TcpTable[freeNo].myPort = port;
    TcpTable[freeNo].snd.iss = TcpTable[freeNo].snd.una = TcpTable[freeNo].snd.nxt = random();
    TcpTable[freeNo].rcv.irs = TcpTable[freeNo].rcv.nxt = 0;
    TcpTable[freeNo].snd.wnd = TCP_INIT_WINDOW;
    TcpTable[freeNo].status = TCP_CLOSE;

    pthread_rwlock_unlock(&TcpTableLock);

    return freeNo;
}

int TcpSearchTable(u_int16_t port)
{
    pthread_rwlock_rdlock(&TcpTableLock);

    for (int i = 0; i < TCP_TABLE_NO; i++)
    {
        if (TcpTable[i].myPort == port)
        {
            pthread_rwlock_unlock(&TcpTableLock);
            return i;
        }
    }
    pthread_rwlock_unlock(&TcpTableLock);

    return -1;
}

int TcpShowTable()
{
    char buf1[80], buf2[80];

    pthread_rwlock_rdlock(&TcpTableLock);

    for (int i = 0; TCP_TABLE_NO; i++)
    {
        if (TcpTable[i].myPort != 0)
        {
            if (TcpTable[i].status == TCP_ESTABLISHED)
            {
                printf("TCP:%d:%u=%s:%u-%s:%u:%s\n", i, TcpTable[i].myPort,
                       inet_ntop(AF_INET, &Param.vip, buf1, sizeof(buf1)),
                       TcpTable[i].myPort,
                       inet_ntop(AF_INET6, &TcpTable[i].dstAddr, buf2, sizeof(buf2)),
                       TcpTable[i].dstPort,
                       TcpStatusStr(TcpTable[i].status));
            }
            else
            {
                printf("TCP:%d:%u=%s:%u:%s\n", i, TcpTable[i].myPort,
                       inet_ntop(AF_INET, &Param.vip, buf1, sizeof(buf1)),
                       TcpTable[i].myPort,
                       TcpStatusStr(TcpTable[i].status));
            }
        }
    }

    pthread_rwlock_unlock(&TcpTableLock);

    return 0;
}

u_int16_t TcpSearchFreePort()
{
    u_int16_t i;

    for (int i = 32768; i < 61000; i++)
    {
        if (TcpSearchTable(i) == -1)
        {
            return i;
        }
    }

    return 0;
}

int TcpSocketListen(u_int16_t port)
{
    int no;

    if (port == 0)
    {
        if ((port = TcpSearchFreePort()) == 0)
        {
            printf("TcpSocket:no free port\n");
            return -1;
        }
    }
    no = TcpAddTable(port);
    if (no == -1)
    {
        return -1;
    }
    TcpTable[no].status = TCP_LISTEN;

    return no;
}

int TcpSocketClose(u_int16_t port)
{
    int no;

    no = TcpSearchTable(port);
    if (no == -1)
    {
        printf("TcpSocketClose:%u:not exists\n", port);
        return -1;
    }
    pthread_rwlock_wrlock(&TcpTableLock);
    TcpTable[no].myPort == 0;
    pthread_rwlock_unlock(&TcpTableLock);

    return 0;
}

int TcpSendSyn(int soc, int no, int ackFlag)
{
    u_int8_t *ptr;
    u_int8_t sbuf[DEFAULT_MTU - sizeof(struct ip)];
    struct tcphdr *tcp;

    
}

int TcpSendFin(int soc, int no);

int TcpSendRst(int soc, int no);

int TcpSendAck(int soc, int no);

int TcpSendRstDirect(int soc, struct ether_header *r_eh, struct ip *r_ip, struct tcphdr *r_tcp);

int TcpConnect(int soc, u_int16_t sport, struct in_addr *daddr, u_int16_t dport);

int TcpClose(int soc, u_int16_t sport);

int TcpReset(int soc, u_int16_t sport);

int TcpAllSocketClose(int soc);

int TcpSendData(int soc, u_int16_t sport, u_int8_t *data, int len);

int TcpSend(int soc, u_int16_t sport, u_int8_t *data, int len);

int TcpRecv(int soc, struct ether_header *eh, struct ip *ip, u_int8_t *data, int len);
