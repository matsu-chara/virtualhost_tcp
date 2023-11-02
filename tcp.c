#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "param.h"
#include "sock.h"
#include "ether.h"
#include "ip.h"
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
        u_int32_t irs; // 初期受信シーケンス番号
    } rcv;
    int status;
} TCP_TABLE; // TCB相当の構造体 (Transmission Control Block)

TCP_TABLE TcpTable[TCP_TABLE_NO];

// see https://support.eforce.co.jp/viewtopic.php?t=354
// enum
// {
// TCP_ESTABLISHED = 1, // TCPハンドシェークが成立し、TCP接続済の状態
// TCP_SYN_SENT,        // TCPクライアントとして、SYN要求を送ってTCPサーバからの応答を待っている状態
// TCP_SYN_RECV,        // TCPサーバとしてSYN要求を受信し、SYN/ACKを送信してTCPクライアントからのACKを待っている状態
// TCP_FIN_WAIT1,       // ESTABLISHED状態の時、FINを送信して、対向からのFINまたはACKを待っている状態
// TCP_FIN_WAIT2,       // FIN-WAIT1状態の時、送信したFINに対するACKを受信した状態
// TCP_TIME_WAIT,       // FIN-WAIT2からの遷移の場合、FIN受信のACKを送信した状態。CLOSINGからの遷移の場合、送信FINのACKを受信した状態
// TCP_CLOSE,           // TCP接続無しの状態
// TCP_CLOSE_WAIT,      // ESTABLISHED状態の時、対向からのFINを受信した状態
// TCP_LAST_ACK,        // CLOSE-WAIT状態の時、FINを送信して、ACKを待っている状態
// TCP_LISTEN,          // TCPサーバとしてSYN要求を待っている状態
// TCP_CLOSING          // FIN-WAIT1状態の時、FINを受信後そのFINに対するACKを送信した状態
// };

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

    for (int i = 0; i < TCP_TABLE_NO; i++)
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
    for (u_int16_t i = 32768; i < 61000; i++)
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
    TcpTable[no].myPort = 0;
    pthread_rwlock_unlock(&TcpTableLock);

    return 0;
}

// synを送る。 ackFlag引数によってsyn/ackも送れる
int TcpSendSyn(int soc, int no, int ackFlag)
{
    u_int8_t *ptr;
    u_int8_t sbuf[DEFAULT_MTU - sizeof(struct ip)];
    struct tcphdr *tcp;

    ptr = sbuf;
    tcp = (struct tcphdr *)ptr;
    memset(tcp, 0, sizeof(struct tcphdr));

    // 以下headerの設定
    // see https://milestone-of-se.nesuke.com/nw-basic/tcp-udp/tcp-format/

    /* シーケンス番号
     * シーケンス番号はクライアント側サーバー側で別々の値になり、互いにrandomに初期値を決める。
     * 値の初期化はクライアントがsyn送信時、サーバーがsyn/ack送信時に行われる。
     *
     * それ以降は シーケンス番号 = 初期値 + 相手に送信したデータの byte 数 となる。
     * ただし、3way ハンドシェイクのパケットについては（データ部が0byteではあるが）例外的に1byteとしてカウントする
     *
     * ack_seqはTCP syn送信時は0
     * それ以降は 応答シーケンス番号 = 前回の相手のシーケンス番号 + 相手から受信したデータの byte 数 となる。
     * ただし、3way ハンドシェイクのパケットについては（データ部が0byteではあるが）例外的に1byteとしてカウントする
     */
    tcp->seq = htonl(TcpTable[no].snd.una);     // シーケンス番号 32bit
    tcp->ack_seq = htonl(TcpTable[no].rcv.nxt); // 受信シーケンス番号 32bit

    tcp->source = htons(TcpTable[no].myPort); // 16bit = 2byte = 65535まで。送信元がクライアントの場合1024以上のhigher portがよく使われる
    tcp->dest = htons(TcpTable[no].dstPort);  // 宛先ポート
    tcp->doff = 5;                            // data offset。TCP ヘッダの長さ (4Bytes単位) が入る。

    // フラグ情報(6個) URG,ACK,PSH,RST,SYN,FIN
    tcp->urg = 0; // 立ってると緊急を意味する。制御はアプリケーションが決めるためTCPでは何もしない
    tcp->ack = ackFlag;
    tcp->psh = 0; // 立ってると、受信側で直ちにアプリケーションにデータを渡せという意味になる。制御はアプリケーションが行うためTCPとしては特に何もしない。(terminalソフトなどで１文字ずつデータを送る場合、バッファせずにレンダリングしてほしい場合にpshフラグを利用するらしい)
    tcp->rst = 0; // 直ちにtcpを切断する。(synを受信したがポートが利用中の場合や接続シーケンスが不正になった場合に利用する。)
    tcp->syn = 1;
    tcp->fin = 0;

    tcp->window = htons(TcpTable[no].snd.wnd); // windowサイズ（ackを待たずに送れるデータサイズ） 受信側が受け入れ可能なデータのバイト数を送信側に知らせるもの。(ackフラグがセットされたときに、このフィールドも埋めるのが良い)
    tcp->check = htons(0);                     // checksum（後で代入）
    tcp->urg_ptr = htons(0);                   // urgフラグがONの場合に緊急データの位置を示す(実際にはsequence番号 + 緊急データのバイト数での位置が入る)

    ptr += sizeof(struct tcphdr);

    tcp->check = TcpChecksum(&Param.vip, &TcpTable[no].dstAddr, IPPROTO_TCP, (u_int8_t *)sbuf, ptr - sbuf);

    printf("=== TCP ===[\n");
    IpSend(soc, &Param.vip, &TcpTable[no].dstAddr, IPPROTO_TCP, 1, Param.IpTTL, sbuf, ptr - sbuf);
    print_tcp(tcp);
    printf("]\n");

    TcpTable[no].snd.nxt = TcpTable[no].snd.una;

    return 0;
}

int TcpSendFin(int soc, int no)
{
    u_int8_t *ptr;
    u_int8_t sbuf[DEFAULT_MTU - sizeof(struct ip)];
    struct tcphdr *tcp;

    ptr = sbuf;
    tcp = (struct tcphdr *)ptr;
    memset(tcp, 0, sizeof(struct tcphdr));

    tcp->seq = htonl(TcpTable[no].snd.una);
    tcp->ack_seq = htonl(TcpTable[no].rcv.nxt);

    tcp->source = htons(TcpTable[no].myPort);
    tcp->dest = htons(TcpTable[no].dstPort);
    tcp->doff = 5;

    tcp->urg = 0;
    tcp->ack = 1;
    tcp->psh = 0;
    tcp->rst = 0;
    tcp->syn = 0;
    tcp->fin = 1;

    tcp->window = htons(TcpTable[no].snd.wnd);
    tcp->check = htons(0);
    tcp->urg_ptr = htons(0);

    ptr += sizeof(struct tcphdr);

    tcp->check = TcpChecksum(&Param.vip, &TcpTable[no].dstAddr, IPPROTO_TCP, (u_int8_t *)sbuf, ptr - sbuf);

    printf("=== TCP ===[\n");
    IpSend(soc, &Param.vip, &TcpTable[no].dstAddr, IPPROTO_TCP, 1, Param.IpTTL, sbuf, ptr - sbuf);
    print_tcp(tcp);
    printf("]\n");

    TcpTable[no].snd.nxt = TcpTable[no].snd.una;

    return 0;
}

int TcpSendRst(int soc, int no)
{
    u_int8_t *ptr;
    u_int8_t sbuf[DEFAULT_MTU - sizeof(struct ip)];
    struct tcphdr *tcp;

    ptr = sbuf;
    tcp = (struct tcphdr *)ptr;
    memset(tcp, 0, sizeof(struct tcphdr));

    tcp->seq = htonl(TcpTable[no].snd.una);
    tcp->ack_seq = htonl(TcpTable[no].rcv.nxt);

    tcp->source = htons(TcpTable[no].myPort);
    tcp->dest = htons(TcpTable[no].dstPort);
    tcp->doff = 5;

    tcp->urg = 0;
    tcp->ack = 1;
    tcp->psh = 0;
    tcp->rst = 1;
    tcp->syn = 0;
    tcp->fin = 0;

    tcp->window = htons(TcpTable[no].snd.wnd);
    tcp->check = htons(0);
    tcp->urg_ptr = htons(0);

    ptr += sizeof(struct tcphdr);

    tcp->check = TcpChecksum(&Param.vip, &TcpTable[no].dstAddr, IPPROTO_TCP, (u_int8_t *)sbuf, ptr - sbuf);

    printf("=== TCP ===[\n");
    IpSend(soc, &Param.vip, &TcpTable[no].dstAddr, IPPROTO_TCP, 1, Param.IpTTL, sbuf, ptr - sbuf);
    print_tcp(tcp);
    printf("]\n");

    TcpTable[no].snd.nxt = TcpTable[no].snd.una;

    return 0;
}

int TcpSendAck(int soc, int no)
{
    // ack応答は毎回やるのではなく最後に受信したseq_numに対して行う。送信側はそれまでに送信したすべてのセグメントに対してackが来たものとみなす。
    // 欠損がある場合は、欠損直前までのseq_numについてackを返して、それ以降のデータをすべて再送してもらう。
    // ただしTCP optionでSACK (selective ack)に対応している場合は受信したseq_numを(先頭~欠損の末尾, 欠損の次~次の欠損の末尾, ...)のように列挙してackすることができる。（対応しているかどうかは3way handshake時に対応オプションを通知しあう）

    u_int8_t *ptr;
    u_int8_t sbuf[sizeof(struct ether_header) + DEFAULT_MTU];
    struct tcphdr *tcp;

    ptr = sbuf;
    tcp = (struct tcphdr *)ptr;
    memset(tcp, 0, sizeof(struct tcphdr));

    tcp->seq = htonl(TcpTable[no].snd.una);
    tcp->ack_seq = htonl(TcpTable[no].rcv.nxt);

    tcp->source = htons(TcpTable[no].myPort);
    tcp->dest = htons(TcpTable[no].dstPort);
    tcp->doff = 5;

    tcp->urg = 0;
    tcp->ack = 1;
    tcp->psh = 0;
    tcp->rst = 0;
    tcp->syn = 0;
    tcp->fin = 0;

    tcp->window = htons(TcpTable[no].snd.wnd);
    tcp->check = htons(0);
    tcp->urg_ptr = htons(0);

    ptr += sizeof(struct tcphdr);

    tcp->check = TcpChecksum(&Param.vip, &TcpTable[no].dstAddr, IPPROTO_TCP, (u_int8_t *)sbuf, ptr - sbuf);

    printf("=== TCP ===[\n");
    IpSend(soc, &Param.vip, &TcpTable[no].dstAddr, IPPROTO_TCP, 1, Param.IpTTL, sbuf, ptr - sbuf);
    print_tcp(tcp);
    printf("]\n");

    TcpTable[no].snd.nxt = TcpTable[no].snd.una;

    return 0;
}

// 受信対象ではないポートからTCPパケットが届いた場合に送るRSTパケット
int TcpSendRstDirect(int soc, struct ether_header *r_eh, struct ip *r_ip, struct tcphdr *r_tcp)
{
    u_int8_t *ptr;
    u_int8_t sbuf[sizeof(struct ether_header) + DEFAULT_MTU];
    struct tcphdr *tcp;

    ptr = sbuf;
    tcp = (struct tcphdr *)ptr;
    memset(tcp, 0, sizeof(struct tcphdr));

    tcp->seq = r_tcp->ack_seq;
    tcp->ack_seq = htonl((r_tcp->seq) + 1);

    tcp->source = r_tcp->dest;
    tcp->dest = r_tcp->source;
    tcp->doff = 5;

    tcp->urg = 0;
    tcp->ack = 1;
    tcp->psh = 0;
    tcp->rst = 1;
    tcp->syn = 0;
    tcp->fin = 0;

    tcp->window = 0;
    tcp->check = htons(0);
    tcp->urg_ptr = htons(0);

    ptr += sizeof(struct tcphdr);

    tcp->check = TcpChecksum(&Param.vip, &r_ip->ip_src, IPPROTO_TCP, (u_int8_t *)sbuf, ptr - sbuf);

    printf("=== TCP ===[\n");
    IpSend(soc, &Param.vip, &r_ip->ip_src, IPPROTO_TCP, 1, Param.IpTTL, sbuf, ptr - sbuf);
    print_tcp(tcp);
    printf("]\n");

    return 0;
}

int TcpConnect(int soc, u_int16_t sport, struct in_addr *daddr, u_int16_t dport)
{
    int count, no;

    if ((no = TcpAddTable(sport)) == -1)
    {
        return -1;
    }

    TcpTable[no].dstPort = dport;
    TcpTable[no].dstAddr.s_addr = daddr->s_addr;
    TcpTable[no].status = TCP_SYN_SENT;
    count = 0;
    do
    {
        TcpSendSyn(soc, no, 0);
        DummyWait(DUMMY_WAIT_MS * (count + 1));
        printf("TcpConnect:%s\n", TcpStatusStr(TcpTable[no].status));
        count++;
        if (count > RETRY_COUNT)
        {
            printf("TcpConnect:retry over\n");
            TcpSocketClose(sport);
            return 0;
        }
    } while (TcpTable[no].status != TCP_ESTABLISHED);

    printf("TcpConnect:success\n");

    return 1;
}

int TcpClose(int soc, u_int16_t sport)
{
    int count, no;
    time_t now_t;

    if ((no = TcpAddTable(sport)) == -1)
    {
        return -1;
    }

    if (TcpTable[no].status == TCP_ESTABLISHED)
    {
        TcpTable[no].status = TCP_FIN_WAIT1;
        count = 0;
        do
        {
            TcpSendFin(soc, no); // FINを送る
            DummyWait(DUMMY_WAIT_MS * (count + 1));
            printf("TcpClose:%s\n", TcpStatusStr(TcpTable[no].status));
            count++;
            if (count > RETRY_COUNT)
            {
                printf("TcpClose:retry over\n");
                TcpSocketClose(sport);
                return 0;
            }

            // 次のどちらかになるのを待つ
            // - TCP_FIN_WAIT2 (fin/ack受信, fin受信待ち)
            // - TCP_CLOSING (fin受信, fin/ack受信待ち)
            // （いきなり RST パケットを送られて TCP_CLOSE になることもある）
        } while (TcpTable[no].status == TCP_FIN_WAIT1);
    }

    count = 0;

    // 次のどちらかかを待つ
    // - TCP_FIN_WAIT2 =>  fin受信待ち
    // - TCP_CLOSING => fin/ack受信待ち
    // どちらもメッセージ受信時には TCP_TIME_WAIT に移行する。
    // いきなり RST パケットを送られて TCP_CLOSE になることもあるので TCP_CLOSE でないことも確認する
    while (TcpTable[no].status != TCP_TIME_WAIT && TcpTable[no].status != TCP_CLOSE)
    {
        DummyWait(DUMMY_WAIT_MS * (count + 1));
        printf("TcpClose:%s\n", TcpStatusStr(TcpTable[no].status));
        count++;
        if (count > RETRY_COUNT)
        {
            printf("TcpClose:retry over\n");
            TcpSocketClose(sport);
            return 0;
        }
    }

    // TCP_TIME_WAIT から TCP_CLOSE に移行するのを一定時間待つ
    // いきなり RST パケットを送られて TCP_CLOSE になることもあるので TCP_CLOSE でないことを確認する
    if (TcpTable[no].status != TCP_CLOSE)
    {
        now_t = time(NULL);
        while (time(NULL) - now_t < TCP_FIN_TIMEOUT)
        {
            printf("TcpClose:status=%s", TcpStatusStr(TcpTable[no].status));
            sleep(1);
        }
        // 一定時間経過したのでcloseする。
        TcpTable[no].status = TCP_CLOSE;
    }

    printf("TcpClose:status=%s:success\n", TcpStatusStr(TcpTable[no].status));
    if (TcpTable[no].myPort != 0)
    {
        TcpSocketClose(sport);
    }

    return 1;
}

int TcpReset(int soc, u_int16_t sport)
{
    int no;

    if ((no = TcpSearchTable(sport)) == -1)
    {
        return -1;
    }

    TcpSendRst(soc, no);
    TcpSocketClose(sport);

    return 1;
}

int TcpAllSocketClose(int soc)
{
    for (int i = 0; i < TCP_TABLE_NO; i++)
    {
        if (TcpTable[i].myPort != 0 && TcpTable[i].status == TCP_ESTABLISHED)
        {
            TcpClose(soc, TcpTable[i].myPort);
        }
    }

    return 0;
}

int TcpSendData(int soc, u_int16_t sport, u_int8_t *data, int len)
{
    u_int8_t *ptr;
    u_int8_t sbuf[DEFAULT_MTU - sizeof(struct ip)];
    int no;
    struct tcphdr *tcp;

    if ((no = TcpSearchTable(sport)) == -1)
    {
        return -1;
    }

    if (TcpTable[no].status != TCP_ESTABLISHED)
    {
        printf("TcpSend:not established\n");
        return -1;
    }

    ptr = sbuf;
    tcp = (struct tcphdr *)ptr;
    memset(tcp, 0, sizeof(struct tcphdr));
    tcp->seq = htonl(TcpTable[no].snd.una);
    tcp->ack_seq = htonl(TcpTable[no].rcv.nxt); // ピギーバックするため rcv.nxt を詰める。（次二相手が送ってくるメッセージの seq が rcv.nxt になる
    tcp->source = htons(TcpTable[no].myPort);
    tcp->dest = htons(TcpTable[no].dstPort);
    tcp->doff = 5;
    tcp->urg = 0;
    // 常にピギーバックしている (dataと同時に前回の受信セグメントに対するack応答を実施している)
    // ただし、 recv 処理で常に ack を返している（遅延確認応答するようになってない）ので、意味はそんなにないかもしれない
    // 遅延確認応答する場合は、セグメント受信時に前回の受信セグメントに対して ack を返信済みか？を判定して返信済みだったら ack を保留するような処理を入れれば良い
    // 本実装では  ack 応答を返すと snd.nxt = snd.una になるので、それを判定すれば良さそう。
    tcp->ack = 1;
    tcp->psh = 0;
    tcp->rst = 0;
    tcp->syn = 0;
    tcp->fin = 0;
    tcp->window = htons(TcpTable[no].snd.wnd);
    tcp->check = htons(0);
    tcp->urg_ptr = htons(0);

    ptr += sizeof(struct tcphdr);

    memcpy(ptr, data, len);
    ptr += len;

    tcp->check = TcpChecksum(&Param.vip, &TcpTable[no].dstAddr, IPPROTO_TCP, (u_int8_t *)sbuf, ptr - sbuf);

    printf("=== TCP ===[\n");
    IpSend(soc, &Param.vip, &TcpTable[no].dstAddr, IPPROTO_TCP, 0, Param.IpTTL, sbuf, ptr - sbuf);
    print_tcp(tcp);
    print_hex(data, len);
    printf("]\n");

    TcpTable[no].snd.nxt = TcpTable[no].snd.una + len;

    return 0;
}

int TcpSend(int soc, u_int16_t sport, u_int8_t *data, int len)
{
    u_int8_t *ptr;
    int count, no;
    int lest, sndLen;

    if ((no = TcpSearchTable(sport) == -1))
    {
        return -1;
    }

    ptr = data;
    lest = len;

    while (lest > 0)
    {
        if (lest >= TcpTable[no].rcv.wnd)
        {
            sndLen = TcpTable[no].rcv.wnd;
        }
        else if (lest >= Param.MSS)
        {
            sndLen = Param.MSS;
        }
        else
        {
            sndLen = lest;
        }

        printf("TcpSend:offset=%ld,len=%d,lest=%d\n", ptr - data, sndLen, lest);

        count = 0;
        do
        {
            // Nagle アルゴリズムでデータをバッファにためて一括送信といったことはしない。
            // 以下を確認しどちらかを満たしている場合にのみデータを送るようにすると
            // レイテンシを犠牲にスループットを向上できる
            // - すべての送信済みデータに ack が帰ってきているか (snd.una == snd.nxt)
            // - sndLen = MSS のデータを送信できるか
            TcpSendData(soc, sport, ptr, sndLen); // 内部で snd.nxt = snd.una + sndLen になる

            // 再送間隔が長ければパケット消失が発生してから無駄な待ちが発生するので、スループットが低下する
            // 再送間隔が短ければパケット消失のご検知が発生し、無駄な再送が発生する
            // 待ち時間は RTT から算出すると良い
            //   - ackを受信した時刻 - sendした時刻
            //   - ackまでにかかったタイマーの割り込み回数 (本実装では count )
            // see: https://www.nic.ad.jp/ja/materials/iw/1999/proceedings/C03.PDF
            // rtt は常に変動するので srtt としてタイマ割り込みごとに平滑化する形で更新する
            // srtt = α × srtt + (1 - α) * rtt
            // ※ α の推奨値は 0.9
            //
            // 本実装では
            // rtt = DUMMY_WAIT_MS * (count + 1) なので while を抜けたあとに以下のように更新できそう
            // if (srtt == 0) { srtt = rtt; } else { srtt = 0.9 * srtt + 0.1 * DUMMY_WAIT_MS * (count + 1); }
            //
            // タイマー割り込み頻度であるDUMMY_WAIT_MSは本実装では100msec。
            // 再送タイマはスロータイマー・ファストタイマーでいうと前者で、berkly実装だと 500msec らしい
            //
            // 実際のタイムアウト時間は rto = 平均 rtt + 4 × 平均偏差 といった式や 指数バックオフなどで制御する。（タイムアウトが過ぎたら再送する）
            DummyWait(DUMMY_WAIT_MS * (count + 1));
            printf("TcpSend:una=%u,nextSeq=%u\n", TcpTable[no].snd.una - TcpTable[no].snd.iss, TcpTable[no].snd.nxt - TcpTable[no].snd.iss);
            count++;
            if (count > RETRY_COUNT)
            {
                printf("TcpSend:retry over\n");
                return 0;
            }
        } while (TcpTable[no].snd.una != TcpTable[no].snd.nxt); // ack を受信すると　snd.nxt = snd.una に更新されるので ack 受信まで待つという意味になる。

        ptr += sndLen;
        lest -= sndLen;
    }

    printf("TcpSend:una=%u,nextSeq=%u:success\n", TcpTable[no].snd.una - TcpTable[no].snd.iss, TcpTable[no].snd.nxt - TcpTable[no].snd.iss);

    return 1;
}

int TcpRecv(int soc, struct ether_header *eh, struct ip *ip, u_int8_t *data, int len)
{
    struct tcphdr *tcp;
    u_int8_t *ptr = data;
    u_int16_t sum;
    int no, lest, tcplen;

    tcplen = len;

    sum = TcpChecksum(&ip->ip_src, &ip->ip_dst, ip->ip_p, data, tcplen);
    if (sum != 0 && sum != 0xFFFF)
    {
        printf("TcpRecv:bad tcp checksum(%x)\n", sum);
        return -1;
    }

    tcp = (struct tcphdr *)ptr;
    ptr += sizeof(struct tcphdr);
    tcplen -= sizeof(struct tcphdr);

    printf("--- recv ---[\n");
    print_ether_header(eh);
    print_ip(ip);
    print_tcp(tcp);

    lest = tcp->doff * 4 - sizeof(struct tcphdr); // data_offsetは4byte単位
    if (lest > 0)
    {
        print_tcp_optpad(ptr, lest);
        ptr += lest;
        tcplen -= lest;
    }
    print_hex(ptr, tcplen);
    printf("]\n");

    if ((no = TcpSearchTable(ntohs(tcp->dest))) != -1)
    {
        if (TcpTable[no].rcv.nxt != 0 && ntohl(tcp->seq) != TcpTable[no].rcv.nxt)
        {
            // 連番以外だったらDROPする
            printf("TcpRecv:%d:seq(%u)!=rcv.nxt(%u)\n", no, ntohl(tcp->seq), TcpTable[no].rcv.nxt);
        }
        else
        {
            if (TcpTable[no].status == TCP_SYN_SENT)
            {
                if (tcp->rst == 1)
                {
                    printf("TcpRecv:%d:SYN_SENT:rst\n", no);
                    TcpTable[no].status = TCP_CLOSE;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq);
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                    TcpSocketClose(TcpTable[no].myPort);
                }
                else if (tcp->syn == 1)
                {
                    printf("TcpRecv:%d:SYN_SENT:syn\n", no);
                    TcpTable[no].status = TCP_SYN_RECV;
                    if (tcp->ack == 1)
                    {
                        printf("TcpRecv:SYN_RECV:syn-ack:%d\n", no);
                        TcpTable[no].status = TCP_ESTABLISHED;
                    }
                    TcpTable[no].rcv.irs = ntohl(tcp->seq);
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq) + 1; // 相手に ACK を返して自分は ESTABLISHED になるから次のデータは中身があるはず。そのため rcv.nxt をインクメントする。
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                    TcpSendAck(soc, no);
                }
            }
            else if (TcpTable[no].status == TCP_SYN_RECV)
            {
                if (tcp->rst == 1)
                {
                    printf("TcpRecv:%d:SYN_RECV:rst\n", no);
                    TcpTable[no].status = TCP_CLOSE;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq);
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                    TcpSocketClose(TcpTable[no].myPort);
                }
                else if (tcp->ack == 1)
                {
                    printf("TcpRecv:%d:SYN_RECV:ack\n", no);
                    TcpTable[no].status = TCP_ESTABLISHED;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq);
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                }
            }
            else if (TcpTable[no].status == TCP_LISTEN)
            {
                if (tcp->syn == 1)
                {
                    printf("TcpRecv:%d:LISTEN:syn\n", no);
                    TcpTable[no].status = TCP_SYN_RECV;
                    TcpTable[no].dstAddr.s_addr = ip->ip_src.s_addr;
                    TcpTable[no].dstPort = ntohs(tcp->source);
                    TcpTable[no].rcv.irs = ntohl(tcp->seq) + 1;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq) + 1;
                    TcpSendSyn(soc, no, 1);
                }
            }
            else if (TcpTable[no].status == TCP_FIN_WAIT1)
            {
                if (tcp->rst == 1)
                {
                    printf("TcpRecv:%d:FIN_WAT1:rst\n", no);
                    TcpTable[no].status = TCP_CLOSE;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq);
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                    TcpSocketClose(TcpTable[no].myPort);
                }
                else if (tcp->fin == 1)
                {
                    printf("TcpRecv:%d:FIN_WAIT1:fin\n", no);
                    TcpTable[no].status = TCP_CLOSING;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq) + tcplen + 1;
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                    TcpSendAck(soc, no);
                    if (tcp->ack == 1)
                    {
                        printf("TcpRecv:FIN_WAIT1: fin-ack:%d\n", no);
                        TcpTable[no].status = TCP_TIME_WAIT;
                    }
                }
                else if (tcp->ack == 1)
                {
                    printf("TcpRecv:%d:FIN_WAIT1:ack\n", no);
                    TcpTable[no].status = TCP_FIN_WAIT2;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq);
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                }
            }
            else if (TcpTable[no].status == TCP_FIN_WAIT2)
            {
                if (tcp->rst == 1)
                {
                    printf("TcpRecv:%d:FIN_WAIT2:rst\n", no);
                    TcpTable[no].status = TCP_CLOSE;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq);
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                    TcpSocketClose(TcpTable[no].myPort);
                }
                else if (tcp->fin == 1)
                {
                    printf("TcpRecv:%d:FIN_WAIT2:fin\n", no);
                    TcpTable[no].status = TCP_TIME_WAIT;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq) + tcplen + 1;
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                    TcpSendAck(soc, no);
                }
            }
            else if (TcpTable[no].status == TCP_CLOSING)
            {
                if (tcp->rst == 1)
                {
                    printf("TcpRecv:%d:FIN_CLOSING:rst\n", no);
                    TcpTable[no].status = TCP_CLOSE;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq);
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                    TcpSocketClose(TcpTable[no].myPort);
                }
                else if (tcp->ack == 1)
                {
                    printf("TcpRecv:%d:CLOSING:ack\n", no);
                    TcpTable[no].status = TCP_TIME_WAIT;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq);
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                }
            }
            else if (TcpTable[no].status == TCP_CLOSE_WAIT)
            {
                if (tcp->rst == 1)
                {
                    printf("TcpRecv:%d:CLOSE_WAIT:rst\n", no);
                    TcpTable[no].status = TCP_CLOSE;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq);
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                    TcpSocketClose(TcpTable[no].myPort);
                }
                else if (tcp->ack == 1)
                {
                    printf("TcpRecv:%d:CLOSE_WAIT:ack\n", no);
                    TcpTable[no].status = TCP_CLOSE;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq);
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                    TcpSocketClose(TcpTable[no].myPort);
                }
            }
            else if (TcpTable[no].status == TCP_ESTABLISHED)
            {
                if (tcp->rst == 1)
                {
                    printf("TcpRecv:%d:ESTABLISHED:rst\n", no);
                    TcpTable[no].status = TCP_CLOSE;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq);
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                    TcpSocketClose(TcpTable[no].myPort);
                }
                else if (tcp->fin == 1)
                {
                    printf("TcpRecv:%d:ESTABLISHED:fin\n", no);
                    TcpTable[no].status = TCP_CLOSE_WAIT;
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq) + tcplen + 1;
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                    TcpSendFin(soc, no);
                }
                else if (tcplen > 0)
                {
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq) + tcplen;
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                    TcpSendAck(soc, no);
                }
                else
                {
                    TcpTable[no].rcv.nxt = ntohl(tcp->seq);
                    TcpTable[no].snd.una = ntohl(tcp->ack_seq);
                }
            }
            TcpTable[no].rcv.wnd = ntohs(tcp->window);
        }
        printf("TcpRecv:%d:%s:S[%u,%u,%u,%u]:R[%u,%u,%u]\n", no, TcpStatusStr(TcpTable[no].status),
               TcpTable[no].snd.una - TcpTable[no].snd.iss, TcpTable[no].snd.nxt - TcpTable[no].snd.iss, TcpTable[no].snd.wnd, TcpTable[no].snd.iss,
               TcpTable[no].rcv.nxt - TcpTable[no].rcv.irs, TcpTable[no].rcv.wnd, TcpTable[no].rcv.irs);
    }
    else
    {
        printf("TcpRecv:no target:%u\n", ntohs(tcp->dest));
        TcpSendRstDirect(soc, eh, ip, tcp);
    }

    return 0;
}
