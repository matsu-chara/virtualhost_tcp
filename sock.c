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
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <linux/if.h>
#include <arpa/inet.h>

#include "sock.h"
#include "param.h"

/* 16ビットごとの1の補数和を取り、さらにそれの1の補数を取る。
 * IP, ICMP, UDP, TCPすべてチェックサムの計算方法は同じ。
 * UDPは計算結果が0x0000の場合に0xFFFFにする（0x0000はチェックサム計算なしを意味するため）という処理が入る。
 *
 * 計算の詳細は
 *   - https://www.mew.org/~kazu/doc/bsdmag/cksum.html
 *   - https://alpha-netzilla.blogspot.com/2011/08/network.html
 */
u_int16_t checksum(u_int8_t *data, int len)
{
    u_int32_t sum;
    u_int16_t *ptr;
    int c;

    sum = 0;
    ptr = (u_int16_t *)data; // 1byteごとのデータを2byte(16bit)区切りにする

    for (c = len; c > 1; c -= 2)
    {
        sum += (*ptr);        // 16bitごとに値を加算
        if (sum & 0x80000000) // 32bitの先頭byteが1 == オーバフローする前に足しこみ
        {
            // 32bitでチェックサムを計算し、上位16bitと下位の16bitを足すと16bitの1の補数和が得られる
            sum = (sum & 0xFFFF) + (sum >> 16); // sum = 下16bit + 上16bit
        }
        ptr++; // 次の16bitへ
    }
    if (c == 1) // 最後に8bit余ったらそれも足す
    {
        u_int16_t val;
        val = 0;
        memcpy(&val, ptr, sizeof(u_int8_t));
        sum += val;
    }

    while (sum >> 16) // 上位16bitが0になるまで足し込む
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum; // 最後に1の補数を取る
}

u_int16_t checksum2(u_int8_t *data1, int len1, u_int8_t *data2, int len2)
{
    u_int32_t sum;
    u_int16_t *ptr;
    int c;

    sum = 0;
    ptr = (u_int16_t *)data1;

    for (c = len1; c > 1; c -= 2)
    {
        sum += (*ptr);
        if (sum & 0x80000000)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        ptr++;
    }
    if (c == 1)
    {
        u_int16_t val;
        val = ((*ptr) << 8) + (*data2);
        sum += val;
        if (sum & 0x80000000)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        ptr = (u_int16_t *)(data2 + 1);
        len2--;
    }
    else
    {
        ptr = (u_int16_t *)data2;
    }

    for (c = len2; c > 1; c -= 2)
    {
        sum += (*ptr);
        if (sum & 0x80000000)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        ptr++;
    }
    if (c == 1)
    {
        u_int16_t val;
        val = 0;
        memcpy(&val, ptr, sizeof(u_int8_t));
        sum += val;
    }

    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

int GetMacAddress(char *device, u_int8_t *hwaddr)
{
    struct ifreq ifreq;
    int soc;
    u_int8_t *p;

    // AF_INET = address family internetwork
    // SOCK_DGRAM = datagram socket
    if ((soc = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("GetMacAddress():socket");
        return -1;
    }

    strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);

    // 本に乗ってるSIOCGIFHWADDR は mac os x 未対応
    if (ioctl(soc, SIOCGIFHWADDR, &ifreq) == -1)
    {
        perror("GetMacAddress((:ioctl:hwaddr))");
        close(soc);
        return -1;
    }
    else
    {
        p = (uint8_t *)&ifreq.ifr_hwaddr.sa_data;
        memcpy(hwaddr, p, 6);
        close(soc);
        return 1;
    }
}

int DummyWait(int ms)
{
    struct timespec ts;

    ts.tv_sec = 0;
    ts.tv_nsec = ms * 1000 * 1000;

    // reqはsleepする時間
    // remはsleepの残り時間を格納する構造体 (シグナルが送られるとsleepが解除されることがある)
    nanosleep(&ts, NULL);

    return 0;
}

int init_socket(char *device)
{
    struct ifreq if_req;
    struct sockaddr_ll sa;
    int soc;

    if ((soc = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("socket");
        return -1;
    }

    strcpy(if_req.ifr_name, device);
    if (ioctl(soc, SIOCGIFINDEX, &if_req) < 0)
    {
        perror("ioctl");
        close(soc);
        return -1;
    }

    sa.sll_family = PF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = if_req.ifr_ifindex;
    if (bind(soc, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    {
        perror('bind');
        close(soc);
        return -1;
    }

    if (ioctl(soc, SIOCGIFFLAGS, &if_req) < 0)
    {
        perror('ioctl');
        close(soc);
        return -1;
    }

    if_req.ifr_flags = if_req.ifr_flags | IFF_PROMISC | IFF_UP;
    if (ioctl(soc, SIOCSIFFLAGS, &if_req) < 0)
    {
        perror("ioctl");
        close(soc);
        return -1;
    }

    return soc;
}
