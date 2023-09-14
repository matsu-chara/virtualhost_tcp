#include <stdio.h>
#include <errno.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <netinet/if_ether.h>
#include <net/if.h>

#include "param.h"

int EndFlag = 0;
int DeviceSoc; // 送受信するPF_PACKETのディスクリプタを格納
PARAM Param;

void *MyEthThread(void *arg)
{
    int nready;
    struct pollfd targets[1];
    u_int8_t buf[2048];
    int len;

    targets[0].fd = DeviceSoc;
    targets[0].events = POLLIN | POLLERR; // in or errorを監視

    while (EndFlag == 0)
    {
        // poll(descriptors, number of file descriptors, 1000msec timeout)
        switch (nready = poll(targets, 1, 1000)) // deviceSocを監視
        {
        case -1:
            if (errno != EINTR) // if not intruppted
            {
                perror("poll");
            }
            break;
        case 0:
            break;
        default:
            if (targets[0].revents & (POLLIN | POLLERR))
            {
                if ((len = read(DeviceSoc, buf, sizeof(buf))) <= 0)
                {
                    perror("read");
                }
                else
                {
                    EtherRecv(DeviceSoc, buf, len);
                }
            }
            break;
        }
    }

    return NULL;
}

void *StdInThread(void *arg)
{
    int nready;
    struct pollfd targets[1];
    char buf[2048];

    targets[0].fd = fileno(stdin); // 標準入力を監視
    targets[0].events = POLLIN | POLLERR;

    while (EndFlag == 0)
    {
        switch (nready = poll(targets, 1, 1000))
        {
        case -1:
            if (errno != EINTR)
            {
                perror("poll");
            }
            break;
        case 0:
            break;
        default:
            if (targets[0].revents & (POLLIN | POLLERR))
            {
                fgets(buf, sizeof(buf), stdin);
                DoCmd(buf);
            }
            break;
        }
    }
}

void sig_term(int sig)
{
    EndFlag = 1;
}
