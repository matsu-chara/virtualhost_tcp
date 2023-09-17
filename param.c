#include <stdio.h>
// #include <ctype.h>
// #include <unistd.h>
#include <stdlib.h>
#include <string.h>
// #include <errno.h>
// #include <signal.h>
// #include <time.h>
// #include <sys/stat.h>
// #include <sys/param.h>
// #include <sys/types.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#include "param.h"

extern PARAM Param;

static char *ParamFname = NULL;

int SetDefaultParam()
{
    Param.MTU = DEFAULT_MTU;
    Param.IpTTL = DEFAULT_IP_TTL;

    return 0;
}

int ReadParam(char *fname)
{
    FILE *fp;
    char buf[1024];
    char *ptr, *saveptr;

    ParamFname = fname;

    if ((fp = fopen(fname, "r")) == NULL)
    {
        printf("%s cannot read\n", fname);
        return -1;
    }

    while (1)
    {
        fgets(buf, sizeof(buf), fp);
        if (feof(fp))
        {
            break;
        }
        ptr = strtok_r(buf, "=", &saveptr); // strtok_r = reentrant string tokens
        if (ptr != NULL)
        {
            if (strcmp(ptr, "IP-TTL") == 0)
            {
                // strtok_rは同じ文字列への二回目以降の呼び出しではstrをnullにして、saveptrのみを渡す必要がある
                if ((ptr = strtok_r(NULL, "\r\n", &saveptr)) != NULL)
                {
                    Param.IpTTL = atoi(ptr);
                }
            }
            else if (strcmp(ptr, "MTU") == 0)
            {
                if ((ptr = strtok_r(NULL, "\r\n", &saveptr)) != NULL)
                {
                    Param.IpTTL = atoi(ptr);
                }
            }
            else if (strcmp(ptr, "MTU") == 0)
            {
                if ((ptr = strtok_r(NULL, "\r\n", &saveptr)) != NULL)
                {
                    Param.MTU = atoi(ptr);
                    if (Param.MTU > ETHERMTU)
                    {
                        printf("ReadParam:MTU(%d) <= ETHERMTU(%d)\n", Param.MTU, ETHERMTU);
                        Param.MTU = ETHERMTU;
                    }
                }
            }
            else if (strcmp(ptr, "gateway") == 0)
            {
                if ((ptr = strtok_r(NULL, "\r\n", &saveptr)) != NULL)
                {
                    Param.gateway.s_addr = inet_addr(ptr);
                }
            }
            else if (strcmp(ptr, "device") == 0)
            {
                if ((ptr = strtok_r(NULL, "\r\n", &saveptr)) != NULL)
                {
                    Param.device = strdup(ptr);
                }
            }
            else if (strcmp(ptr, "vmac") == 0)
            {
                if ((ptr = strtok_r(NULL, "\r\n", &saveptr)) != NULL)
                {
                    my_ether_aton(ptr, Param.vmac);
                }
            }
            else if (strcmp(ptr, "vip") == 0)
            {
                if ((ptr = strtok_r(NULL, "\r\n", &saveptr)) != NULL)
                {
                    Param.vip.s_addr = inet_addr(ptr);
                }
            }
            else if (strcmp(ptr, "vmask") == 0)
            {
                if ((ptr = strtok_r(NULL, "\r\n", &saveptr)) != NULL)
                {
                    Param.vmask.s_addr = inet_addr(ptr);
                }
            }
        }
    }

    fclose(fp);

    return 0;
}

int isTargetIPAddr(struct in_addr *addr)
{
    if (Param.vip.s_addr == addr->s_addr)
    {
        return 1;
    }

    return 0;
}

int isSameSubnet(struct in_addr *addr)
{
    // addr と vipが同一サブネットか判定
    if ((addr->s_addr & Param.vmask.s_addr) == (Param.vip.s_addr & Param.vmask.s_addr))
    {
        return 1;
    }
    else
    {
        return 0;
    }
}
