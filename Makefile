PROGRAM=MyEth
OBJS=main.o param.o sock.o ether.o arp.o ip.o icmp.o cmd.o dhcp.o
SRCS=$(OBJS:%.o=%.c)
CFLAGS=-std=gnu99 -Wall -g
LDFLAGS=-lpthread

$(PROGRAM):$(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(PROGRAM) $(OBJS) $(LDLIBS)

clean:
	rm -f $(OBJS)
