[ソースコードで体感するネットワークの仕組み](https://www.amazon.co.jp/dp/4774197440) の写経

# remote development

```sh
vagrant up

## node1
vagrant ssh node1
make
sudo ./MyEth
# 何も入れないでEnterを押すとヘルプが出る

## node2
# provisioningにより DHCP サーバーが起動している

# udp で listen （ node1 から `udp send 20000 192.168.33.12:10000 foobar` でメッセージを受け取れる）
nc -lu 10000
# udp で 送信（ node1 で `udp open 10005` していればメッセージを送信できる）
nc -u 192.168.33.100 10005

# 
# tcp で listen （ node1 から `tcp connect 20000 192.168.33.12:10005 => tcp send 20000 foobar` でメッセージを受け取れる）
nc -lu 10005
# tcp で 送信（ node1 で `tcp listen 10005` していればメッセージを送信できる）
nc 192.168.33.100 10005

```

# http to somewhere

MyEth.ini を以下のように書き換える

```
device=eth0
vip=192.168.33.11
vmask=192.168.33.0
gateway=10.0.2.2
```

```
tcp connect 10000 $(アクセス先のip):80
tcp send 10000 GET / HTTP/1.1\n\n
```
