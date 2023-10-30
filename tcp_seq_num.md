
# seq_num 遷移表

## まとめ

結局は snd.nxt, send.una, rcv.nxt の三種類

- 送信時
  - SYN          (seq = snd.una)                          => (snd.nxt = snd.una +   0)
  - SYN/ACK      (seq = snd.una, ack_seq = rcv.nxt)       => (snd.nxt = snd.una +   0)
  - ACK          (seq = snd.una, ack_seq = rcv.nxt)       => (snd.nxt = snd.una +   0)
  - SEND         (seq = snd.una)                          => (snd.nxt = snd.una + len)
- 受信時
  - RECV_SYN     (rcv.nxt = seq +   1)                    => SEND_SYN/ACK
  - RECV_SYN/ACK (rcv.nxt = seq +   1, snd.una = ack_seq) => SEND_ACK
  - RECV_ACK     (rcv.nxt = seq +   0, snd.una = ack_seq) => SEND or RECV
  - RECV_SEND    (rcv.nxt = seq + len, snd.una = ack_seq) => SEND_ACK
  - ※ RECV_ACK は handshake/established 双方同じ挙動

## snd.nxt について

本実装では send のたびにack を待っている。そのため snd.nxt は実質送ったメッセージが ack されているかどうかを　(snd == una かどうか見ることで)確認する用途でしか使っていない。
本来は window の分だけ send できるはずなので snd.nxt はどんどん先に進み、 snd.una があとから追いつく形になる。
（その場合メッセージに詰めるべきなのは snd.una ではなく snd.nxt のはず）

また、ハンドシェイク時は snd.nxt = snd.una + dataLen の dataLen が 0 byte のため、 snd.nxt が常に snd.una に追いつく形になる。
この場合、相手が ack を返したかどうかをチェックすることができないが connection status をチェックすることで ack を確認できる。

## ハンドシェイク時の seq_num

### TcpAddTable

- state of S
  - TCP_CLOSE
  - snd.nxt = x1
  - snd.una = x1
  - rcv.nxt = 0
- state of R
  - TCP_LISTEN
  - snd.nxt = x2
  - snd.una = x2
  - rcv.nxt = 0

### TsySendSyn from S

- send msg of S
  - tcp->seq     = snd.una = x1 // まだackされてない番号を送りたいので una = x1 を送る
  - tcp->ack_seq = rcv.nxt = 0  // まだ何もackしてないので rcv.nxt = 0 を送る
- state of S
  - TCP_SEND_SYN
  - snd.nxt      = snd.una = x1 // nxt = una + len だが len が 0 byte なので同一の値になる。
  - // snd.una = x1
  - // rcv.nxt = 0

### TcpRecv (Syn) of R

- rcv msg of R
  - tcp->seq       = x1
  - tcp->ack_seq   = 0
- state of R
  - TCP_SYN_RECV
  - // snd.una = x2
  - // snd.nxt = x2
  // seq + (受け取ったデータ長 (SYNは特別に1)) になる。これを ack_seq として相手に送ると相手は次に x1 + 1 のメッセージを送ってくれる。
  - rcv.nxt        = tcp->seq + 1 = x1 + 1

### TcpSendSynAck from R

- send msg of R
  - tcp->seq     = snd.una  = x2
  - tcp->ack_seq = rcv.nxt  = x1 + 1
- state of R
  - TCP_SYN_RECV
  - // snd.una = x2
  - snd.nxt = snd.una = x2
  - // rcv.nxt = x1 + 1

### TcpRecv (SynAck) of S

- rcv msg of S
  - tcp->seq     = x2
  - tcp->ack_seq = x1 + 1
- state of S
  - TCP_ESTABLISHED
  - snd.una = tcp->ack_seq = x1 + 1
  - // snd.nxt = x1
  - rcv.nxt = tcp->seq + 1 = x2 + 1

### TcpSendAck from S

- send msg of S
  - tcp->seq = snd.una = x1 + 1
  - tcp->ack_seq = rcv.nxt = x2 + 1
- state of S
  - TCP_ESTABLISHED
  - // snd.una = x1 + 1
  - snd.nxt = snd.una = x1 + 1
  - // rcv.nxt = x2 + 1

### TcpRecv (Ack) of R

- rcv msg of R
  - tcp->seq =  x1 + 1
  - tcp->ack_seq = x2 + 1
- state of R
  - TCP_ESTABLISHED
  - snd.una = tcp_ack_seq = x2 + 1
  - //snd.nxt = x2
  - rcv.nxt = tcp->seq + 1 = x1 + 2
