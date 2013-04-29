define(_base_seq, 0x1)
define(_plen, 1480)
define(_tcp_snd, `(eth type=0x0800 src=00:00:00:00:00:01 dst=00:00:00:00:00:02
 (ipv4 src=1.1.1.1 dst=1.1.1.2 
  id=2 prot = 6 csum=0
  (tcp src=1234 ack wsc=2 offset=24 seqno=eval(`2 + $1') ackno=2
   (payload length=_plen pattern=$2))))')

(eth type=0x0800 src=00:00:00:00:00:01 dst=00:00:00:00:00:02
 (ipv4 src=1.1.1.1 dst=1.1.1.2 
  id=2 prot = 6 csum=0
  (tcp src=1234 syn wsc=2 offset=24 seqno=_base_seq ackno=0)))
(eth type=0x0800 src=00:00:00:00:00:02 dst=00:00:00:00:00:01
 (ipv4 src=1.1.1.2 dst=1.1.1.1 
  id=2 prot = 6 csum=0
  (tcp dst=1234 wsc=2 offset=24  syn ack ackno=eval(_base_seq+1) seqno=1000)))
(eth type=0x0800 src=00:00:00:00:00:01 dst=00:00:00:00:00:02
 (ipv4 src=1.1.1.1 dst=1.1.1.2 
  id=2 prot = 6 csum=0
  (tcp src=1234 ack seqno=eval(_base_seq+1) ackno=1001)))
_tcp_snd(eval(2 * _plen), 2)
_tcp_snd(eval(4 * _plen), 4)
_tcp_snd(eval(0 * _plen), 0)
_tcp_snd(eval(3 * _plen), 3)
_tcp_snd(eval(1 * _plen), 1)

(eth type=0x0800 src=00:00:00:00:00:02 dst=00:00:00:00:00:01
 (ipv4 src=1.1.1.2 dst=1.1.1.1 
  id=2 prot = 6 csum=0
  (tcp dst=1234 fin ack ackno=eval(_base_seq+1 + 4*_plen) seqno=1001)))
(eth type=0x0800 src=00:00:00:00:00:01 dst=00:00:00:00:00:02
 (ipv4 src=1.1.1.1 dst=1.1.1.2 
  id=2 prot = 6 csum=0
  (tcp src=1234 fin ack seqno=eval(_base_seq+1 + 4*_plen) ackno=1002)))
(eth type=0x0800 src=00:00:00:00:00:02 dst=00:00:00:00:00:01
 (ipv4 src=1.1.1.2 dst=1.1.1.1 
  id=2 prot = 6 csum=0
  (tcp dst=1234 ack ackno=eval(_base_seq+2 + 4*_plen) seqno=1002)))





