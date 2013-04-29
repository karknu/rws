define(_base_seqA, 0x1)
define(_base_seqB, 0xf00000)
define(_plen, 1480)
define(_tcp_snd, `(eth type=0x0800 src=00:00:00:00:00:01 dst=00:00:00:00:00:02
 (ipv4 src=1.1.1.1 dst=1.1.1.2 
  id=2 prot = 6 csum=0
  (tcp src=1234 ack seqno=eval(`2 + $1') ackno=eval(2 + _base_seqB) (payload length=_plen))))')

(eth type=0x0800 src=00:00:00:00:00:01 dst=00:00:00:00:00:02
 (ipv4 src=1.1.1.1 dst=1.1.1.2
  id=2 prot = 6 csum=0
  (tcp src=1234 syn seqno=_base_seqA ackno=0)))
(eth type=0x0800 src=00:00:00:00:00:01 dst=00:00:00:00:00:02
 (ipv4 src=1.1.1.1 dst=1.1.1.2
  id=2 prot = 6 csum=0
  (tcp src=1234 syn seqno=_base_seqA ackno=0)))
(eth type=0x0800 src=00:00:00:00:00:02 dst=00:00:00:00:00:01
 (ipv4 src=1.1.1.2 dst=1.1.1.1 
  id=2 prot = 6 csum=0
  (tcp dst=1234 syn ack seqno=eval(_base_seqB + 1) ackno=eval(_base_seqA+1))))
(eth type=0x0800 src=00:00:00:00:00:01 dst=00:00:00:00:00:02
 (ipv4 src=1.1.1.1 dst=1.1.1.2
  id=2 prot = 6 csum=0
  (tcp src=1234 ack seqno=eval(_base_seqA+1) ackno=eval(_base_seqB + 2))))

_tcp_snd(eval(0 * _plen))
_tcp_snd(eval(1 * _plen))
_tcp_snd(eval(2 * _plen))
_tcp_snd(eval(3 * _plen))





