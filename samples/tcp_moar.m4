define(_base_seqA, 0x1)
define(_base_seqB, 0xf00000)
define(_plen, 1480)
define(_seqA, _base_seqA)
define(_seqB, _base_seqB)

define(_tcp_sndA,
`(eth type=0x0800 src=00:00:00:00:00:01 dst=00:00:00:00:00:02
  (ipv4 src=1.1.1.1 dst=1.1.1.2 
   id=2 prot = 6 csum=0
   (tcp src=1234 seqno=_seqA ackno=_seqB $1)))')
define(_tcp_sndB,
`(eth type=0x0800 src=00:00:00:00:00:02 dst=00:00:00:00:00:01
  (ipv4 src=1.1.1.2 dst=1.1.1.1
   id=2 prot = 6 csum=0
   (tcp dst=1234 seqno=_seqB ackno=_seqA $1)))')

define(_tcp_sndDataA,
`(eth type=0x0800 src=00:00:00:00:00:01 dst=00:00:00:00:00:02
  (ipv4 src=1.1.1.1 dst=1.1.1.2 
   id=2 prot = 6 csum=0
   (tcp src=1234 ack seqno=_seqA ackno=_seqB (payload length=$1 pattern=$2))))
    define(`_seqA', eval(_seqA + $1))')

define(_tcp_sndDataB,
`(eth type=0x0800 src=00:00:00:00:00:02 dst=00:00:00:00:00:01
  (ipv4 src=1.1.1.2 dst=1.1.1.1
   id=2 prot = 6 csum=0
   (tcp dst=1234 ack seqno=_seqB ackno=_seqA (payload length=$1 pattern=$2))))
    define(`_seqB', eval(_seqB + $1))')

(eth type=0x0800 src=00:00:00:00:00:01 dst=00:00:00:00:00:02
  (ipv4 src=1.1.1.1 dst=1.1.1.2 
   id=2 prot = 6 csum=0
   (tcp src=1234 seqno=_seqA ackno=0 syn)))
define(`_seqA', eval(_seqA + 1))
_tcp_sndB(`syn ack') define(`_seqB', eval(_seqB + 1))
_tcp_sndA(`ack')
_tcp_sndDataA(1480, 0)
_tcp_sndDataA(1480, 1)
_tcp_sndDataA(1480, 1)
_tcp_sndDataA(1480, 1)
_tcp_sndDataA(1480, 1)
_tcp_sndDataA(1480, 1)
_tcp_sndDataA(1480, 1)
_tcp_sndDataA(1480, 1)
_tcp_sndDataA(1480, 1)
_tcp_sndDataA(1480, 1)
_tcp_sndDataA(1480, 1)
_tcp_sndDataA(1480, 1)
_tcp_sndDataB(1480, 0)
_tcp_sndDataB(1480, 1)
_tcp_sndA(`fin ack') define(`_seqA', eval(_seqA + 1))
_tcp_sndB(`fin ack') define(`_seqB', eval(_seqB + 1))
_tcp_sndA(`ack')





