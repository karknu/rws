define(_frag,`
(eth type=0x0800
 (ipv4 src=10.0.0.1 dst=10.0.0.2 off=0x2000 prot=17 id=$1
   (udp csum=0 fixcsum=false len=2024 (payload pattern=0 length=1040))))
(eth type=0x0800
  (ipv4 src=10.0.0.1 dst=10.0.0.2 off=0x0083  prot=17 id=$1
   (payload pattern=1 length=1024)))
')

_frag(1)
_frag(2)
_frag(3)
_frag(5)
_frag(6)
_frag(7)
_frag(8)

