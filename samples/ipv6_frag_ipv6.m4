define(_frag,`
(eth type=0x86dd
 (ipv6 hl=32 src=20:0:0:0:0:0:0:2 dst=30:0:0:0:0:0:0:1 nh=44
  (fragv6 nh=4 off =1 id=0x1234
   (ipv4 src=10.0.0.1 dst=10.0.0.2 prot=17 id=$1 len=2072
    (udp csum=0 fixcsum=false len=2024 (payload pattern=0 length=1020))))))
(eth type=0x86dd
 (ipv6 hl=32 src=20:0:0:0:0:0:0:2 dst=30:0:0:0:0:0:0:1 nh=44
  (fragv6 nh=4 off = 1048 id=0x1234
   (payload pattern=1 length=1024))))
')

_frag(1)
_frag(2)
_frag(3)
_frag(5)
_frag(6)
_frag(7)
_frag(8)

