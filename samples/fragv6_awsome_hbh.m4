define(`forloop',
       `pushdef(`$1', `$2')_forloop(`$1', `$2', `$3', `$4')popdef(`$1')')
define(`_forloop',
       `$4`'ifelse($1, `$3', ,
		   `define(`$1', incr($1))_forloop(`$1', `$2', `$3', `$4')')')

define(`_len', 1312)

define(`_frag',
`(eth type=0x86dd
 (ipv6 nh = 44
  (fragv6 nh=17 off =eval(1312 * $1 + 1) id=0xffffffff (payload pattern=$1 length=_len))))
')

dnl first frag
(eth type=0x86dd
 (ipv6 nh = 44
  (fragv6 nh=17 off =1 id=0xffffffff (udp len=65481 (payload pattern=0 length=eval(_len - 8)) csum=0xbaf5))))

forloop(`i', 1, 48, `_frag(`i')')

dnl last frag
dnl interesting last lengths 1247, 1208 and 1194
(eth type=0x86dd
 (ipv6 nh = 44
  (fragv6 nh=17 off =eval(1312 * 49) id=0xffffffff (payload pattern=49 length=1194))))


