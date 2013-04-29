{-# LANGUAGE CPP#-}


import Test.Framework (Test, defaultMain)

import Ethernet
import Fragv6
import Gre
import Gtp
import HexPayload
import HopByHop
import Icmp
import IcmpV6
import IPv4
import IPv6
import L2tp
import PadN
import Parser
import Ppp
import Tcp
import Teredo
import Udp

main :: IO ()
main = defaultMain tests

tests ::[Test]
tests =
  ethTests ++
  fragv6Tests ++
  greTests ++
  gtpTests ++
  hexPayloadTests ++
  hopByHopTests ++
  icmpTests ++
  icmpV6Tests ++
  ipv4Tests ++
  ipv6Tests ++
  l2tpTests ++
  padNTests ++
  parserTests ++
  pppTests ++
  tcpTests ++
  teredoTests ++
  udpTests


