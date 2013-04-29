{-# LANGUAGE CPP #-}
module Parser where

import Text.ParserCombinators.Parsec

import Packet
import IPv4
import IPv6
import Ethernet
import Udp
import Gtp
import L2tp
import Ppp
import Payload
import Lexer
import Tcp
import Teredo
import Gre
import Icmp
import IcmpV6
import Fragv6
import HopByHop
import PadN
import HexPayload

#ifdef HRWS_TEST
--import Debug.Trace
import Test.Framework (Test)
import Test.Framework.Providers.QuickCheck2 (testProperty)
#endif

parsePacket :: Parser [Packet]
parsePacket = do
    whiteSpace
    many1 packetDecl

packetDeclH :: Parser Packet
packetDeclH = choice [
    try $ ipv4Decl packetDecl,
    try $ ipv6Decl packetDecl,
    try $ icmpV6Decl packetDecl,
    try $ icmpDecl packetDecl,
    udpDecl packetDecl,
    try $ tcpDecl packetDecl,
    ethDecl packetDecl,
    try $ gtpDecl packetDecl,
    try $ greDecl packetDecl,
    l2tpDecl packetDecl,
    try $ payloadDecl packetDecl,
    try $ pppDecl packetDecl,
    try $ padNDecl packetDecl,
    try $ teredoDecl packetDecl,
    try $ fragv6Decl packetDecl,
    try $ hopByHopDecl packetDecl,
    try $ hexPayloadDecl packetDecl
    ]

packetDecl :: Parser Packet
packetDecl = do
  char '('
  p <- packetDeclH
  char ')'
  whiteSpace
  return p

readPacket :: String -> [Packet]
readPacket input = case parse parsePacket "packet parse" input of
                         Left err -> error $ show err
                         Right val -> val

#ifdef HRWS_TEST
{- Unit Tests -}

testParserIPv4Udp :: () -> Bool
testParserIPv4Udp _ =
  let expPkt = PEth defaultEthernetFrame {ethernPayload = [PIPv4 defaultIPv4Packet {
                    ipv4PktPayload = [PUdp defaultUdpPacket]}]} in
  let pkts = readPacket "(eth (ipv4 (udp)))" in
  (length pkts == 1) && (head pkts == expPkt)

testParserIPv6Tcp :: () -> Bool
testParserIPv6Tcp _ =
  let expPkt = PEth defaultEthernetFrame {ethernPayload = [PIPv6 defaultIPv6Packet {
                    ipv6PktPayload = [PTcp defaultTcpPacket]}]} in
  let pkts = readPacket "(eth (ipv6 (tcp)))" in
  (length pkts == 1) && (head pkts == expPkt)

testParserIPv6Gtp :: () -> Bool
testParserIPv6Gtp _ =
  let expPkt = PEth defaultEthernetFrame {ethernPayload = [PIPv6 defaultIPv6Packet {
                    ipv6PktPayload = [PUdp defaultUdpPacket {
                    udpPktPayload  = [PGtp defaultGtpPacket {
                    gtpPktPayload = [PIPv4 defaultIPv4Packet {
                    ipv4PktPayload = [PUdp defaultUdpPacket]}]}]}]}]} in
  let pkts = readPacket "(eth (ipv6 (udp (gtp (ipv4 (udp))))))" in
  (length pkts == 1) && (head pkts == expPkt)



parserTests :: [Test]
parserTests = [
  testProperty "Parser: Eth IPv4 Udp " testParserIPv4Udp,
  testProperty "Parser: Eth IPv6 Tcp" testParserIPv6Tcp,
  testProperty "Parser: Eth IPv6 Gtp" testParserIPv6Gtp
  ]

#endif

