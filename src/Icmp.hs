{-# LANGUAGE CPP #-}
module Icmp where

import Data.Binary.Put
import qualified Data.ByteString.Lazy as B
import Text.ParserCombinators.Parsec
import Text.ParserCombinators.Parsec.Perm

import Util
import Packet
import Lexer

#ifdef HRWS_TEST
import Debug.Trace
import Test.QuickCheck hiding ((.&.))
import Test.Framework (Test)
import Test.Framework.Providers.QuickCheck2 (testProperty)
import Text.Printf
#endif

parseIcmpPkt :: Parser Packet -> Parser IcmpPkt
parseIcmpPkt f = permute
  (tuple <$?> (8, parseIntAttribute "type")
         <|?> (0, try (parseIntAttribute "code"))
         <|?> (0, try (parseIntAttribute "csum"))
         <|?> (0xcafe, parseIntAttribute "id")
         <|?> (0x1, parseIntAttribute "seq")
         <|?> (True, parseBoolAttribute "fixcsum")
         <|?> ([PPayload defaultPayload], parsePayload f))
  where
    tuple t c cs i s fc = IcmpPkt (Icmp t c cs i s fc)


icmpDecl :: Parser Packet -> Parser Packet
icmpDecl f = do
  symbol "icmp"
  g <- parseIcmpPkt f
  return (PIcmp g)

icmpWriteHdr :: Icmp -> Put
icmpWriteHdr p = do
    putWord8 $ icmpType p
    putWord8 $ icmpCode p
    putWord16be $ icmpCsum p
    putWord16be $ icmpId p
    putWord16be $ icmpSeq p

icmpWrite :: Icmp -> Maybe Packet -> B.ByteString -> Put
icmpWrite h _ bs = do
  icmpWriteHdr h
  putLazyByteString bs

instance PacketWriteable IcmpPkt where packetWrite p = icmpWrite (icmpPktHeader p)

#ifdef HRWS_TEST
{- Unit Tests -}

instance Arbitrary Icmp where
  arbitrary = do
    t   <- arbitrary
    c   <- arbitrary
    cs  <- arbitrary
    i   <- arbitrary
    s   <- arbitrary
    return (Icmp t c cs i s True)

testValidParse :: String -> (Icmp -> Bool) -> Bool
testValidParse str fn =
  case parse (dummyParsePacket icmpDecl) "packet parse" str of
       Left  err -> trace (show err) False
       Right val -> fn $ testIcmpPkt val

testIcmpPkt :: Packet -> Icmp
testIcmpPkt (PIcmp p) = icmpPktHeader p
testIcmpPkt _ = error "Unexpected packet type"

testIcmpDefault :: () -> Bool
testIcmpDefault _ =
  let cmp p = defaultIcmp == p in
  testValidParse "(icmp)" cmp

testIcmpPacket :: Icmp -> Bool
testIcmpPacket pkt =
  let cmp p = pkt == p in
  testValidParse (printf "(icmp type=%d code=%d csum=%d id=%d seq=%d fixcsum=true)" (icmpType pkt)
                  (icmpCode pkt) (icmpCsum pkt) (icmpId pkt) (icmpSeq pkt)) cmp

testIcmpWrite :: () -> Bool
testIcmpWrite _ =
  let expPkt = B.pack [0x08, 0x00, 0xab, 0xcd, 0x04, 0xd2, 0x16, 0x2e] in
  let cmp p = runPut (icmpWrite p Nothing B.empty) == expPkt in
  testValidParse "(icmp id=1234 seq=5678 csum=0xabcd)" cmp

icmpTests :: [Test]
icmpTests = [
  testProperty "ICMP: Default" testIcmpDefault,
  testProperty "ICMP: Packet" testIcmpPacket,
  testProperty "ICMP: Write" testIcmpWrite
  ]

#endif

