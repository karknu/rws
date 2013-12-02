{-# LANGUAGE CPP #-}
module IPv6 where

import Data.Binary.Put
import Data.Bits
import qualified Data.ByteString.Lazy as B
import Data.Word
import Text.ParserCombinators.Parsec
import Text.ParserCombinators.Parsec.Perm

import Lexer
import Packet
import Util

#ifdef HRWS_TEST
import Debug.Trace
import Test.QuickCheck hiding ((.&.))
import Test.Framework (Test)
import Test.Framework.Providers.QuickCheck2 (testProperty)
#endif

ipv6AddressDecl :: Parser IPv6Addr
ipv6AddressDecl = do
    a0 <- integer
    char ':'
    a1 <- integer
    char ':'
    a2 <- integer
    char ':'
    a3 <- integer
    char ':'
    a4 <- integer
    char ':'
    a5 <- integer
    char ':'
    a6 <- integer
    char ':'
    a7 <- integer

    let fix a b = fromIntegral a `shiftL` 16 .|. b

    return (IPv6Addr (fromIntegral (fix a0 a1))
                     (fromIntegral (fix a2 a3))
                     (fromIntegral (fix a4 a5))
                     (fromIntegral (fix a6 a7)))

parseIPv6Address :: String -> Parser IPv6Addr
parseIPv6Address s = do
  symbol s
  symbol "="
  a <- ipv6AddressDecl
  whiteSpace
  return a

parseIPv6Pkt :: Parser Packet -> Parser IPv6Pkt
parseIPv6Pkt f = permute
  (tuple <$?> (IPv6Addr 0x2001000 0 0 1, parseIPv6Address "src")
         <|?> (IPv6Addr 0x2001000 0 0 2, parseIPv6Address "dst")
         <|?> (6, parseIntAttribute "ver")
         <|?> (0, try $ parseIntAttribute "tcl")
         <|?> (0, try $ parseIntAttribute "flow")
         <|?> (-1,  parseIntAttribute "len")
         <|?> (17, parseIntAttribute "nh")
         <|?> (64, parseIntAttribute "hl")
         <|?> ([PPayload defaultPayload], parsePayload f))
  where
    tuple s d v tcl fl l nh hl =
      IPv6Pkt (IPv6 v tcl fl l nh hl s d)

ipv6Decl :: Parser Packet -> Parser Packet
ipv6Decl f = do
 symbol "ipv6"
 p <- parseIPv6Pkt f
 return (PIPv6 p)

ipv6AddrWrite :: IPv6Addr -> Put
ipv6AddrWrite a = do
  putWord32be $ ipv6Addr0 a
  putWord32be $ ipv6Addr1 a
  putWord32be $ ipv6Addr2 a
  putWord32be $ ipv6Addr3 a

ipv6WriteHdr :: IPv6 -> Put
ipv6WriteHdr p = do
    -- pl_uint8_t vertcl
    putWord8 $ ipv6Ver p `shiftL` 4 .|. ipv6Tcl p `shiftR` 4
    -- pl_uint8_t tclflow XXX byte order of ipv6Flow!!!
    putWord8 $ ipv6Tcl p `shiftL` 4 .|. fromIntegral (ipv6Flow p `shiftR` 16)
    -- pl_uint16_t flow_id
    putWord16be $ fromIntegral $ ipv6Flow p .&. 0xffff
    putWord16be $ fromIntegral $ ipv6Length p
    putWord8 $ ipv6Nh p
    putWord8 $ ipv6Hl p
    ipv6AddrWrite $ ipv6Src p 
    ipv6AddrWrite $ ipv6Dst p

ipv6Write :: IPv6 -> Maybe Packet -> B.ByteString -> Put
ipv6Write h _ bs = do
  let hdr = if ipv6Length h == -1 then h {ipv6Length = fromIntegral $ B.length bs}
                                  else h
  ipv6WriteHdr hdr
  putLazyByteString bs

pseudoIpv6Write :: IPv6 -> Word16 -> Put
pseudoIpv6Write p l = do
    ipv6AddrWrite $ ipv6Src p 
    ipv6AddrWrite $ ipv6Dst p
    putWord16be l
    putWord8 0
    putWord8 0
    putWord8 0
    putWord8 $ ipv6Nh p

instance PacketWriteable IPv6Pkt where packetWrite p = ipv6Write (ipv6PktHeader p)

#ifdef HRWS_TEST
{- Unit Tests -}

instance Arbitrary IPv6Addr where
  arbitrary = do
    a0 <- arbitrary
    a1 <- arbitrary
    a2 <- arbitrary
    a3 <- arbitrary
    return (IPv6Addr a0 a1 a2 a3)

instance Arbitrary IPv6 where
  arbitrary = do
    v    <- arbitrary
    tcl  <- arbitrary
    flow <- arbitrary
    len  <- arbitrary
    nh   <- arbitrary
    hl   <- arbitrary
    src  <- arbitrary
    dst  <- arbitrary
    return (IPv6 v tcl flow len nh hl src dst)

testValidParse :: String -> (IPv6 -> Bool) -> Bool
testValidParse str fn =
  case parse (dummyParsePacket ipv6Decl) "packet parse" str of
       Left  err -> trace (show err) False
       Right val -> fn $ testIPv6Pkt val

testIPv6Pkt :: Packet -> IPv6
testIPv6Pkt (PIPv6 p) = ipv6PktHeader p
testIPv6Pkt _ = error "Unexpected packet type"

testIPv6Default :: () -> Bool
testIPv6Default _ = let cmp f = defaultIPv6 == f in
  testValidParse "(ipv6)" cmp

ipv6ToPktStr :: IPv6 -> String
ipv6ToPktStr ip = "ipv6 ver=" ++ show (ipv6Ver ip) ++ " tcl=" ++ show (ipv6Tcl ip) ++
                  " flow=" ++ show (ipv6Flow ip) ++ " len=" ++ show (ipv6Length ip) ++
                  " nh=" ++ show (ipv6Nh ip) ++ " hl=" ++ show (ipv6Hl ip) ++
                  " src=" ++ show (ipv6Src ip) ++ " dst=" ++ show (ipv6Dst ip)


testIPv6Pkt0 :: IPv6 -> Bool
testIPv6Pkt0 ip = let cmp p = ip == p in
  testValidParse ("(" ++ ipv6ToPktStr ip ++ ")") cmp

testIPv6InIPv6 :: IPv6 -> Bool
testIPv6InIPv6 inner =
  let outer = inner {ipv6Nh = 41} in
  let cmp p = p == outer in
  testValidParse ("(" ++ ipv6ToPktStr outer ++ "(" ++ ipv6ToPktStr inner ++ "))") cmp
  

testIPv6Write :: () -> Bool
testIPv6Write _ =
  let expPkt = B.pack [0x60, 0xf0, 0xbe, 0xef, 0x00, 0x00, 0x04, 0x40,
                       0x07, 0xd1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                       0x07, 0xd1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02] in
   let cmp p = runPut (ipv6Write p Nothing B.empty) == expPkt in
   testValidParse "(ipv6 ver=6 tcl=0xf flow=0xbeef len=0 hl=64 src=2001:0:0:0:0:0:0:1 dst=2001:0:0:0:0:0:0:2 nh=4)" cmp

testIPv6PseudoWrite :: () -> Bool
testIPv6PseudoWrite _ =
  let expPkt = B.pack [0x07, 0xd1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                       0x07, 0xd1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                       0x00, 0x54, 0x00, 0x00, 0x00, 0x04] in
   let cmp p = runPut (pseudoIpv6Write p 84) == expPkt in
   testValidParse "(ipv6 ver=6 tcl=0xf flow=0xbeef len=84 hl=64 src=2001:0:0:0:0:0:0:1 dst=2001:0:0:0:0:0:0:2 nh=4)" cmp

  


ipv6Tests :: [Test]
ipv6Tests = [
  testProperty "IPv6: Default" testIPv6Default,
  testProperty "IPv6 Packet 0" testIPv6Pkt0,
  testProperty "IPv6 in IPv6" testIPv6InIPv6,
  testProperty "IPv6 Write" testIPv6Write,
  testProperty "IPv6 Pesudo Write" testIPv6PseudoWrite
  ]

#endif



