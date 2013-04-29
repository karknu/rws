{-# LANGUAGE CPP #-}
module Udp where

import Data.Binary.Put
import qualified Data.ByteString.Lazy as B
import Data.Word

import Text.ParserCombinators.Parsec
import Text.ParserCombinators.Parsec.Perm

import Lexer
import Packet
import PseudoSum
import Util

#ifdef HRWS_TEST
import Debug.Trace
import Test.QuickCheck hiding ((.&.))
import Test.Framework (Test)
import Test.Framework.Providers.QuickCheck2 (testProperty)
#endif

parseUdpSrc :: Parser Word16
parseUdpSrc = parseIntAttribute "src"

parseUdpDst :: Parser Word16
parseUdpDst = parseIntAttribute "dst"

parseUdpLen :: Parser Word16
parseUdpLen = parseIntAttribute "len"

parseUdpCsum :: Parser Word16
parseUdpCsum = parseIntAttribute "csum"

parseUdpFixCsum :: Parser Bool
parseUdpFixCsum = parseBoolAttribute "fixcsum"

parseUdpPkt :: Parser Packet -> Parser UdpPkt
parseUdpPkt f = permute
  (tuple <$?> (7, parseUdpSrc)
         <|?> (7, parseUdpDst)
         <|?> (8, parseUdpLen)
         <|?> (0, parseUdpCsum)
         <|?> ([PPayload defaultPayload], parsePayload f)
         <|?> (True, parseUdpFixCsum))
  where
    tuple s d l c p fc = UdpPkt (Udp s d l c fc) p

udpDecl :: Parser Packet -> Parser Packet
udpDecl f = do
 symbol "udp"
 u <- parseUdpPkt f
 return (PUdp u)

udpWriteHdr :: Udp -> Put
udpWriteHdr p = do
    putWord16be (udpSrc p)
    putWord16be (udpDst p)
    putWord16be (udpLen p)
    putWord16be (udpCsum p)

udpWrite :: Udp -> Maybe Packet -> B.ByteString -> Put
udpWrite h mp bs = do
    let ulen = fromIntegral $ 8 + B.length bs
    let hdr = h {udpLen = ulen}
    let csum = if udpCorrectCsum hdr
                  then
                    let sum32 = csumAdd (B.unpack $ runPut $ udpWriteHdr hdr) $ genPseudoSum mp ulen in
                    csumFin $ csumAdd (B.unpack bs) sum32
                  else udpCsum hdr
    udpWriteHdr hdr {udpCsum = csum}
    putLazyByteString bs

instance PacketWriteable UdpPkt where packetWrite p = udpWrite (udpPktHeader p)

#ifdef HRWS_TEST
{- Unit Tests -}

instance Arbitrary Udp where
  arbitrary = do
    src <- arbitrary
    dst <- arbitrary
    len <- arbitrary
    csum <- arbitrary
    return (Udp src dst len csum True)

testValidParse :: String -> (Udp -> Bool) -> Bool
testValidParse str fn =
  case parse (dummyParsePacket udpDecl) "packet parse" str of
       Left  err -> trace (show err) False
       Right val -> fn $ testUdpPkt val

testUdpPkt :: Packet -> Udp
testUdpPkt (PUdp p) = udpPktHeader p
testUdpPkt _ = error "Unexpected packet type"

testUdpDefault :: () -> Bool
testUdpDefault _ = let cmp f = defaultUdp == f in
  testValidParse "(udp)" cmp


testUdpPkt0 :: Udp -> Bool
testUdpPkt0 u = let cmp p = u == p in
  testValidParse ("(udp src=" ++ show (udpSrc u) ++ " dst=" ++ show (udpDst u) ++ " len=" ++
                  show (udpLen u) ++ " csum=" ++ show (udpCsum u) ++ " fixcsum=true)") cmp

testUdpWrite :: () -> Bool
testUdpWrite _ =
  let expPkt = B.pack [0x00, 0x08, 0x00, 0x07, 0x00, 0x08, 0xff, 0xc0] in
  let cmp p = runPut (udpWrite p Nothing B.empty) == expPkt in
   testValidParse "(udp dst=7 src=8 len=8 csum=0xffc0 fixcsum=false)" cmp

udpTests :: [Test]
udpTests = [
  testProperty "UDP: default" testUdpDefault,
  testProperty "UDP: Pkt0" testUdpPkt0,
  testProperty "UDP: Write" testUdpWrite
  ]

#endif



