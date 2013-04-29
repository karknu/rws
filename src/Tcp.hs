{-# LANGUAGE CPP #-}
module Tcp where

import Control.Monad
import Data.Binary.Put
import Data.Bits
import qualified Data.ByteString.Lazy as B
import Data.Word
import Text.ParserCombinators.Parsec
import Text.ParserCombinators.Parsec.Perm

import Packet
import Lexer
import PseudoSum
import Util

#ifdef HRWS_TEST
import Debug.Trace
import Test.QuickCheck hiding ((.&.))
import Test.Framework (Test)
import Test.Framework.Providers.QuickCheck2 (testProperty)
#endif

finFlag :: Word16
finFlag = 0x0001 :: Word16
synFlag :: Word16
synFlag = 0x0002 :: Word16
rstFlag :: Word16
rstFlag = 0x0004 :: Word16
pshFlag :: Word16
pshFlag = 0x0008 :: Word16
ackFlag :: Word16
ackFlag = 0x0010 :: Word16
urgFlag :: Word16
urgFlag = 0x0020 :: Word16
ecneFlag :: Word16
ecneFlag = 0x0040 :: Word16
cwrFlag :: Word16
cwrFlag = 0x0080 :: Word16

parseTcpFlag :: String -> Word16 -> Parser Word16
parseTcpFlag s f = do
    reserved s
    return f


parseTcpPkt :: Parser Packet -> Parser TcpPkt
parseTcpPkt f = permute
  (tuple <$?> (7, try $ parseIntAttribute "src")
         <|?> (7, parseIntAttribute "dst")
         <|?> (0, try $ parseIntAttribute "seqno")
         <|?> (0, try $ parseIntAttribute "ackno")
         <|?> (0, try $ parseIntAttribute "flags")
         <|?> (0xffff, parseIntAttribute "win")
         <|?> (0, try $ parseIntAttribute "csum")
         <|?> (0, try $ parseIntAttribute "urgno")
         <|?> (20, parseIntAttribute "offset") -- in bytes
         <|?> (0x0, try $ parseTcpFlag "fin" finFlag)
         <|?> (0x0, try $ parseTcpFlag "syn" synFlag)
         <|?> (0x0, parseTcpFlag "rst" rstFlag)
         <|?> (0x0, parseTcpFlag "psh" pshFlag)
         <|?> (0x0, try $ parseTcpFlag "ack" ackFlag)
         <|?> (0x0, try $ parseTcpFlag "urg" urgFlag)
         <|?> (0x0, parseTcpFlag "ecne" ecneFlag)
         <|?> (0x0, try $ parseTcpFlag "cwr" cwrFlag)
         <|?> (True, try $ parseBoolAttribute "fixcsum")
         <|?> (0x0, try $ parseIntAttribute "wsc")
         <|?> (0x0, try $ parseIntAttribute "ts")
         <|?> ([PPayload (Payload 0 0)], parsePayload f))
  where
    tuple s d sq ack fl win c u hl ff sf rf pf af uf ef cf fc wsc ts =
        TcpPkt (Tcp s d sq ack
                 (fl .|. ff .|. sf .|. rf .|. af .|. pf .|. uf .|. ef .|.
                  cf .|. (fromIntegral hl `shiftL` 10))
                 win c u hl fc wsc ts)

tcpDecl :: Parser Packet -> Parser Packet
tcpDecl f = do
 symbol "tcp"
 u <- parseTcpPkt f
 return (PTcp u)

tcpWriteHdr :: Tcp -> Put
tcpWriteHdr p = do
    putWord16be (tcpSrc p)
    putWord16be (tcpDst p)
    putWord32be (tcpSeqNo p)
    putWord32be (tcpAckNo p)
    putWord16be (tcpFlags p)
    putWord16be (tcpWin p)
    putWord16be (tcpCsum p)
    putWord16be (tcpUrg p)
    when (tcpWindowScale p /= 0) $
      do
        putWord8 3; -- Kind = Window Scale
        putWord8 3; -- Len = 3
        putWord8 (tcpWindowScale p); -- Shift Count
        putWord8 0; -- End of Option List

    when (tcpTimeStamp p /= 0) $
       do
         putWord8 8  -- Kind = timestamp
         putWord8 10 -- len = 10
         putWord64be (tcpTimeStamp p)
         putWord8 1  -- no option
         putWord8 0  -- end of option list

tcpWrite :: Tcp -> Maybe Packet -> B.ByteString -> Put
tcpWrite h mp bs = do
  let len = shiftR (tcpFlags h)  12 * 4 + fromIntegral (B.length bs)
  let csum = if tcpCorrectCsum h
                then let sum32 = csumAdd (B.unpack $ runPut $ tcpWriteHdr h) $ genPseudoSum mp len in
                     csumFin $ csumAdd (B.unpack bs) sum32
                else tcpCsum h
  tcpWriteHdr h {tcpCsum = csum}
  putLazyByteString bs

instance PacketWriteable TcpPkt where packetWrite p = tcpWrite (tcpPktHeader p)

#ifdef HRWS_TEST
{- Unit Tests -}


instance Arbitrary Tcp where
  arbitrary = do
    src   <- arbitrary
    dst   <- arbitrary
    sq    <- arbitrary
    ack   <- arbitrary
    flags <- arbitrary
    win   <- arbitrary
    csum  <- arbitrary
    urg   <- arbitrary
    return (Tcp src dst sq ack flags win csum urg 0 True 0 0)

testValidParse :: String -> (Tcp -> Bool) -> Bool
testValidParse str fn =
  case parse (dummyParsePacket tcpDecl) "packet parse" str of
       Left  err -> trace (show err) False
       Right val -> fn $ testTcpPkt val

testTcpPkt :: Packet -> Tcp
testTcpPkt (PTcp p) = tcpPktHeader p
testTcpPkt _ = error "Unexpected packet type"

testTcpDefault :: () -> Bool
testTcpDefault _ = let cmp f = defaultTcp == f in
  testValidParse "(tcp)" cmp

testTcpPkt0 :: Tcp -> Bool
testTcpPkt0 p = let cmp f = p == f in
  testValidParse ("(tcp offset=0 src=" ++ show (tcpSrc p) ++ " dst=" ++ show (tcpDst p) ++
                  " seqno=" ++ show (tcpSeqNo p) ++ " ackno=" ++ show (tcpAckNo p) ++
                  " flags=" ++ show (tcpFlags p) ++ " win=" ++ show (tcpWin p) ++ " csum=" ++
                  show (tcpCsum p) ++ " urgno=" ++ show (tcpUrg p) ++ ")") cmp

testTcpWrite :: () -> Bool
testTcpWrite _ =
  let expPkt = B.pack [0x04, 0xd2, 0x00, 0x07, 0x00, 0x00, 0x00, 0x0a,
                       0x00, 0x00, 0x03, 0xf1, 0x50, 0x11, 0xff, 0xff,
                       0x24, 0x7b, 0x00, 0x00] in
  let cmp p = runPut (tcpWrite p Nothing B.empty) == expPkt in
  testValidParse "(tcp src=1234 fin ack seqno=10 ackno=1009 csum=0x247b fixcsum=false)" cmp


tcpTests :: [Test]
tcpTests = [
  testProperty "TCP: Default Packet" testTcpDefault,
  testProperty "TCP: Packet 0" testTcpPkt0,
  testProperty "TCP: Write" testTcpWrite
  ]

#endif




