{-# LANGUAGE CPP #-}

module Gtp where

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

parseGtpPkt :: Parser Packet -> Parser GtpPkt
parseGtpPkt f = permute
  (tuple <$?> (0x32, parseIntAttribute "flags")
         <|?> (0xff, try $ parseIntAttribute "type")
         <|?> (0, parseIntAttribute "len")
         <|?> (0x012345678, try $ parseIntAttribute "teid")
         <|?> (0, parseIntAttribute "seq")
         <|?> (0, try $ parseIntAttribute "npdu")
         <|?> (0, try $ parseIntAttribute "nh")
         <|?> ([PPayload defaultPayload], parsePayload f))
  where
    tuple fl t l teid s np nh = GtpPkt (Gtp fl t l teid s np nh)


gtpDecl :: Parser Packet -> Parser Packet
gtpDecl f = do
  symbol "gtp"
  g <- parseGtpPkt f
  return (PGtp g)

gtpWriteHdr :: Gtp -> Put
gtpWriteHdr p = do
    putWord8 (gtpFlags p)
    putWord8 (gtpType p)
    putWord16be (gtpLen p)
    putWord32be (gtpTeid p)
    putWord16be (gtpSeq p)
    putWord8 (gtpNpdu p)
    putWord8 (gtpNh p)

gtpWrite :: Gtp -> Maybe Packet -> B.ByteString -> Put
gtpWrite h _ bs = do
    gtpWriteHdr h {gtpLen = fromIntegral $ B.length bs}
    putLazyByteString bs

instance PacketWriteable GtpPkt where packetWrite p = gtpWrite (gtpPktHeader p)


#ifdef HRWS_TEST
{- Unit Tests -}

instance Arbitrary Gtp where
  arbitrary = do
    f    <- arbitrary
    t    <- arbitrary
    l    <- arbitrary
    teid <- arbitrary
    s    <- arbitrary
    np   <- arbitrary
    nh   <- arbitrary
    return (Gtp f t l teid s np nh)

testValidParse :: String -> (Gtp -> Bool) -> Bool
testValidParse str fn =
  case parse (dummyParsePacket gtpDecl) "packet parse" str of
       Left  err -> trace (show err) False
       Right val -> fn $ testGtpPkt val

testGtpPkt :: Packet -> Gtp
testGtpPkt (PGtp p) = gtpPktHeader p
testGtpPkt _ = error "Unexpected packet type"

testGtpDefault :: () -> Bool
testGtpDefault _ =
  let cmp p = defaultGtp == p in
  testValidParse "(gtp)" cmp

testGtpPacket :: Gtp -> Bool
testGtpPacket pkt =
  let cmp p = pkt == p in
  testValidParse (printf "(gtp flags=%d type=%d len=%d teid=%d seq=%d npdu=%d nh=%d)"
                  (gtpFlags pkt) (gtpType pkt) (gtpLen pkt) (gtpTeid pkt) (gtpSeq pkt)
                  (gtpNpdu pkt) (gtpNh pkt)) cmp

testGtpWrite :: () -> Bool
testGtpWrite _ =
  let expPkt = B.pack [0x32, 0xff, 0x00, 0x0, 0xcc, 0xcc, 0xcc, 0xcc, 0x00, 0x03, 0x02, 0x00] in
  let cmp p = runPut (gtpWrite p Nothing B.empty) == expPkt in
  testValidParse "(gtp flags=0x32 type=0xff len=0 teid=0xcccccccc seq=3 npdu=2 nh=0)" cmp

gtpTests :: [Test]
gtpTests = [
  testProperty "GTP: Default" testGtpDefault,
  testProperty "GTP: Packet" testGtpPacket,
  testProperty "GTP: Write" testGtpWrite
  ]

#endif
