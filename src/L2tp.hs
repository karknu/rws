{-# LANGUAGE CPP #-}
module L2tp where

import Control.Monad
import Data.Binary.Put
import Data.Bits
import Text.ParserCombinators.Parsec
import qualified Data.ByteString.Lazy as B
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

parseL2tpPkt :: Parser Packet -> Parser L2tpPkt
parseL2tpPkt f = permute
  (tuple <$?> (0x0002, parseIntAttribute "flags")
         <|?> (0, parseIntAttribute "length")
         <|?> (0x1234, parseIntAttribute "tid")
         <|?> (0x5678, parseIntAttribute "sid")
         <|?> (0, try (parseIntAttribute "ns"))
         <|?> (0, try (parseIntAttribute "nr"))
         <|?> (0, parseIntAttribute "offset")
         <|?> (True, parseBoolAttribute "addoffset")
         <|?> ([PPayload defaultPayload], parsePayload f))
  where
    tuple fl l tid sid ns nr offset ao =
        L2tpPkt (L2tp fl l tid sid ns nr offset ao)


l2tpDecl :: Parser Packet -> Parser Packet
l2tpDecl f = do
  symbol "l2tp"
  g <- parseL2tpPkt f
  return (PL2tp g)

l2tpWriteHdr :: L2tp -> Put
l2tpWriteHdr p = do
    putWord16be (l2tpFlags p)
    -- Optional Length Field
    when (l2tpFlags p .&. 0x4000 == 0x4000) $
      putWord16be $ l2tpLength p
    putWord16be (l2tpTid p)
    putWord16be (l2tpSid p)
    -- Optional Ns and Nr Field
    when (l2tpFlags p .&. 0x0800 == 0x0800) $
      do
        putWord16be (l2tpNs p)
        putWord16be (l2tpNr p)
    -- Optional Offset Size Field XXX add actual offset
    when (l2tpFlags p .&. 0x0200 == 0x0200) $
      do
        putWord16be (l2tpOffset p)
        when (l2tpCorrectOffset p) $
          putLazyByteString $ B.replicate (fromIntegral (l2tpOffset p)) 0x0

l2tpWrite :: L2tp -> Maybe Packet -> B.ByteString -> Put
l2tpWrite h _ bs = do
  l2tpWriteHdr h {l2tpLength = fromIntegral $ B.length bs}
  putLazyByteString bs

instance PacketWriteable L2tpPkt where packetWrite p = l2tpWrite (l2tpPktHeader p)


#ifdef HRWS_TEST
{- Unit Tests -}

instance Arbitrary L2tp where
  arbitrary = do
    f  <- arbitrary
    l  <- arbitrary
    t  <- arbitrary
    s  <- arbitrary
    ns <- arbitrary
    nr <- arbitrary
    o  <- arbitrary
    return (L2tp f l t s ns nr o True)

testValidParse :: String -> (L2tp -> Bool) -> Bool
testValidParse str fn =
  case parse (dummyParsePacket l2tpDecl) "packet parse" str of
       Left  err -> trace (show err) False
       Right val -> fn $ testL2tpPkt val

testL2tpDefault :: () -> Bool
testL2tpDefault _ = let cmp f = defaultL2tp == f in
  testValidParse "(l2tp)" cmp

testL2tpPkt :: Packet -> L2tp
testL2tpPkt (PL2tp f) = l2tpPktHeader f
testL2tpPkt _ = error "Unexpected packet type"

testL2tpPacket :: L2tp -> Bool
testL2tpPacket pkt =
  let cmp p = pkt == p in
  testValidParse (printf "(l2tp flags=%d length=%d tid=%d sid=%d ns=%d nr=%d offset=%d)"
                  (l2tpFlags pkt) (l2tpLength pkt) (l2tpTid pkt) (l2tpSid pkt)
                  (l2tpNs pkt) (l2tpNr pkt) (l2tpOffset pkt)) cmp

testL2tpWrite :: () -> Bool
testL2tpWrite _ =
  let expPkt = B.pack [0x00, 0x02, 0xb0, 0xb1, 0xc1, 0xc2] in
  let cmp p = runPut (l2tpWrite p Nothing B.empty) == expPkt in
  testValidParse "(l2tp flags=0x2 tid=0xb0b1 sid=0xc1c2)" cmp

l2tpTests :: [Test]
l2tpTests = [
  testProperty "L2TP: Default Packet" testL2tpDefault,
  testProperty "L2TP: Packet" testL2tpPacket,
  testProperty "L2TP: Write" testL2tpWrite
  ]
#endif

