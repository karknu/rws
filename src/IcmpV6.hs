{-# LANGUAGE CPP #-}
module IcmpV6 where

import Control.Monad
import Data.Binary.Put
import qualified Data.ByteString.Lazy as B
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
import Text.Printf
#endif

parseIcmpV6Pkt :: Parser Packet -> Parser IcmpV6Pkt
parseIcmpV6Pkt f = permute
  (tuple <$?> (8, parseIntAttribute "type")
         <|?> (0, try (parseIntAttribute "code"))
         <|?> (0, try (parseIntAttribute "csum"))
         <|?> (0xffffffff, try (parseIntAttribute "pad"))
         <|?> (True, parseBoolAttribute "fixcsum")
         <|?> ([PPayload defaultPayload], parsePayload f))
  where
    tuple t c cs pad fc = IcmpV6Pkt (IcmpV6 t c cs pad fc)


icmpV6Decl :: Parser Packet -> Parser Packet
icmpV6Decl f = do
  symbol "icmpv6"
  g <- parseIcmpV6Pkt f
  return (PIcmpV6 g)

icmpV6WriteHdr :: IcmpV6 -> Put
icmpV6WriteHdr p = do
    putWord8 $ icmpV6Type p
    putWord8 $ icmpV6Code p
    putWord16be $ icmpV6Csum p
    when (icmpV6Pad p /= 0xffffffff) $ putWord32be $ icmpV6Pad p

icmpV6Write :: IcmpV6 -> Maybe Packet -> B.ByteString -> Put
icmpV6Write h mp bs = do
  let hdrLen = if icmpV6Pad h /= 0xffffffff
                  then 8
                  else 4
  let len = hdrLen + fromIntegral (B.length bs)
  let csum = if icmpV6CorrectCsum h
                then let sum32 = csumAdd (B.unpack $ runPut $ icmpV6WriteHdr h) $ genPseudoSum mp len in
                     csumFin $ csumAdd (B.unpack bs) sum32
                else icmpV6Csum h

  icmpV6WriteHdr h {icmpV6Csum = csum}
  putLazyByteString bs

instance PacketWriteable IcmpV6Pkt where packetWrite p = icmpV6Write $ icmpV6PktHeader p


#ifdef HRWS_TEST
{- Unit Tests -}

instance Arbitrary IcmpV6 where
  arbitrary = do
    t   <- arbitrary
    c   <- arbitrary
    cs  <- arbitrary
    pad <- arbitrary
    return (IcmpV6 t c cs pad True)

testValidParse :: String -> (IcmpV6 -> Bool) -> Bool
testValidParse str fn =
  case parse (dummyParsePacket icmpV6Decl) "packet parse" str of
       Left  err -> trace (show err) False
       Right val -> fn $ testIcmpV6Pkt val

testIcmpV6Pkt :: Packet -> IcmpV6
testIcmpV6Pkt (PIcmpV6 p) = icmpV6PktHeader p
testIcmpV6Pkt _ = error "Unexpected packet type"

testIcmpV6Default :: () -> Bool
testIcmpV6Default _ =
  let cmp p = defaultIcmpV6 == p in
  testValidParse "(icmpv6)" cmp

testIcmpV6Packet :: IcmpV6 -> Bool
testIcmpV6Packet pkt =
  let cmp p = pkt == p in
  testValidParse (printf "(icmpv6 type=%d code=%d csum=%d pad=%d)" (icmpV6Type pkt)
                  (icmpV6Code pkt) (icmpV6Csum pkt) (icmpV6Pad pkt)) cmp

testIcmpV6Write :: () -> Bool
testIcmpV6Write _ =
  let expPkt = B.pack [0x80, 0x00, 0xb1, 0x4c, 0xca, 0xfe, 0xba, 0xbe] in
  let cmp p = runPut (icmpV6Write p Nothing B.empty) == expPkt in
  testValidParse "(icmpv6 type=128 code=0 pad=0xcafebabe csum=0xb14c fixcsum=false)" cmp

icmpV6Tests :: [Test]
icmpV6Tests = [
  testProperty "ICMPv6: Default" testIcmpV6Default,
  testProperty "ICMPv6: Packet" testIcmpV6Packet,
  testProperty "ICMPv6: Write" testIcmpV6Write
  ]
#endif
