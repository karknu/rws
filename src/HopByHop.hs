{-# LANGUAGE CPP #-}
module HopByHop where

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


parseHopByHopPkt :: Parser Packet -> Parser HopByHopPkt
parseHopByHopPkt f = permute
  (tuple <$?> (17, parseIntAttribute "nh")
         <|?> (0, try (parseIntAttribute "len"))
         <|?> ([PPayload defaultPayload], parsePayload f))
  where
    tuple nh l = HopByHopPkt (HopByHop nh l)


hopByHopDecl :: Parser Packet -> Parser Packet
hopByHopDecl f = do
  symbol "hopbyhop"
  g <- parseHopByHopPkt f
  return (PHopByHop g)

hopByHopWriteHdr :: HopByHop -> Put
hopByHopWriteHdr p = do
    putWord8 $ hopByHopNh p
    putWord8 $ hopByHopLen p

hopByHopWrite :: HopByHop -> Maybe Packet -> B.ByteString -> Put
hopByHopWrite h _ bs = do
  hopByHopWriteHdr h
  putLazyByteString bs

instance PacketWriteable HopByHopPkt where packetWrite p = hopByHopWrite $ hopByHopPktHeader p


#ifdef HRWS_TEST
{- Unit Tests -}

instance Arbitrary HopByHop where
  arbitrary = do
    nh   <- arbitrary
    l    <- arbitrary
    return (HopByHop nh l)

testValidParse :: String -> (HopByHop -> Bool) -> Bool
testValidParse str fn =
  case parse (dummyParsePacket hopByHopDecl) "packet parse" str of
       Left  err -> trace (show err) False
       Right val -> fn $ testHopByHopPkt val

testHopByHopPkt :: Packet -> HopByHop
testHopByHopPkt (PHopByHop p) = hopByHopPktHeader p
testHopByHopPkt _ = error "Unexpected packet type"

testHopByHopDefault :: () -> Bool
testHopByHopDefault _ =
  let cmp p = defaultHopByHop == p in
  testValidParse "(hopbyhop)" cmp

testHopByHopPacket :: HopByHop -> Bool
testHopByHopPacket pkt =
  let cmp p = pkt == p in
  testValidParse (printf "(hopbyhop nh=%d len=%d)" (hopByHopNh pkt)
                  (hopByHopLen pkt)) cmp

testHopByHopWrite :: () -> Bool
testHopByHopWrite _ =
  let expPkt = B.pack [0x11, 0x00] in
  let cmp p = runPut (hopByHopWrite p Nothing B.empty) == expPkt in
  testValidParse "(hopbyhop nh=17 len=0)" cmp

hopByHopTests :: [Test]
hopByHopTests = [
  testProperty "HopByHop: Default" testHopByHopDefault,
  testProperty "HopByHop: Packet" testHopByHopPacket,
  testProperty "HopByHop: Write" testHopByHopWrite
  ]

#endif
