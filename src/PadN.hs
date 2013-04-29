{-# LANGUAGE CPP #-}
module PadN where

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

parsePadNPkt :: Parser Packet -> Parser PadNPkt
parsePadNPkt f = permute
  (tuple <$?> (1, parseIntAttribute "code")
         <|?> (0, try (parseIntAttribute "len"))
         <|?> ([PPayload defaultPayload], parsePayload f))
  where
    tuple nh l = PadNPkt (PadN nh l)


padNDecl :: Parser Packet -> Parser Packet
padNDecl f = do
  symbol "padn"
  g <- parsePadNPkt f
  return (PPadN g)

padNWriteHdr :: PadN -> Put
padNWriteHdr p = do
    putWord8 $ padNCode p
    putWord8 $ padNLen p
    let bs = B.replicate (fromIntegral $ padNLen p) 0
    putLazyByteString bs

padNWrite :: PadN -> Maybe Packet -> B.ByteString -> Put
padNWrite h _ bs = do
  padNWriteHdr h
  putLazyByteString bs

instance PacketWriteable PadNPkt where packetWrite p = padNWrite $ padNPktHeader p

#ifdef HRWS_TEST
{- Unit Tests -}

instance Arbitrary PadN where
  arbitrary = do
    c <- arbitrary
    l <- arbitrary
    return (PadN c l)

testValidParse :: String -> (PadN -> Bool) -> Bool
testValidParse str fn =
  case parse (dummyParsePacket padNDecl) "packet parse" str of
       Left  err -> trace (show err) False
       Right val -> fn $ testPadNPkt val

testPadNDefault :: () -> Bool
testPadNDefault _ = let cmp f = defaultPadN == f in
  testValidParse "(padn)" cmp

testPadNPkt :: Packet -> PadN
testPadNPkt (PPadN f) = padNPktHeader f
testPadNPkt _ = error "Unexpected packet type"

testPadNPacket :: PadN -> Bool
testPadNPacket pkt =
  let cmp p = pkt == p in
  testValidParse (printf "(padn code=%d len=%d)" (padNCode pkt) (padNLen pkt)) cmp

testPadNWrite :: () -> Bool
testPadNWrite _ =
  let expPkt = B.pack [0x01, 0x04, 0x00, 0x00, 0x00, 0x00] in
  let cmp p = runPut (padNWrite p Nothing B.empty) == expPkt in
  testValidParse "(padn len=4)" cmp

padNTests :: [Test]
padNTests = [
  testProperty "GRE: Default Packet" testPadNDefault,
  testProperty "GRE: Packet" testPadNPacket,
  testProperty "GRE: Write" testPadNWrite
  ]
#endif


