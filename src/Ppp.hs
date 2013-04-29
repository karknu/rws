{-# LANGUAGE CPP #-}
module Ppp where

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

parsePppPkt :: Parser Packet -> Parser PppPkt
parsePppPkt f = permute
  (tuple <$?> (0xff, parseIntAttribute "address")
         <|?> (0x03, parseIntAttribute "control")
         <|?> (0x0021, parseIntAttribute "protocol")
         <|?> ([PPayload defaultPayload], parsePayload f))
  where
    tuple a c prot = PppPkt (Ppp a c prot)


pppDecl :: Parser Packet -> Parser Packet
pppDecl f = do
  symbol "ppp"
  g <- parsePppPkt f
  return (PPpp g)

pppWriteHdr :: Ppp -> Put
pppWriteHdr p = do
    putWord8 (pppAddress p)
    putWord8 (pppControl p)
    putWord16be (pppProtocol p)

pppWrite :: Ppp -> Maybe Packet -> B.ByteString -> Put
pppWrite h _ bs = do
    pppWriteHdr h
    putLazyByteString bs

instance PacketWriteable PppPkt where packetWrite p = pppWrite (pppPktHeader p)


#ifdef HRWS_TEST
{- Unit Tests -}

instance Arbitrary Ppp where
  arbitrary = do
    a <- arbitrary
    c <- arbitrary
    p <- arbitrary
    return (Ppp a c p)

testValidParse :: String -> (Ppp -> Bool) -> Bool
testValidParse str fn =
  case parse (dummyParsePacket pppDecl) "packet parse" str of
       Left  err -> trace (show err) False
       Right val -> fn $ testPppPkt val

testPppDefault :: () -> Bool
testPppDefault _ = let cmp f = defaultPpp == f in
  testValidParse "(ppp)" cmp

testPppPkt :: Packet -> Ppp
testPppPkt (PPpp f) = pppPktHeader f
testPppPkt _ = error "Unexpected packet type"

testPppPacket :: Ppp -> Bool
testPppPacket pkt =
  let cmp p = pkt == p in
  testValidParse (printf "(ppp address=%d control=%d protocol=%d)" (pppAddress pkt)
                  (pppControl pkt) (pppProtocol pkt)) cmp

testPppWrite :: () -> Bool
testPppWrite _ =
  let expPkt = B.pack [0xff, 0x03, 0xca, 0xfe] in
  let cmp p = runPut (pppWrite p Nothing B.empty) == expPkt in
  testValidParse "(ppp address=0xff protocol=0xcafe)" cmp

pppTests :: [Test]
pppTests = [
  testProperty "PPP: Default Packet" testPppDefault,
  testProperty "PPP: Packet" testPppPacket,
  testProperty "PPP: Write" testPppWrite
  ]
#endif

