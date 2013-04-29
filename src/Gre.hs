{-# LANGUAGE CPP #-}
module Gre where

import Control.Monad
import Data.Binary.Put
import Data.Bits
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

parseGrePkt :: Parser Packet -> Parser GrePkt
parseGrePkt f = permute
  (tuple <$?> (0x3000, parseIntAttribute "flags")
         <|?> (0x0800, parseIntAttribute "protocol")
         <|?> (0xcafecafe, parseIntAttribute "key")
         <|?> (0, try (parseIntAttribute "seq"))
         <|?> ([PPayload defaultPayload], parsePayload f))
  where
    tuple fl prot k s =
        GrePkt (Gre fl prot k s)


greDecl :: Parser Packet -> Parser Packet
greDecl f = do
  symbol "gre"
  g <- parseGrePkt f
  return (PGre g)

greWriteHdr :: Gre -> Put
greWriteHdr p = do
    putWord16be (greFlags p)
    putWord16be (greProtocol p)
    -- Optional Key Field
    when (greFlags p .&. 0x2000 == 0x2000) $
      putWord32be $ greKey p
    when (greFlags p .&. 0x1000 == 0x1000) $
      putWord32be $ greSeq p

greWrite :: Gre -> Maybe Packet -> B.ByteString -> Put
greWrite h _ bs = do
    greWriteHdr h
    putLazyByteString bs

instance PacketWriteable GrePkt where packetWrite p = greWrite (grePktHeader p)


#ifdef HRWS_TEST
{- Unit Tests -}

instance Arbitrary Gre where
  arbitrary = do
    f <- arbitrary
    p <- arbitrary
    k <- arbitrary
    s <- arbitrary
    return (Gre f p k s)

testValidParse :: String -> (Gre -> Bool) -> Bool
testValidParse str fn =
  case parse (dummyParsePacket greDecl) "packet parse" str of
       Left  err -> trace (show err) False
       Right val -> fn $ testGrePkt val

testGreDefault :: () -> Bool
testGreDefault _ = let cmp f = defaultGre == f in
  testValidParse "(gre)" cmp

testGrePkt :: Packet -> Gre
testGrePkt (PGre f) = grePktHeader f
testGrePkt _ = error "Unexpected packet type"

testGrePacket :: Gre -> Bool
testGrePacket pkt =
  let cmp p = pkt == p in
  testValidParse (printf "(gre flags=%d protocol=%d key=%d seq=%d)" (greFlags pkt)
                  (greProtocol pkt) (greKey pkt) (greSeq pkt)) cmp

testGreWrite :: () -> Bool
testGreWrite _ =
  let expPkt = B.pack [0x30, 0x00, 0x08, 0x00, 0x12, 0x34, 0x56, 0x78, 0xaa, 0xaa, 0xaa, 0xaa] in
  let cmp p = runPut (greWrite p Nothing B.empty) == expPkt in
  testValidParse "(gre flags=0x3000 protocol=0x0800 key=0x12345678 seq=0xaaaaaaaa)" cmp

greTests :: [Test]
greTests = [
  testProperty "GRE: Default Packet" testGreDefault,
  testProperty "GRE: Packet" testGrePacket,
  testProperty "GRE: Write" testGreWrite
  ]
#endif

