{-# LANGUAGE CPP #-}
module Fragv6 where

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
#endif


parseFragv6Pkt :: Parser Packet -> Parser Fragv6Pkt
parseFragv6Pkt f = permute
  (tuple <$?> (17, parseIntAttribute "nh")
         <|?> (0, try (parseIntAttribute "res"))
         <|?> (0, try (parseIntAttribute "off"))
         <|?> (0, try (parseIntAttribute "id"))
         <|?> ([PPayload defaultPayload], parsePayload f))
  where
    tuple nh r o i =
        Fragv6Pkt (Fragv6 nh r o i)

fragv6Decl :: Parser Packet -> Parser Packet
fragv6Decl f = do
  symbol "fragv6"
  g <- parseFragv6Pkt f
  return (PFragv6 g)

fragv6WriteHdr :: Fragv6 -> Put
fragv6WriteHdr p = do
    putWord8 $ fragv6Nh p
    putWord8 $ fragv6Res p
    putWord16be $ fragv6Off p
    putWord32be $ fragv6Id p

fragv6Write :: Fragv6 -> Maybe Packet -> B.ByteString -> Put
fragv6Write h _ bs = do
  fragv6WriteHdr h
  putLazyByteString bs

instance PacketWriteable Fragv6Pkt where packetWrite p = fragv6Write $ fragv6PktHeader p

#ifdef HRWS_TEST
{- Unit Tests -}

instance Arbitrary Fragv6 where
  arbitrary = do
    nh  <- arbitrary
    res <- arbitrary
    off <- arbitrary
    i   <- arbitrary
    return (Fragv6 nh res off i)

testValidParse :: String -> (Fragv6 -> Bool) -> Bool
testValidParse str fn =
  case parse (dummyParsePacket fragv6Decl) "packet parse" str of
       Left  err -> trace (show err) False
       Right val -> fn $ testFragv6Pkt val

testFragv6Pkt :: Packet -> Fragv6
testFragv6Pkt (PFragv6 p) = fragv6PktHeader p
testFragv6Pkt _ = error "Unexpected packet type"

testFragv6Default :: () -> Bool
testFragv6Default _ = let cmp f = defaultFragv6 == f in
  testValidParse "(fragv6)" cmp

testFragv6Pkt0 :: Fragv6 -> Bool
testFragv6Pkt0 f = let cmp a = f == a in
   testValidParse ("(fragv6 nh=" ++ show (fragv6Nh f) ++ " res=" ++ show (fragv6Res f) ++
                  " off=" ++ show (fragv6Off f) ++ " id=" ++ show (fragv6Id f) ++ ")") cmp

testFragv6Write :: () -> Bool
testFragv6Write  _ =
  let expFrag = B.pack [0x11, 0x00, 0x00, 0x40, 0xff, 0xff, 0xff, 0xff] in
  let cmp f = runPut (fragv6Write f Nothing B.empty) == expFrag in
  testValidParse "(fragv6 nh=17 off =64 id=0xffffffff)" cmp

fragv6Tests :: [Test]
fragv6Tests = [
  testProperty "Fragv6: Default" testFragv6Default,
  testProperty "Fragv6: Frag0" testFragv6Pkt0,
  testProperty "Fragv6: Write" testFragv6Write
  ]
#endif

