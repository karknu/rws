{-# LANGUAGE CPP #-}

module HexPayload where

import Data.Binary.Put
import Data.Bits
import Data.Char
import Data.Word
import Text.ParserCombinators.Parsec
import Text.ParserCombinators.Parsec.Perm

import Packet
import Lexer

#ifdef HRWS_TEST
import qualified Data.ByteString.Lazy as B
import Debug.Trace
import Test.QuickCheck hiding ((.&.))
import Test.Framework (Test)
import Test.Framework.Providers.QuickCheck2 (testProperty)
import Text.Printf
import Util
#endif

hexByte :: Parser Word8
hexByte = do
  h1 <- hexDigit
  h2 <- hexDigit
  let w = digitToInt h1 `shiftL` 4 .|. digitToInt h2
  return (fromIntegral w)


parseHexData :: Parser [Word8]
parseHexData = do
  symbol "data"
  symbol "="
  many hexByte

hexPayloadPkt :: Parser Packet -> Parser HexPayload
hexPayloadPkt _ = permute
  (tuple <$?> (replicate 64 0, parseHexData))
  where
    tuple = HexPayload

hexPayloadDecl :: Parser Packet -> Parser Packet
hexPayloadDecl f = do
  symbol "hex"
  p <- hexPayloadPkt f
  return (PHexPayload p)

hexPayloadWrite :: HexPayload -> Put
hexPayloadWrite p =
  mapM_ putWord8 (hexPayloadData p)

instance PacketWriteable HexPayload where packetWrite p _ _= hexPayloadWrite p

#ifdef HRWS_TEST
{- Unit Tests -}

instance Arbitrary HexPayload where
  arbitrary = do
    d <- arbitrary
    l <- choose (1, 16)
    return (HexPayload (replicate (2*l) d))

testHexPayloadString :: HexPayload -> String
testHexPayloadString h =
  concatMap (printf "%02x") (hexPayloadData h)

testValidParse :: String -> (HexPayload -> Bool) -> Bool
testValidParse str fn =
  case parse (dummyParsePacket hexPayloadDecl) "packet parse" str of
       Left  err -> trace (show err) False
       Right val -> fn $ testHexPayloadPkt val

testHexPayloadPkt :: Packet -> HexPayload
testHexPayloadPkt (PHexPayload p) = p
testHexPayloadPkt _ = error "Unexpected packet type"

testHexPayloadDefault :: () -> Bool
testHexPayloadDefault _ =
  let cmp p = defaultHexPayload == p in
  testValidParse "(hex)" cmp

testHexPayloadPacket :: HexPayload -> Bool
testHexPayloadPacket pkt =
  let cmp p = pkt == p in
  testValidParse (printf "(hex data=%s)" (testHexPayloadString pkt)) cmp

testHexPayloadWrite :: () -> Bool
testHexPayloadWrite _ =
  let expPkt = B.pack [0x80, 0x00, 0xb1, 0x4c, 0xca, 0xfe, 0xba, 0xbe] in
  let cmp p = runPut (hexPayloadWrite p) == expPkt in
  testValidParse "(hex data=8000b14ccafebabe)" cmp

hexPayloadTests :: [Test]
hexPayloadTests = [
  testProperty "HexPayload: Default" testHexPayloadDefault,
  testProperty "HexPayload: Packet" testHexPayloadPacket,
  testProperty "HexPayload: Write" testHexPayloadWrite
  ]
#endif

