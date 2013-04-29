{-# LANGUAGE CPP #-}
module Ethernet where

import Data.Binary.Put
import Data.Bits
import qualified Data.ByteString.Lazy as B
import Data.Char
import Data.Word
import Text.ParserCombinators.Parsec
import Text.ParserCombinators.Parsec.Perm

import Packet
import Lexer
import Util

#ifdef HRWS_TEST
import Debug.Trace
import Test.QuickCheck hiding ((.&.))
import Test.Framework (Test)
import Test.Framework.Providers.QuickCheck2 (testProperty)
#endif

macAddressPart :: Parser Word8
macAddressPart = do
  h1 <- hexDigit
  h2 <- hexDigit
  char ':'
  let w = digitToInt h1 `shiftL` 4 .|. digitToInt h2
  return (fromIntegral w)

macAddressPart' :: Parser Word8
macAddressPart' = do
  h1 <- hexDigit
  h2 <- hexDigit
  let w = digitToInt h1 `shiftL` 4 .|. digitToInt h2
  return (fromIntegral w)

macAddressDecl :: Parser MacAddress
macAddressDecl = do
  h0 <- macAddressPart
  h1 <- macAddressPart
  h2 <- macAddressPart
  h3 <- macAddressPart
  h4 <- macAddressPart
  h5 <- macAddressPart'
  return (MacAddress h0 h1 h2 h3 h4 h5)

parseMacAddress :: String -> Parser MacAddress
parseMacAddress s = do
  symbol s
  symbol "="
  a <- macAddressDecl
  whiteSpace
  return a

parseEthFrame :: Parser Packet -> Parser EthernetFrame
parseEthFrame f = permute
  (tuple <$?> (MacAddress 0 0 0 0 0 1, parseMacAddress "dst" )
         <|?> (MacAddress 0 0 0 0 0 2, parseMacAddress "src" )
         <|?> (0x800, parseIntAttribute "type")
         <|?> ([PPayload defaultPayload], parsePayload f))
  where
    tuple a b c = EthernetFrame (Ethernet a b c)

ethDecl :: Parser Packet -> Parser Packet
ethDecl f = do
 symbol "eth"
 ef <- parseEthFrame f
 return $ PEth ef

macAddressWrite :: MacAddress -> Put
macAddressWrite a = do
    putWord8 (macAddress0 a)
    putWord8 (macAddress1 a)
    putWord8 (macAddress2 a)
    putWord8 (macAddress3 a)
    putWord8 (macAddress4 a)
    putWord8 (macAddress5 a)

ethernetWriteHdr :: Ethernet -> Put
ethernetWriteHdr f = do
    macAddressWrite (ethernetDst f)
    macAddressWrite (ethernetSrc f)
    putWord16be (ethernetType f)

ethernetWrite :: Ethernet -> Maybe Packet -> B.ByteString -> Put
ethernetWrite h _ bs = do
    ethernetWriteHdr h
    putLazyByteString bs

instance PacketWriteable EthernetFrame where packetWrite f = ethernetWrite (ethernFrameHeader f)

#ifdef HRWS_TEST
{- Unit Tests -}

instance Arbitrary MacAddress where
  arbitrary = do
    w0 <- arbitrary
    w1 <- arbitrary
    w2 <- arbitrary
    w3 <- arbitrary
    w4 <- arbitrary
    w5 <- arbitrary
    return (MacAddress w0 w1 w2 w3 w4 w5)

instance Arbitrary Ethernet where
  arbitrary = do
    dst <- arbitrary
    src <- arbitrary
    t <- arbitrary
    return (Ethernet dst src t)

testValidParse :: String -> (Ethernet -> Bool) -> Bool
testValidParse str fn =
  case parse (dummyParsePacket ethDecl) "packet parse" str of
       Left  err -> trace (show err) False
       Right val -> fn $ testEthFrame val

testInvalidParse :: String -> Bool
testInvalidParse str =
  case parse (dummyParsePacket ethDecl) "packet parse" str of
       Left  _ -> True
       Right _ -> False

testEthDefault :: () -> Bool
testEthDefault _ = let cmp f = defaultEthernet == f in
  testValidParse "(eth)" cmp

testEthFrame :: Packet -> Ethernet
testEthFrame (PEth f) = ethernFrameHeader f
testEthFrame _ = error "Unexpected packet type"

testEthType :: Word16 -> Bool
testEthType t = let cmp f = defaultEthernet {ethernetType = t} == f in
  testValidParse ("(eth type=" ++ show t ++ ")") cmp

testEthDst :: MacAddress -> Bool
testEthDst a =
  let cmp f = defaultEthernet {ethernetDst = a} == f in
  testValidParse ("(eth dst=" ++ show a ++ ")") cmp

testEthSrc :: MacAddress -> Bool
testEthSrc a =
  let cmp f = defaultEthernet {ethernetSrc = a} == f in
  testValidParse ("(eth src=" ++ show a ++ ")") cmp

testEthFrame0 :: Ethernet -> Bool
testEthFrame0 f =
  let cmp a = f == a in
  testValidParse ("(eth dst=" ++ show (ethernetDst f) ++ " src=" ++ show (ethernetSrc f) ++
                  " type=" ++ show (ethernetType f) ++ ")") cmp

testEthInvFrame0 :: () -> Bool
testEthInvFrame0 _ = testInvalidParse "(eth src=asdf)"

testEthInvFrame1 :: () -> Bool
testEthInvFrame1 _ = testInvalidParse "(eth dst=1:2:2 )"

testEthInvFrame2 :: () -> Bool
testEthInvFrame2 _ = testInvalidParse "(eth type=src=banan )"

testEthWrite :: () -> Bool
testEthWrite _ =
  let expFrame = B.pack [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, -- dst
                         0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, -- src
                         0xca, 0xfe] in                      -- type 
  let cmp f = runPut (ethernetWrite f Nothing B.empty) == expFrame in
  testValidParse "(eth dst=00:11:22:33:44:55 src=66:77:88:99:aa:bb type=0xcafe)" cmp

ethTests :: [Test]
ethTests = [
  testProperty "Ethernet: Default Packet" testEthDefault,
  testProperty "Ethernet: Type" testEthType,
  testProperty "Ethernet: Destination" testEthDst,
  testProperty "Ethernet: Source" testEthSrc,
  testProperty "Ethernet: valid frame" testEthFrame0,
  testProperty "Ethernet: invalid frame 0" testEthInvFrame0,
  testProperty "Ethernet: invalid frame 1" testEthInvFrame1,
  testProperty "Ethernet: invalid frame 2" testEthInvFrame2,
  testProperty "Ethernet: Write" testEthWrite
  ]

#endif
