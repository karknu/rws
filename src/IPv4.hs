{-# LANGUAGE CPP #-}
module IPv4 where

import Data.Binary.Put
import Data.Bits
import qualified Data.ByteString.Lazy as B
import Data.Word
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

parseIPv4Pkt :: Parser Packet -> Parser IPv4Pkt
parseIPv4Pkt f = permute
  (tuple <$?> (0xa0a0a0a1, parseIPv4Address "src")
         <|?> (0xa0a0a0a2, parseIPv4Address "dst")
         <|?> (4, parseIntAttribute "ver")
         <|?> (5, parseIntAttribute "hlen")
         <|?> (-1, parseIntAttribute "len")
         <|?> (0x1234, parseIntAttribute "id")
         <|?> (17, parseIntAttribute "prot")
         <|?> (0, try $ parseIntAttribute "tos")
         <|?> (64, try $ parseIntAttribute "ttl")
         <|?> (0, try $ parseIntAttribute "csum")
         <|?> (0, parseIntAttribute "off")
         <|?> ([PPayload defaultPayload], parsePayload f)
         <|?> (True, parseBoolAttribute "fixcsum"))
  where
    tuple s d v hl l id_ p tos ttl csum off pl cc =
      IPv4Pkt (IPv4 v hl tos l id_ off ttl p csum s d cc) pl

ipv4Decl :: Parser Packet -> Parser Packet
ipv4Decl f = do
 symbol "ipv4"
 p <- parseIPv4Pkt f
 return (PIPv4 p)

pseudoIpv4Write :: IPv4 -> Word16 -> Put
pseudoIpv4Write p l = do
    putWord32be (ipv4Src p)
    putWord32be (ipv4Dst p)
    putWord8    0
    putWord8    (ipv4Prot p)
    putWord16be l

ipv4WriteHdr :: IPv4 -> Put
ipv4WriteHdr p = do
    putWord8    ((ipv4Ver p `shiftL` 4) .|. ipv4Hlen p)
    putWord8    (ipv4Tos p)
    putWord16be $ fromIntegral (ipv4Len p)
    putWord16be (ipv4Id p)
    putWord16be (ipv4Offset p)
    putWord8    (ipv4Ttl p)
    putWord8    (ipv4Prot p)
    putWord16be (ipv4Csum p)
    putWord32be    (ipv4Src p)
    putWord32be    (ipv4Dst p)

instance PacketWriteable IPv4Pkt where packetWrite p = ipv4Write $ ipv4PktHeader p

ipv4Write :: IPv4 -> Maybe Packet -> B.ByteString -> Put
ipv4Write h _ bs = do
    let hdr = if ipv4Len h == -1 then h {ipv4Len = fromIntegral $ 20 + B.length bs}
                                 else h
    let sum32 = if ipv4CorrectCsum hdr
                   then csumFin $ csumAdd (B.unpack $ runPut $
                                           ipv4WriteHdr hdr) 0
                   else ipv4Csum hdr
    ipv4WriteHdr hdr {ipv4Csum = sum32}
    putLazyByteString bs


#ifdef HRWS_TEST
{- Unit Tests -}

instance Arbitrary IPv4 where
  arbitrary = do
    v   <- choose (0, 15)
    hl  <- choose (0, 15)
    tos <- arbitrary
    len <- choose (0, 64*1024)
    i   <- arbitrary
    off <- arbitrary
    ttl <- arbitrary
    p   <- arbitrary
    cs  <- arbitrary
    src <- arbitrary
    dst <- arbitrary
    return (IPv4 v hl tos len i off ttl p cs src dst True)

testValidParse :: String -> (IPv4 -> Bool) -> Bool
testValidParse str fn =
  case parse (dummyParsePacket ipv4Decl) "packet parse" str of
       Left  err -> trace (show err) False
       Right val -> fn $ testIPv4Frame val

testIPv4Frame :: Packet -> IPv4
testIPv4Frame (PIPv4 p) = ipv4PktHeader p
testIPv4Frame _ = error "Unexpected packet type"

testIPv4Default :: () -> Bool
testIPv4Default _ = let cmp f = defaultIPv4 == f in
  testValidParse "(ipv4)" cmp

testIPv4Version :: Word8 -> Bool
testIPv4Version v = let cmp f = defaultIPv4 {ipv4Ver = v} == f in
  testValidParse ("(ipv4 ver=" ++ show v ++ ")") cmp

testIPv4Hlen :: Word8 -> Bool
testIPv4Hlen hl = let cmp f = defaultIPv4 {ipv4Hlen = hl} == f in
  testValidParse  ("(ipv4 hlen=" ++ show hl ++ ")") cmp

testIPv4Tos :: Word8 -> Bool
testIPv4Tos t = let cmp f = defaultIPv4 {ipv4Tos = t} == f in
  testValidParse ("(ipv4 tos=" ++ show t ++ ")") cmp

testIPv4Len :: Int -> Bool
testIPv4Len l = let cmp f = defaultIPv4 {ipv4Len = l} == f in
  testValidParse ("(ipv4 len=" ++ show l ++ ")") cmp

testIPv4Id :: Word16 -> Bool
testIPv4Id i = let cmp f = defaultIPv4 {ipv4Id =i} == f in
  testValidParse ("(ipv4 id=" ++ show i ++ ")") cmp

testIPv4Offset :: Word16 -> Bool
testIPv4Offset o = let cmp f = defaultIPv4 {ipv4Offset = o} == f in
  testValidParse ("(ipv4 off=" ++ show o ++ ")") cmp

testIPv4Ttl :: Word8 -> Bool
testIPv4Ttl ttl = let cmp f = defaultIPv4 {ipv4Ttl = ttl} == f in
  testValidParse ("(ipv4 ttl=" ++ show ttl ++ ")") cmp

testIPv4Prot :: Word8 -> Bool
testIPv4Prot p = let cmp f = defaultIPv4 {ipv4Prot = p} == f in
  testValidParse ("(ipv4 prot=" ++ show p ++ ")") cmp

testIPv4Csum :: Word16 -> Bool
testIPv4Csum c = let cmp f = defaultIPv4 {ipv4Csum = c} == f in
  testValidParse ("(ipv4 csum=" ++ show c ++ ")") cmp

testIPv4Src :: Word32 -> Bool
testIPv4Src ip = let cmp f = defaultIPv4 {ipv4Src = ip} == f in
  testValidParse ("(ipv4 src=" ++ showIPv4Address ip ++ ")") cmp

testIPv4Dst :: Word32 -> Bool
testIPv4Dst ip = let cmp f = defaultIPv4 {ipv4Dst = ip} == f in
  testValidParse ("(ipv4 dst=" ++ showIPv4Address ip ++ ")") cmp

testIPv4FixCsum :: () -> Bool
testIPv4FixCsum _ = let cmp p = defaultIPv4 {ipv4CorrectCsum = False} == p in
  testValidParse "(ipv4 fixcsum=false)" cmp

testIPv4Pkt0 :: IPv4 -> Bool
testIPv4Pkt0 ip = let cmp p = ip == p in
  testValidParse ("(ipv4 ver=" ++ show (ipv4Ver ip) ++ " hlen=" ++ show (ipv4Hlen ip) ++
                  " tos=" ++ show (ipv4Tos ip) ++ " len=" ++ show (ipv4Len ip) ++
                  " id=" ++ show (ipv4Id ip) ++ " off=" ++ show (ipv4Offset ip) ++
                  " ttl=" ++ show (ipv4Ttl ip) ++ " prot=" ++ show (ipv4Prot ip) ++
                  " csum=" ++ show (ipv4Csum ip) ++ "src=" ++ showIPv4Address (ipv4Src ip) ++
                  " dst=" ++ showIPv4Address (ipv4Dst ip) ++ "fixcsum=true)") cmp

testIPv4Write :: () -> Bool
testIPv4Write _ =
  let expPkt = B.pack [0x45, 0x0c, 0x00, 0x14, 0xbe, 0xef, 0x00, 0x00,
                       0x0a, 0x07, 0xdd, 0x9d, 0x0a, 0x00, 0x00, 0x01,
                       0x0a, 0x00, 0x00, 0x02] in
  let cmp p = runPut (ipv4Write p Nothing B.empty) == expPkt in
  testValidParse "(ipv4 ver=4 hlen=5 tos=12 len=20 id=0xbeef off=0 ttl=0xa prot=7 csum=0xdd9d src=10.0.0.1 dst=10.0.0.2 fixcsum=false)" cmp

testIPv4PseudoWrite :: () -> Bool
testIPv4PseudoWrite _ =
  let expPh = B.pack [0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0x00, 0x07, 0x00, 0x5c] in
  let cmp p = runPut (pseudoIpv4Write p 92) == expPh in
  testValidParse "(ipv4 ver=4 hlen=5 tos=12 len=92 id=0xbeef off=0 ttl=0xa prot=7 csum=0xdd9d src=10.0.0.1 dst=10.0.0.2)" cmp

  
ipv4Tests :: [Test]
ipv4Tests = [
  testProperty "IPv4: Default Packet" testIPv4Default,
  testProperty "IPv4: Version" testIPv4Version,
  testProperty "IPv4: Header Length" testIPv4Hlen,
  testProperty "IPv4: Type of Service" testIPv4Tos,
  testProperty "IPv4: Length" testIPv4Len,
  testProperty "IPv4: ID" testIPv4Id,
  testProperty "IPv4: Offset" testIPv4Offset,
  testProperty "IPv4: TTL" testIPv4Ttl,
  testProperty "IPv4: Protocol" testIPv4Prot,
  testProperty "IPv4: Checksum" testIPv4Csum,
  testProperty "IPv4: Source" testIPv4Src,
  testProperty "IPv4: Dest" testIPv4Dst,
  testProperty "IPv4: Correct Checksum" testIPv4FixCsum,
  testProperty "IPv4: Packet 0" testIPv4Pkt0,
  testProperty "IPv4: Write" testIPv4Write,
  testProperty "IPv4: Write Pseudo Header" testIPv4PseudoWrite
  ]

#endif


