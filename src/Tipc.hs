{-# LANGUAGE CPP #-}
module Tipc where

import Control.Monad
import Data.Binary.Put
import Data.Bits
import qualified Data.ByteString.Lazy as B
import Data.Maybe
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
import Text.Printf

#endif

parseTipcPkt :: Parser Packet -> Parser TipcPkt
parseTipcPkt f = permute
  (tuple <$?> (2, parseIntAttribute "ver")
         <|?> (0, parseIntAttribute "user")
         <|?> (6, parseIntAttribute "hsize")
         <|?> (0, parseIntAttribute "flags")
         <|?> (Nothing, try $ do { ms <- parseIntAttribute "msize"; return $ Just ms})
         <|?> (0, try (parseIntAttribute "mtype"))
         <|?> (0, parseIntAttribute "error")
         <|?> (0, try (parseIntAttribute "reroute"))
         <|?> (3, try (parseIntAttribute "lsc"))
         <|?> (0, try (parseIntAttribute "res"))
         <|?> (0, parseIntAttribute "back")
         <|?> (0, try (parseIntAttribute "lack"))
         <|?> (0, try (parseIntAttribute "lseq"))
         <|?> (0xabba, parseIntAttribute "pnode")
         <|?> (1234, try (parseIntAttribute "oport"))
         <|?> (5678, try (parseIntAttribute "dportnet"))
         <|?> (Nothing, try $ do { on <- parseIntAttribute "onode"; return $ Just on})
         <|?> (Nothing, try $ do { dn <- parseIntAttribute "dnode"; return $ Just dn})
         <|?> ([PPayload defaultPayload], parsePayload f))
  where
    tuple v u hs fl ms mt e re ls rs ba la lq pn op dp on dn =
        TipcPkt (Tipc v u hs fl ms mt e re ls rs ba la lq pn op dp on dn)


tipcDecl :: Parser Packet -> Parser Packet
tipcDecl f = do
  symbol "tipc"
  g <- parseTipcPkt f
  return (PTipc g)

tipcWriteHdr :: Tipc -> Word32 -> Put
tipcWriteHdr p len = do
     let msize = fromMaybe ((fromIntegral (tipcHsize p) * 4) + len) (tipcMsize p)
     let w0 = (fromIntegral (tipcVer p) `shiftL` 29)   .|.
              (fromIntegral (tipcUser p) `shiftL` 25)  .|.
              (fromIntegral (tipcHsize p) `shiftL` 21) .|.
              (fromIntegral (tipcFlags p) `shiftL` 17) .|.
              msize
     putWord32be w0
     let w1 = (fromIntegral (tipcMtype p) `shiftL` 29)   .|.
              (fromIntegral (tipcError p) `shiftL` 25)   .|.
              (fromIntegral (tipcReroute p) `shiftL` 21) .|.
              (fromIntegral (tipcLsc p) `shiftL` 19) .|.
              (fromIntegral (tipcRes p) `shiftL` 16) .|.
              fromIntegral (tipcBack p)
     putWord32be w1
     putWord16be $ tipcLack p
     putWord16be $ tipcLseq p
     putWord32be $ tipcPnode p
     putWord32be $ tipcOport p
     putWord32be $ tipcDportNet p
     when (isJust $ tipcOnode p) $ putWord32be (fromJust $ tipcOnode p)
     when (isJust $ tipcDnode p) $ putWord32be (fromJust $ tipcDnode p)

tipcWrite :: Tipc -> Maybe Packet -> B.ByteString -> Put
tipcWrite h _ bs = do
    let plen = fromIntegral $ B.length bs
    tipcWriteHdr h plen
    putLazyByteString bs

instance PacketWriteable TipcPkt where packetWrite p = tipcWrite (tipcPktHeader p)


#ifdef HRWS_TEST
{- Unit Tests -}

instance Arbitrary Tipc where
  arbitrary = do
    ver <- arbitrary
    user <- arbitrary
    hsize <- arbitrary
    flags <- arbitrary
    msize <- arbitrary
    mtype <- arbitrary
    err <- arbitrary
    reroute <- arbitrary
    lsc <- arbitrary
    res <- arbitrary
    back <- arbitrary
    lack <- arbitrary
    lseq <- arbitrary
    pnode <- arbitrary
    oport <- arbitrary
    dportnet <- arbitrary
    onode <- arbitrary
    dnode <- arbitrary
    return (Tipc ver user hsize flags (Just msize) mtype err reroute lsc res back lack lseq pnode
            oport dportnet (Just onode) (Just dnode))

testValidParse :: String -> (Tipc -> Bool) -> Bool
testValidParse str fn =
  case parse (dummyParsePacket tipcDecl) "packet parse" str of
       Left  err -> trace (show err) False
       Right val -> fn $ testTipcPkt val

testTipcDefault :: () -> Bool
testTipcDefault _ = let cmp f = defaultTipc == f in
  testValidParse "(tipc)" cmp

testTipcPkt :: Packet -> Tipc
testTipcPkt (PTipc f) = tipcPktHeader f
testTipcPkt _ = error "Unexpected packet type"

testTipcPacket :: Tipc -> Bool
testTipcPacket pkt =
  let cmp p = pkt == p in
  testValidParse (printf "(tipc ver=%d user=%d hsize=%d flags=%d msize=%d mtype=%d error=%d reroute=%d lsc=%d res=%d back=%d lack=%d lseq=%d pnode=%d oport=%d dportnet=%d onode=%d dnode=%d)"
                  (tipcVer pkt) (tipcUser pkt) (tipcHsize pkt) (tipcFlags pkt)
                  (fromJust $ tipcMsize pkt) (tipcMtype pkt) (tipcError pkt) (tipcReroute pkt)
                  (tipcLsc pkt) (tipcRes pkt) (tipcBack pkt) (tipcLack pkt) (tipcLseq pkt)
                  (tipcPnode pkt) (tipcOport pkt) (tipcDportNet pkt) (fromJust $ tipcOnode pkt)
                  (fromJust $ tipcDnode pkt)) cmp

testTipcWrite :: () -> Bool
testTipcWrite _ =
  let expPkt = B.pack [0x41, 0x00, 0x00, 0x20, 0x60, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0xab, 0xba, 0x00, 0x00, 0x04, 0xd2, 0x00, 0x00, 0x16, 0x2e,
                       0x00, 0x01, 0x02, 0x03, 0x00, 0x04, 0x05, 0x06] in
  let cmp p = runPut (tipcWrite p Nothing B.empty) == expPkt in
  testValidParse "(tipc ver=2 user=0 mtype=3 onode=0x010203 dnode=0x040506 hsize=8)" cmp

tipcTests :: [Test]
tipcTests = [
  testProperty "TIPC: Default Packet" testTipcDefault,
  testProperty "TIPC: Packet" testTipcPacket,
  testProperty "TIPC: Write" testTipcWrite
  ]
#endif

