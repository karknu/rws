{-# LANGUAGE CPP #-}
module Teredo where

import Text.ParserCombinators.Parsec
import Text.ParserCombinators.Parsec.Perm
import Data.Word
import Data.Bits

import Lexer
import Packet
import Util

#ifdef HRWS_TEST
import Debug.Trace
import Test.QuickCheck hiding ((.&.))
import Test.Framework (Test)
import Test.Framework.Providers.QuickCheck2 (testProperty)
import Text.Printf
#endif

parseTeredoPkt :: Parser Packet -> Parser TeredoPkt
parseTeredoPkt f = permute
  (tuple <$?> (True, try $ parseBoolAttribute "fixsrc")
         <|?> (True, try $ parseBoolAttribute "fixdst")
         <|?> (PPayload (Payload 0 0), f))
  where
    tuple fs fd =
        TeredoPkt (Teredo 0 0 0 0 0 0 False False fs fd)

teredoDecl :: Parser Packet -> Parser Packet
teredoDecl f = do
 symbol "teredo"
 u <- parseTeredoPkt f
 return (PTeredo u)

mkTeredoAddress :: Word32 -> Word16 -> IPv6Addr
mkTeredoAddress host port =
  let host' = complement host in
  let port' = fromIntegral $ complement port in
  IPv6Addr 0x20010000 0xcafebabe port' host'

fixTeredoAddresses :: Bool -> Bool -> Packet -> Packet -> Packet
fixTeredoAddresses False False p _ = p
fixTeredoAddresses s d (PIPv6 v6) (PIPv4 v4) =
  let (sp, dp) = case head (ipv4PktPayload v4) of
                      PUdp u -> (udpSrc $ udpPktHeader u, udpDst $ udpPktHeader u)
                      _      -> error "Need a UDP header to generate teredo addresses" in
  PIPv6 v6 {ipv6PktHeader =
    (ipv6PktHeader v6) {ipv6Src = if s then mkTeredoAddress (ipv4Src $ ipv4PktHeader v4) sp
                                       else ipv6Src $ ipv6PktHeader v6,
                        ipv6Dst = if d then mkTeredoAddress (ipv4Dst $ ipv4PktHeader v4) dp
                                       else ipv6Dst $ ipv6PktHeader v6}}
fixTeredoAddresses _ _ p _ = p



#ifdef HRWS_TEST
{- Unit Tests -}

instance Arbitrary Teredo where
  arbitrary = do
    fs <- arbitrary
    fd <- arbitrary
    return (Teredo 0 0 0 0 0 0 False False fs fd)

testValidParse :: String -> (Teredo -> Bool) -> Bool
testValidParse str fn =
  case parse (dummyParsePacket teredoDecl) "packet parse" str of
       Left  err -> trace (show err) False
       Right val -> fn $ testTeredoPkt val

testTeredoDefault :: () -> Bool
testTeredoDefault _ = let cmp f = defaultTeredo == f in
  testValidParse "(teredo)" cmp

testTeredoPkt :: Packet -> Teredo
testTeredoPkt (PTeredo f) = teredoPktHeader f
testTeredoPkt _ = error "Unexpected packet type"

testTeredoPacket :: Teredo -> Bool
testTeredoPacket pkt =
  let cmp p = pkt == p in
  testValidParse (printf "(teredo fixsrc=%s fixdst=%s)"
                  (showBool (teredoFixSrc pkt))
                  (showBool (teredoFixDst pkt))) cmp

teredoTests :: [Test]
teredoTests = [
  testProperty "Teredo: Default Packet" testTeredoDefault,
  testProperty "Teredo: Packet" testTeredoPacket
  ]
#endif



