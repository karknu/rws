{-# LANGUAGE CPP #-}

module Util where
import Data.Word
import Data.Bits
import Packet
import Text.ParserCombinators.Parsec

import Lexer

csumAdd :: [Word8] -> Word32 -> Word32
csumAdd [] s = s
csumAdd [a] s = s + fromIntegral a
csumAdd (a:b:as) s =
  let s' = s + shiftL (fromIntegral b) 8 + fromIntegral a in
  csumAdd as s'

csumFin :: Word32 -> Word16
csumFin s =
  let s' = shiftR s 16 + (.&.) s 0xffff in
  let s'' = fromIntegral (complement $ shiftR s' 16 + s') in
  shiftL s'' 8 .|. shiftR s'' 8


parseBoolAttribute :: String -> Parser Bool
parseBoolAttribute s = do
  symbol s
  symbol "="
  do { symbol "true"; return True} <|> do { symbol "false"; return False}

parseIntAttribute :: Num b => String -> Parser b
parseIntAttribute s = do
  symbol s
  symbol "="
  a <- integer
  whiteSpace
  return (fromIntegral a)

ipv4AddressDecl :: Parser Word32
ipv4AddressDecl = do
  a0 <- integer
  char '.'
  a1 <- integer
  char '.'
  a2 <- integer
  char '.'
  a3 <- integer
  let a = a0 `shiftL` 24 .|. a1 `shiftL` 16 .|. a2 `shiftL` 8 .|. a3
  return (fromIntegral a)

parseIPv4Address :: String -> Parser Word32
parseIPv4Address s = do
  symbol s
  symbol "="
  a <- ipv4AddressDecl
  whiteSpace
  return a

showIPv4Address :: Word32 -> String
showIPv4Address ip =
  let a0 = ip `shiftR` 24 in
  let a1 = ip `shiftR` 16 .&. 0xff in
  let a2 = ip `shiftR` 8 .&. 0xff in
  let a3 = ip .&. 0xff in
  show a0 ++ "." ++ show a1 ++ "." ++ show a2 ++ "." ++ show a3

parsePacketList :: Parser Packet -> Parser [Packet]
parsePacketList f = do
  whiteSpace
  char '{'
  pls <- commaSep f
  char '}'
  whiteSpace
  return pls

parsePayload :: Parser Packet -> Parser [Packet]
parsePayload f =
  try (parsePacketList f) <|> do { p <- f; return [p]}

#ifdef HRWS_TEST

dummyParsePacket :: (Parser Packet -> Parser Packet) -> Parser Packet
dummyParsePacket f= do
  char '('
  p <- f (dummyParsePacket f)
  char ')'
  return p

showBool :: Bool -> String
showBool True = "true"
showBool False = "false"

#endif
