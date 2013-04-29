module Payload where

import Data.Binary.Put
import qualified Data.ByteString.Lazy as B
import Text.ParserCombinators.Parsec
import Text.ParserCombinators.Parsec.Perm

import Packet
import Lexer
import Util

payloadPkt :: Parser Packet -> Parser Payload
payloadPkt _ = permute
  (tuple <$?> (0, parseIntAttribute "pattern")
         <|?> (64, parseIntAttribute "length"))
  where
    tuple = Payload

payloadDecl :: Parser Packet -> Parser Packet
payloadDecl f = do
  symbol "payload"
  p <- payloadPkt f
  return (PPayload p)

payloadWrite :: Payload -> Put
payloadWrite p = do
  let bs = B.replicate (fromIntegral $ payloadLength p)
                        (fromIntegral $ payloadPattern p)
  putLazyByteString bs

instance PacketWriteable Payload where packetWrite p _ _ = payloadWrite p

