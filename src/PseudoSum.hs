module PseudoSum where

import Data.Binary.Put
import qualified Data.ByteString.Lazy as BL
import Data.Maybe
import Data.Word

import IPv4
import IPv6
import Packet
import Util

genPseudoSum :: Maybe Packet -> Word16 -> Word32
genPseudoSum mp _ | isNothing mp = 0
genPseudoSum mp l                =
  case fromJust mp of
       (PIPv4 ipv4) -> csumAdd (BL.unpack $ runPut $
                                pseudoIpv4Write (ipv4PktHeader ipv4) l) 0
       (PIPv6 ipv6) -> csumAdd (BL.unpack $ runPut $
                                pseudoIpv6Write (ipv6PktHeader ipv6) l) 0
       _            -> 0


