module SerializePcap (pcapWrite) where

import Data.Binary.Put
import qualified Data.ByteString.Lazy as BL
import Data.Word

import Ethernet()
import Fragv6()
import Gre()
import Gtp()
import HexPayload()
import HopByHop()
import Icmp()
import IcmpV6()
import IPv4()
import IPv6()
import L2tp()
import Packet
import PadN()
import Ppp()
import Payload()
import Tcp()
import Teredo
import Udp()

data PcapFileHdr = PcapFileHdr {
  pcapFileHdrMagic   :: !Word32,
  pcapFileHdrMajVer  :: !Word16,
  pcapFileHdrMinVer  :: !Word16,
  pcapFileHdrTsZone  :: !Word32,
  pcapFileHdrSigFigs :: !Word32,
  pcapFileHdrSnapLen :: !Word32,
  pcapFileHdrLink    :: !Word32
}

data PcapPktHdr = PcapPktHdr {
  pcapPktHdrTsSec  :: !Word32,
  pcapPktHdrTsUsec :: !Word32,
  pcapPktHdrIncLen :: !Word32,
  pcapPktHdrOrgLen :: !Word32
}


pcapFileWrite :: PcapFileHdr -> Put
pcapFileWrite f = do
  putWord32host $ pcapFileHdrMagic f
  putWord16host $ pcapFileHdrMajVer f
  putWord16host $ pcapFileHdrMinVer f
  putWord32host $ pcapFileHdrTsZone f
  putWord32host $ pcapFileHdrSigFigs f
  putWord32host $ pcapFileHdrSnapLen f
  putWord32host $ pcapFileHdrLink f

mkPcapFile :: PcapFileHdr
mkPcapFile = PcapFileHdr {
  pcapFileHdrMagic  = 0xa1b2c3d4,
  pcapFileHdrMajVer = 2,
  pcapFileHdrMinVer = 4,
  pcapFileHdrTsZone = 0,
  pcapFileHdrSigFigs = 0,
  pcapFileHdrSnapLen = 1600,
  pcapFileHdrLink = 1 }


packPayloadCarried :: PayloadCarrier a => a -> Maybe Packet -> BL.ByteString
packPayloadCarried a mp = let ps = payloadCarried a in
  if ps == [] then BL.empty
              else BL.concat $ map (\ pl -> runPut (pcapPacketWrite pl mp)) ps

pcapPktHeaderWrite :: PcapPktHdr -> Put
pcapPktHeaderWrite p = do
  putWord32host $ pcapPktHdrTsSec p
  putWord32host $ pcapPktHdrTsUsec p
  putWord32host $ pcapPktHdrIncLen p
  putWord32host $ pcapPktHdrOrgLen p

pcapWriteEntry :: Packet -> Word32 -> Word32 -> Put
pcapWriteEntry pkt s us = do
  let bs = runPut $ pcapPacketWrite pkt Nothing
  let l = fromIntegral $ BL.length bs
  let ph = PcapPktHdr s us l l
  pcapPktHeaderWrite ph
  putLazyByteString bs

pcapPacketWrite :: Packet -> Maybe Packet -> Put
pcapPacketWrite (PEth p) mp            = packetWrite p mp $ packPayloadCarried p mp
pcapPacketWrite (PFragv6 p) mp         = packetWrite p mp $ packPayloadCarried p mp
pcapPacketWrite (PGtp p) mp            = packetWrite p mp $ packPayloadCarried p mp
pcapPacketWrite (PGre p) mp            = packetWrite p mp $ packPayloadCarried p mp
pcapPacketWrite (PHexPayload p) mp     = packetWrite p mp BL.empty
pcapPacketWrite (PHopByHop p) mp       = packetWrite p mp $ packPayloadCarried p mp
pcapPacketWrite (PIcmp p) mp           = packetWrite p mp $ packPayloadCarried p mp
pcapPacketWrite (PIcmpV6 p) mp         = packetWrite p mp $ packPayloadCarried p mp
pcapPacketWrite (PIPv4 p) _      = packetWrite p Nothing $ packPayloadCarried p $ Just (PIPv4 p)
pcapPacketWrite (PIPv6 p) _      = packetWrite p Nothing $ packPayloadCarried p $ Just (PIPv6 p)
pcapPacketWrite (PL2tp p) mp           = packetWrite p mp $ packPayloadCarried p mp
pcapPacketWrite (PPayload p) mp        = packetWrite p mp BL.empty
pcapPacketWrite (PPadN p) mp           = packetWrite p mp $ packPayloadCarried p mp
pcapPacketWrite (PPpp p) mp            = packetWrite p mp $ packPayloadCarried p mp
pcapPacketWrite (PTcp p) mp            = packetWrite p mp $ packPayloadCarried p mp
pcapPacketWrite (PUdp p) mp            = packetWrite p mp $ packPayloadCarried p mp
pcapPacketWrite (PTeredo p) mp = do -- no auth and org support yet
  let ph = teredoPktHeader p
  let pl = maybe (teredoPktPayload p)
                 (fixTeredoAddresses (teredoFixSrc ph) (teredoFixDst ph)
                                     (teredoPktPayload p)) mp
  let bs = runPut (pcapPacketWrite pl mp)
  putLazyByteString bs

pcapWrite :: [Packet] -> Put
pcapWrite pkts = do
  pcapFileWrite mkPcapFile
  mapM_ (\ p -> pcapWriteEntry p 0 1) pkts

