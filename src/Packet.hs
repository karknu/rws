module Packet where

import Data.Binary.Put
import Data.Bits
import qualified Data.ByteString.Lazy as B
import Data.Word
import Text.Printf

class PayloadCarrier a where
  payloadCarried :: a -> [Packet]

class PacketWriteable a where
  packetWrite :: a -> Maybe Packet -> B.ByteString -> Put

data MacAddress = MacAddress {
  macAddress0 :: Word8,
  macAddress1 :: Word8,
  macAddress2 :: Word8,
  macAddress3 :: Word8,
  macAddress4 :: Word8,
  macAddress5 :: Word8
} deriving Eq

instance Show MacAddress where show = showMacAddress
showMacAddress :: MacAddress -> String
showMacAddress a = printf "%02x:%02x:%02x:%02x:%02x:%02x" (macAddress0 a) (macAddress1 a)
  (macAddress2 a) (macAddress3 a) (macAddress4 a) (macAddress5 a)  

data Ethernet = Ethernet {
  ethernetDst :: MacAddress,
  ethernetSrc :: MacAddress,
  ethernetType :: Word16,
  ethernetVlans :: [Vlan]
} deriving (Show,Eq)

data EthernetFrame = EthernetFrame {
 ethernFrameHeader :: Ethernet,
 ethernPayload :: [Packet]
} deriving (Show,Eq)

instance PayloadCarrier EthernetFrame where payloadCarried = ethernPayload

defaultEthernet :: Ethernet
defaultEthernet = Ethernet (MacAddress 0 0 0 0 0 1) 
                            (MacAddress 0 0 0 0 0 2)
                            0x800 []
defaultEthernetFrame :: EthernetFrame
defaultEthernetFrame = EthernetFrame defaultEthernet
                        [PPayload defaultPayload]

data Vlan = Vlan {
  vlanTpid :: Word16,
  vlanPcp :: Word8,
  vlanDei :: Bool,
  vlanVid :: Word16
} deriving (Show, Eq)

data IPv6Addr = IPv6Addr {
             ipv6Addr0 :: !Word32,
             ipv6Addr1 :: !Word32,
             ipv6Addr2 :: !Word32,
             ipv6Addr3 :: !Word32
} deriving Eq

instance Show IPv6Addr where show = showIPv6Addr
showIPv6Addr :: IPv6Addr -> String
showIPv6Addr a = printf "0x%04x:0x%04x:0x%04x:0x%04x:0x%04x:0x%04x:0x%04x:0x%04x"
  (ipv6Addr0 a `shiftR` 16) (ipv6Addr0 a .&. 0xffff)
  (ipv6Addr1 a `shiftR` 16) (ipv6Addr1 a .&. 0xffff)
  (ipv6Addr2 a `shiftR` 16) (ipv6Addr2 a .&. 0xffff)
  (ipv6Addr3 a `shiftR` 16) (ipv6Addr3 a .&. 0xffff)

data IPv6 = IPv6 {
    ipv6Ver          :: !Word8,
    ipv6Tcl          :: !Word8,
    ipv6Flow         :: !Word32,
    ipv6Length       :: !Word16,
    ipv6Nh           :: !Word8,
    ipv6Hl           :: !Word8,
    ipv6Src          :: !IPv6Addr,
    ipv6Dst          :: !IPv6Addr
} deriving (Show,Eq)

data IPv6Pkt = IPv6Pkt {
  ipv6PktHeader :: IPv6,
  ipv6PktPayload :: [Packet]
} deriving (Show,Eq)

instance PayloadCarrier IPv6Pkt where payloadCarried = ipv6PktPayload

defaultIPv6 :: IPv6
defaultIPv6 = IPv6 6 0 0 0 17 64 (IPv6Addr 0x2001000 0 0 1) (IPv6Addr 0x2001000 0 0 2)
defaultIPv6Packet :: IPv6Pkt
defaultIPv6Packet = IPv6Pkt defaultIPv6 [PPayload $ Payload 0 0]



data IPv4 = IPv4 {
  ipv4Ver    :: !Word8,
  ipv4Hlen   :: !Word8,
  ipv4Tos    :: !Word8,
  ipv4Len    :: !Word16,
  ipv4Id     :: !Word16,
  ipv4Offset :: !Word16,
  ipv4Ttl    :: !Word8,
  ipv4Prot   :: !Word8,
  ipv4Csum   :: !Word16,
  ipv4Src    :: !Word32,
  ipv4Dst    :: !Word32,
  ipv4CorrectCsum :: Bool
} deriving (Show,Eq)

defaultIPv4 :: IPv4
defaultIPv4 = IPv4 4 5 0 0 0x1234 0 64 17 0 0xa0a0a0a1 0xa0a0a0a2 True
defaultIPv4Packet :: IPv4Pkt
defaultIPv4Packet = IPv4Pkt defaultIPv4 [PPayload defaultPayload]

data IPv4Pkt = IPv4Pkt {
  ipv4PktHeader :: IPv4,
  ipv4PktPayload :: [Packet]
} deriving (Show,Eq)

instance PayloadCarrier IPv4Pkt where payloadCarried = ipv4PktPayload

data Udp = Udp {
  udpSrc :: !Word16,
  udpDst :: !Word16,
  udpLen :: !Word16,
  udpCsum :: !Word16,
  udpCorrectCsum :: Bool
} deriving (Show,Eq)

data UdpPkt = UdpPkt {
  udpPktHeader :: Udp,
  udpPktPayload :: [Packet]
} deriving (Show,Eq)

instance PayloadCarrier UdpPkt where payloadCarried = udpPktPayload

defaultUdp :: Udp
defaultUdp = Udp 7 7 8 0 True
defaultUdpPacket :: UdpPkt
defaultUdpPacket = UdpPkt defaultUdp [PPayload defaultPayload]

data Tcp = Tcp {
    tcpSrc :: !Word16,
    tcpDst :: !Word16,
    tcpSeqNo :: !Word32,
    tcpAckNo :: !Word32,
    tcpFlags :: !Word16,
    tcpWin :: !Word16,
    tcpCsum :: !Word16,
    tcpUrg :: !Word16,
    tcpOffset :: !Word8,
    tcpCorrectCsum :: Bool,
    tcpWindowScale :: !Word8,
    tcpTimeStamp :: !Word64
    -- options
} deriving (Show,Eq)

defaultTcp :: Tcp
defaultTcp = Tcp 7 7 0 0 0x5000 0xffff 0 0 20 True 0 0
defaultTcpPacket :: TcpPkt
defaultTcpPacket = TcpPkt defaultTcp [PPayload $ Payload 0 0]



data TcpPkt = TcpPkt {
    tcpPktHeader :: Tcp,
    tcpPktPayload :: [Packet]
} deriving (Show,Eq)

instance PayloadCarrier TcpPkt where payloadCarried = tcpPktPayload

data Gtp = Gtp {
  gtpFlags :: !Word8,
  gtpType :: !Word8,
  gtpLen :: !Word16,
  gtpTeid :: !Word32,
  gtpSeq :: !Word16,
  gtpNpdu :: !Word8,
  gtpNh :: !Word8
} deriving (Show,Eq)

defaultGtp :: Gtp
defaultGtp = Gtp 0x32 0xff 0 0x012345678 0 0 0
defaultGtpPacket :: GtpPkt
defaultGtpPacket = GtpPkt defaultGtp [PPayload defaultPayload]


data GtpPkt = GtpPkt {
  gtpPktHeader :: Gtp,
  gtpPktPayload :: [Packet]
} deriving (Show,Eq)

instance PayloadCarrier GtpPkt where payloadCarried = gtpPktPayload

data Ppp = Ppp {
    pppAddress :: !Word8,
    pppControl :: !Word8,
    pppProtocol :: !Word16
} deriving (Show,Eq)

data PppPkt = PppPkt {
  pppPktHeader :: Ppp,
  pppPktPayload :: [Packet]
} deriving (Show,Eq)

instance PayloadCarrier PppPkt where payloadCarried = pppPktPayload

defaultPpp :: Ppp
defaultPpp = Ppp 0xff 0x03 0x0021
defaultPppPacket :: PppPkt
defaultPppPacket = PppPkt defaultPpp [PPayload $ Payload 0 0]

data L2tp = L2tp {
    l2tpFlags :: !Word16,
    l2tpLength :: !Word16,
    l2tpTid :: !Word16,
    l2tpSid :: !Word16,
    l2tpNs :: !Word16,
    l2tpNr :: !Word16,
    l2tpOffset :: !Word16,
    l2tpCorrectOffset :: Bool
} deriving (Show,Eq)

data L2tpPkt = L2tpPkt {
  l2tpPktHeader :: L2tp,
  l2tpPktPayload :: [Packet]
} deriving (Show,Eq)

defaultL2tp :: L2tp
defaultL2tp = L2tp 0x2 0 0x1234 0x5678 0 0 0 True
defaultL2tpPacket :: L2tpPkt
defaultL2tpPacket = L2tpPkt defaultL2tp [PPayload $ Payload 0 0]

instance PayloadCarrier L2tpPkt where payloadCarried = l2tpPktPayload

data Gre = Gre {
    greFlags :: !Word16,
    greProtocol :: !Word16,
    greKey :: !Word32,
    greSeq :: !Word32
} deriving (Show,Eq)

data GrePkt = GrePkt {
    grePktHeader :: Gre,
    grePktPayload :: [Packet]
} deriving (Show,Eq)

defaultGre :: Gre
defaultGre = Gre 0x3000 0x0800 0xcafecafe 0
defaultGrePacket :: GrePkt
defaultGrePacket = GrePkt defaultGre [PPayload $ Payload 0 0]

instance PayloadCarrier GrePkt where payloadCarried = grePktPayload

data Icmp = Icmp {
    icmpType :: !Word8,
    icmpCode :: !Word8,
    icmpCsum :: !Word16,
    icmpId :: !Word16,
    icmpSeq :: !Word16,
    icmpCorrectCsum :: Bool
} deriving (Show,Eq)

defaultIcmp :: Icmp
defaultIcmp = Icmp 8 0 0 0xcafe 1 True
defaultIcmpPacket :: IcmpPkt
defaultIcmpPacket = IcmpPkt defaultIcmp [PPayload $ Payload 0 0]

data IcmpPkt = IcmpPkt {
    icmpPktHeader :: Icmp,
    icmpPktPayload :: [Packet]
} deriving (Show,Eq)

instance PayloadCarrier IcmpPkt where payloadCarried = icmpPktPayload

data IcmpV6 = IcmpV6 {
    icmpV6Type :: !Word8,
    icmpV6Code :: !Word8,
    icmpV6Csum :: !Word16,
    icmpV6Pad  :: !Word32,
    icmpV6CorrectCsum :: Bool
} deriving (Show,Eq)

defaultIcmpV6 :: IcmpV6
defaultIcmpV6 = IcmpV6 8 0 0 0xffffffff True
defaultIcmpV6Packet :: IcmpV6Pkt
defaultIcmpV6Packet = IcmpV6Pkt defaultIcmpV6 [PPayload $ Payload 0 0]

data IcmpV6Pkt = IcmpV6Pkt {
    icmpV6PktHeader :: IcmpV6,
    icmpV6PktPayload :: [Packet]
} deriving (Show,Eq)

instance PayloadCarrier IcmpV6Pkt where payloadCarried = icmpV6PktPayload

data Teredo = Teredo {
    teredoOrgTag :: !Word16,
    teredoOrgPort :: !Word16,
    teredoAddr :: !Word32,
    teredoAuthTag :: !Word16,
    teredoAuthIdLen :: !Word8,
    teredoAuthAuLen :: !Word8,
    teredoHaveOrg :: Bool,
    teredoHaveAuth :: Bool,
    teredoFixSrc :: Bool,
    teredoFixDst :: Bool
} deriving (Show,Eq)

defaultTeredo :: Teredo
defaultTeredo = Teredo 0 0 0 0 0 0 False False True True
defaultTeredoPacket :: TeredoPkt
defaultTeredoPacket = TeredoPkt defaultTeredo $ PPayload $ Payload 0 0

data TeredoPkt = TeredoPkt {
    teredoPktHeader :: Teredo,
    teredoPktPayload :: Packet
} deriving (Show,Eq)

data EngineId = EngineId {
  eid0 :: Word8,
  eid1 :: Word8,
  eid2 :: Word8,
  eid3 :: Word8,
  eid4 :: Word8,
  eid5 :: Word8
} deriving (Show,Eq)

data ConnSync = ConnSync {
    connSyncVer :: !Word32,
    connSyncArmcs :: !Word32,
    connSyncDst :: !Word32,
    connSyncSrc :: !Word32,
    connSyncType :: !Word8,
    connSyncExtVer :: !Word8,
    connSyncExtEid :: !EngineId,
    connSyncId :: !Word32
} deriving (Show,Eq)

data ConnSyncPkt = ConnSyncPkt {
    connSyncPktHeader :: ConnSync,
    connSyncPktPayload :: [Packet]
} deriving (Show,Eq)

instance PayloadCarrier ConnSyncPkt where payloadCarried = connSyncPktPayload

data ConnSyncSeen = ConnSyncSeen {
    connSyncSeenPcid :: !Word32,
    connSyncSeenPeid :: !EngineId,
    connSyncSeenHasFsService :: !Word8,
    connSyncSeenCtype :: !Word8,
    connSyncSeenBaseService :: !Word32,
    connSyncSeenFsService :: !Word32
} deriving (Show,Eq)

data ConnSyncSeenPkt = ConnSyncSeenPkt {
    connSyncSeenPktHeader :: ConnSyncSeen,
    connSyncSeenPktPayload :: [Packet]
} deriving (Show,Eq)

instance PayloadCarrier ConnSyncSeenPkt where payloadCarried = connSyncSeenPktPayload

data ConnSyncIpv4 = ConnSyncIpv4 {
    connSyncIpv4Int :: !Word32,
    connSyncIpv4Ext :: !Word32,
    connSyncIpv4IntPort :: !Word16,
    connSyncIpv4ExtPort :: !Word16,
    connSyncIpv4Prot :: !Word32
} deriving (Show,Eq)

data ConnSyncIpv4Pkt = ConnSyncIpv4Pkt {
    connSyncIpv4PktHeader :: ConnSyncIpv4,
    connSyncIpv4PktPayload :: [Packet]
} deriving (Show,Eq)

instance PayloadCarrier ConnSyncIpv4Pkt where payloadCarried = connSyncIpv4PktPayload

data ConnSyncUpdate = ConnSyncUpdate {
    connSyncUpdateSeq :: !Word16,
    connSyncUpdateFlags :: !Word8,
    connSyncUpdateService :: !Word32,
    connSyncUpdateCid :: !Word32,
    connSyncUpdateEid :: !EngineId,
    connSyncUpdateIn :: !Word16,
    connSyncUpdateOut :: !Word16
} deriving (Show,Eq)

data ConnSyncUpdatePkt = ConnSyncUpdatePkt {
    connSyncUpdatePktHeader :: ConnSyncUpdate,
    connSyncUpdatePktPayload :: [Packet]
} deriving (Show,Eq)

instance PayloadCarrier ConnSyncUpdatePkt where payloadCarried = connSyncUpdatePktPayload

data Fragv6 = Fragv6 {
    fragv6Nh :: !Word8,
    fragv6Res :: !Word8,
    fragv6Off :: !Word16,
    fragv6Id :: !Word32
} deriving (Show,Eq)

data Fragv6Pkt = Fragv6Pkt {
    fragv6PktHeader :: Fragv6,
    fragv6PktPayload :: [Packet]
} deriving (Show,Eq)

defaultFragv6 :: Fragv6
defaultFragv6 = Fragv6 17 0 0 0
defaultFragv6Packet :: Fragv6Pkt
defaultFragv6Packet = Fragv6Pkt defaultFragv6 [PPayload $ Payload 0 0]

instance PayloadCarrier Fragv6Pkt where payloadCarried = fragv6PktPayload

data HopByHop = HopByHop {
    hopByHopNh :: !Word8,
    hopByHopLen :: !Word8
} deriving (Show,Eq)

data HopByHopPkt = HopByHopPkt {
    hopByHopPktHeader :: HopByHop,
    hopByHopPktPayload :: [Packet]
} deriving (Show,Eq)

defaultHopByHop :: HopByHop
defaultHopByHop = HopByHop 17 0
defaultHopByHopPacket :: HopByHopPkt
defaultHopByHopPacket = HopByHopPkt defaultHopByHop [PPayload $ Payload 0 0]

instance PayloadCarrier HopByHopPkt where payloadCarried = hopByHopPktPayload

data PadN = PadN {
    padNCode :: !Word8,
    padNLen :: !Word8
} deriving (Show,Eq)

data PadNPkt = PadNPkt {
    padNPktHeader :: PadN,
    padNPktPayload :: [Packet]
} deriving (Show,Eq)

defaultPadN :: PadN
defaultPadN = PadN 1 0
defaultPadNPacket :: PadNPkt
defaultPadNPacket = PadNPkt defaultPadN [PPayload $ Payload 0 0]

instance PayloadCarrier PadNPkt where payloadCarried = padNPktPayload

data Payload = Payload {
    payloadPattern :: Word32,
    payloadLength  :: Word16
} deriving (Show,Eq)

defaultPayload :: Payload
defaultPayload = Payload 0 64

data HexPayload = HexPayload {
    hexPayloadData :: [Word8]
} deriving (Show,Eq)

defaultHexPayload  :: HexPayload
defaultHexPayload = HexPayload (replicate 64 0)

data Packet =
    PEth  EthernetFrame
  | PIPv4 IPv4Pkt
  | PUdp UdpPkt
  | PPayload Payload
  | PHexPayload HexPayload
  | PGtp GtpPkt
  | PL2tp L2tpPkt
  | PPpp PppPkt
  | PIPv6 IPv6Pkt
  | PTcp TcpPkt
  | PTeredo TeredoPkt
  | PGre GrePkt
  | PIcmp IcmpPkt
  | PIcmpV6 IcmpV6Pkt
  | PFragv6 Fragv6Pkt
  | PHopByHop HopByHopPkt
  | PPadN PadNPkt
  deriving (Show,Eq)



