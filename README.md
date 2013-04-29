rws
===

Rws generates a pcap from a simple packet descriptor language.  The pcaps can
then be used for testing together with tools such as tcpreplay. It is
especially use full to generate invalid packets that no off-the-shelf traffic
generator would be able to generate, e.g a corrupt TCP packet that is tunneled
inside a Teredo tunnel that is sent over GTP-u. If a field in a protocol isn't
specified resonable defaults are used.

RWS supports:
- Ethernet
- Fragv6 option
- GRE
- GTP-u
- Hexpayload
- HopByHop option
- Icmp
- IcmpV6
- IPv4
- IPv6
- L2TP
- PadN option
- PPP
- TCP
- Teredo
- UDP

Numerous examples are provided in the samples dir.

Example:
Given the file simple.pkt which contains:
(eth (ipv4 src=2.2.2.2 dst=10.10.10.10 (udp)))
the command:
./dist/build/rws/rws -i simple.pkt -o out.pcap

will generate a pcap file with a single UDP packet from 2.2.2.2 to 10.10.10.10.

