import posix
import tables
import net
import std/strformat
import std/terminal
import strutils
import sequtils
import std/endians
import os

const
  BIOCSETIF = 0x8020426c
  BIOCIMMEDIATE = 0x80044270
  IFNAMSIZ = 16

proc ioctl(fd: cint, request: culong, argp: pointer): cint {.importc, header: "<sys/ioctl.h>".}
type IfReq {.importc: "struct ifreq", header: "<net/if.h>", bycopy.} = object
  ifr_name: array[IFNAMSIZ, char]

type Timeval* {.packed.} = object
  tv_sec: int32
  tv_usec: int32

type BPFHeader* {.packed.} = object
  timeval: Timeval
  bh_caplen: uint32
  bh_datalen: uint32
  bh_hdrlen: uint16

type EthernetHeader {.packed.} = object
  dst: array[6, uint8]
  src: array[6, uint8]
  ethType: uint16

const ETHERTYPES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x0842: "Wake-on-LAN",
    0x22EA: "Stream Reservation Protocol",
    0x22F0: "Audio Video Transport Protocol (AVTP)",
    0x22F3: "IETF TRILL Protocol",
    0x6002: "DEC MOP RC",
    0x6003: "DECnet Phase IV, DNA Routing",
    0x6004: "DEC LAT",
    0x8035: "RARP",
    0x809B: "AppleTalk (EtherTalk)",
    0x80D5: "LLC PDU (IBM SNA)",
    0x80F3: "AppleTalk Address Resolution Protocol (AARP)",
    0x8100: "VLAN-tagged frame (IEEE 802.1Q)",
    0x8102: "Simple Loop Prevention Protocol (SLPP)",
    0x8103: "Virtual Link Aggregation Control Protocol (VLACP)",
    0x8137: "IPX",
    0x8204: "QNX Qnet",
    0x86DD: "IPv6",
    0x8808: "Ethernet flow control",
    0x8809: "Ethernet Slow Protocols (LACP)",
    0x8819: "CobraNet",
    0x8847: "MPLS unicast",
    0x8848: "MPLS multicast",
    0x8863: "PPPoE Discovery Stage",
    0x8864: "PPPoE Session Stage",
    0x887B: "HomePlug 1.0 MME",
    0x888E: "EAP over LAN (IEEE 802.1X)",
    0x8892: "PROFINET Protocol",
    0x889A: "HyperSCSI (SCSI over Ethernet)",
    0x88A2: "ATA over Ethernet",
    0x88A4: "EtherCAT Protocol",
    0x88A8: "Service VLAN tag identifier (S-Tag)",
    0x88AB: "Ethernet Powerlink",
    0x88B8: "GOOSE (Generic Object Oriented Substation event)",
    0x88B9: "GSE (Generic Substation Events) Management Services",
    0x88BA: "SV (Sampled Value Transmission)",
    0x88BF: "MikroTik RoMON",
    0x88CC: "Link Layer Discovery Protocol (LLDP)",
    0x88CD: "SERCOS III",
    0x88E1: "HomePlug Green PHY",
    0x88E3: "Media Redundancy Protocol (IEC62439-2)",
    0x88E5: "IEEE 802.1AE MAC security (MACsec)",
    0x88E7: "Provider Backbone Bridges (PBB) (IEEE 802.1ah)",
    0x88F7: "Precision Time Protocol (PTP) over IEEE 802.3 Ethernet",
    0x88F8: "NC-SI",
    0x88FB: "Parallel Redundancy Protocol (PRP)",
    0x8902: "IEEE 802.1ag Connectivity Fault Management (CFM) Protocol",
    0x8906: "Fibre Channel over Ethernet (FCoE)",
    0x8914: "FCoE Initialization Protocol",
    0x8915: "RDMA over Converged Ethernet (RoCE)",
    0x891D: "TTEthernet Protocol Control Frame (TTE)",
    0x893a: "1905.1 IEEE Protocol",
    0x892F: "High-availability Seamless Redundancy (HSR)",
    0x9000: "Ethernet Configuration Testing Protocol",
    0xF1C1: "Redundancy Tag (IEEE 802.1CB Frame Replication and Elimination for Reliability)"
}.toTable


proc formatMac(mac: openArray[uint8]): string =
  mac.mapIt(fmt"{it:02x}").join(":")

type 
  BPFLinkLayer* = object
    bpf_fd: int
    iface: string
  
proc open_bpf(self: var BPFLinkLayer) =
  # Try /dev/bpf0 → /dev/bpf255
  var lastError = ""
  for i in 0..255:
    try:
      self.bpf_fd = open(fmt"/dev/bpf{i}", O_RDWR)
      if self.bpf_fd != -1:
        echo fmt"Successfully opened /dev/bpf{i} with fd {self.bpf_fd}"
        break
    except OSError as e:
      lastError = fmt"Error opening /dev/bpf{i}: {e.msg}"
      continue
  
  if self.bpf_fd == -1:
    raise newException(Exception, fmt"No available /dev/bpfX devices. Last error: {lastError}")
  
  echo "Opened bpf device"
  # Bind to interface
  var ifreq: IfReq
  copyMem(addr ifreq.ifr_name[0], self.iface.cstring, IFNAMSIZ)

  discard ioctl(cint(self.bpf_fd), culong(BIOCSETIF), addr ifreq)
  discard ioctl(cint(self.bpf_fd), culong(BIOCIMMEDIATE), cint(1))

  echo "Successfully bound to interface"

type
  FrameData = object
    dest_mac: string
    src_mac: string
    eth_type: string
    eth_type_name: string
    payload: seq[uint8]

proc read_frame(self: var BPFLinkLayer): FrameData =
  var buffer: array[4096, uint8]
  let bytesRead = read(cint(self.bpf_fd), addr buffer[0], buffer.len)

  if bytesRead <= 0:
    stdout.styledWriteLine(fgRed, "Failed to read\n")
    raise newException(Exception, "Failed to read")

  let bh = cast[ptr BPFHeader](unsafeAddr buffer[0])[]

  let pktStart = bh.bh_hdrlen.int
  let pktEnd = pktStart + bh.bh_caplen.int

  if pktEnd > buffer.len:
    stdout.styledWriteLine(fgRed, "Packet data exceeds buffer length\n")
    raise newException(Exception, "Packet data exceeds buffer length")

  let ethFrame = buffer[pktStart ..< pktEnd]
  if ethFrame.len < 14:
    stdout.styledWriteLine(fgRed, "Incomplete Ethernet frame\n")
    raise newException(Exception, "Incomplete Ethernet frame")

  let dest_mac = ethFrame[0..5]
  let src_mac = ethFrame[6..11]
  var eth_type: uint16
  bigEndian16(addr eth_type, unsafeAddr ethFrame[12])
  let payload = ethFrame[14..<ethFrame.len]

  let dest_mac_str = formatMac(dest_mac)
  let src_mac_str = formatMac(src_mac)
  let eth_type_str = "0x" & eth_type.toHex(4)

  result = FrameData(
    dest_mac: dest_mac_str,
    src_mac: src_mac_str,
    eth_type: eth_type_str,
    eth_type_name: ETHERTYPES.getOrDefault(int(eth_type), "Unknown"),
    payload: @payload
  )

if isMainModule:
  var bpf = BPFLinkLayer(iface: "en0")
  bpf.open_bpf()
  while true:
    let frame = bpf.read_frame()
    echo fmt"Source MAC: {frame.src_mac}"
    echo fmt"Destination MAC: {frame.dest_mac}"
    echo fmt"EtherType: {frame.eth_type} ({frame.eth_type_name})"
    echo fmt"Payload length: {frame.payload.len} bytes"
    echo "Payload: ", frame.payload.mapIt(fmt"{it:02x}").join("")
    echo "---"
