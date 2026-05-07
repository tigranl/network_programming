import posix
import tables
import net
import std/strformat
import std/terminal
import strutils
import sequtils
import std/endians

import types

const
  BIOCSETIF = 0x8020426c
  BIOCIMMEDIATE = 0x80044270
  IFNAMSIZ = 16
  BPF_BUF_SIZE = 4096
  BPF_ALIGNMENT = 4

type
  Sockaddr {.importc: "struct sockaddr", header: "<sys/socket.h>", bycopy.} = object
    sa_len: uint8
    sa_family: uint8

  IfAddrs {.importc: "struct ifaddrs", header: "<ifaddrs.h>", bycopy.} = object
    ifa_next: ptr IfAddrs
    ifa_name: cstring
    ifa_flags: cuint
    ifa_addr: ptr Sockaddr

  SockaddrDl {.importc: "struct sockaddr_dl", header: "<net/if_dl.h>", bycopy.} = object
    sdl_len: uint8
    sdl_family: uint8
    sdl_index: uint16
    sdl_type: uint8
    sdl_nlen: uint8
    sdl_alen: uint8
    sdl_slen: uint8
    sdl_data: array[12, char]

const
  AF_LINK = 18'u8
  IFT_ETHER = 0x06'u8

proc ioctl(fd: cint, request: culong, argp: pointer): cint {.importc, header: "<sys/ioctl.h>".}
proc getifaddrs(ifap: ptr ptr IfAddrs): cint {.importc, header: "<net/if.h>".}
proc freeifaddrs(ifap: ptr IfAddrs) {.importc, header: "<ifaddrs.h>".}

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

type
  BPFLinkLayer* = object
    bpf_fd: int
    iface*: string
    my_mac*: MacAddr

type
  FrameData* = object
    dest_mac*: MacAddr
    src_mac*: MacAddr
    eth_type*: uint16
    payload*: seq[uint8]


proc formatMac(mac: openArray[uint8]): string =
  mac.mapIt(fmt"{it:02x}").join(":")

proc build_ethernet_frame*(dest_mac: MacAddr, src_mac: MacAddr, eth_type: uint16, payload: openArray[uint8]): seq[uint8] =
  var frame: seq[uint8] = @[]
  frame.setLen(14 + payload.len) # Ethernet frame is 14 bytes long (dest_mac + src_mac + eth_type) + payload length
  copyMem(addr frame[0], addr dest_mac[0], 6)
  copyMem(addr frame[6], addr src_mac[0], 6)
  bigEndian16(addr frame[12], addr eth_type)
  if payload.len > 0:
    copyMem(addr frame[14], addr payload[0], payload.len)

  frame

proc get_my_mac_addr(self: var BPFLinkLayer): MacAddr =
  var ifap: ptr IfAddrs
  if getifaddrs(addr ifap) != 0:
    raise newException(Exception, "Failed to get interface addresses")

  defer: freeifaddrs(ifap)

  var curr: ptr IfAddrs = ifap
  while curr != nil:
    if curr.ifa_addr != nil and curr.ifa_addr.sa_family == AF_LINK and curr.ifa_name == self.iface.cstring:
      let sdl = cast[ptr SockaddrDl](curr.ifa_addr)
      if sdl.sdl_type == IFT_ETHER and sdl.sdl_alen == 6:
        let macPtr = cast[ptr UncheckedArray[uint8]](
          cast[uint](addr sdl.sdl_data) + sdl.sdl_nlen.uint
        )
        var mac: array[6, uint8]
        for i in 0..5:
          mac[i] = macPtr[i]
        return mac

    curr = curr.ifa_next
  
  raise newException(Exception, "No MAC address found for interface")

proc open_bpf*(self: var BPFLinkLayer) =
  # Try /dev/bpf0 → /dev/bpf255
  var lastError = ""
  for i in 0..255:
    try:
      self.bpf_fd = open(fmt"/dev/bpf{i}".cstring, O_RDWR)
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
  let nameLen = min(self.iface.len, IFNAMSIZ - 1)
  copyMem(addr ifreq.ifr_name[0], self.iface.cstring, nameLen)

  if ioctl(cint(self.bpf_fd), culong(BIOCSETIF), addr ifreq) != 0:
    raise newException(OSError, fmt"BIOCSETIF failed for interface {self.iface}")

  var enable: cuint = 1
  if ioctl(cint(self.bpf_fd), culong(BIOCIMMEDIATE), addr enable) != 0:
    raise newException(OSError, "BIOCIMMEDIATE failed")

  self.my_mac = self.get_my_mac_addr()
  echo fmt"My MAC address: {formatMac(self.my_mac)}"

  echo "Successfully bound to interface"

iterator read_frames*(self: var BPFLinkLayer): FrameData =
  var buf: array[BPF_BUF_SIZE, uint8]
  while true:
    let bytesRead = read(cint(self.bpf_fd), addr buf[0], buf.len)
    if bytesRead <= 0:
      stdout.styledWriteLine(fgRed, "Failed to read\n")
      raise newException(Exception, "Failed to read")

    var pos = 0
    while pos < bytesRead:
      let bh = cast[ptr BPFHeader](addr buf[pos])[]
      let pktStart = pos + bh.bh_hdrlen.int
      let pktEnd = pktStart + bh.bh_caplen.int

      if pktEnd > bytesRead:
        stdout.styledWriteLine(fgRed, "Packet data exceeds buffer length\n")
        raise newException(Exception, "Packet data exceeds buffer length")

      let ethFrame = buf[pktStart ..< pktEnd]
      if ethFrame.len < 14:
        stdout.styledWriteLine(fgRed, "Incomplete Ethernet frame\n")
        raise newException(Exception, "Incomplete Ethernet frame")

      var frame: FrameData
      copyMem(addr frame.dest_mac[0], addr ethFrame[0], 6)
      copyMem(addr frame.src_mac[0], addr ethFrame[6], 6)
      bigEndian16(addr frame.eth_type, addr ethFrame[12])
      frame.payload = ethFrame[14..<ethFrame.len]
      yield frame

      let totalLen = bh.bh_hdrlen.int + bh.bh_caplen.int
      pos += (totalLen + BPF_ALIGNMENT - 1) and not (BPF_ALIGNMENT - 1)

proc send_frame*(self: var BPFLinkLayer, frame: openArray[uint8]) =
  let n = write(cint(self.bpf_fd), addr frame[0], frame.len)
  if n < 0:
    let err = errno
    raise newException(IOError, fmt"BPF write failed: errno={err} ({$strerror(err)})")
  if n != frame.len:
    raise newException(IOError, fmt"BPF short write: {n}/{frame.len}")


if isMainModule:
  var bpf = BPFLinkLayer(iface: "en0")
  bpf.open_bpf()
  for frame in bpf.read_frames():
    let eth_type_str = "0x" & frame.eth_type.toHex(4)
    let eth_type_name = types.ETHERTYPES.getOrDefault(frame.eth_type.int, "Unknown")
    echo fmt"Source MAC: {formatMac(frame.src_mac)}"
    echo fmt"Destination MAC: {formatMac(frame.dest_mac)}"
    echo fmt"EtherType: {eth_type_str} ({eth_type_name})"
    echo fmt"Payload length: {frame.payload.len} bytes"
    echo "Payload: ", frame.payload.mapIt(fmt"{it:02x}").join("")
    echo "---"
