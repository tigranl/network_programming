import std/tables
import std/endians
import std/options
import std/strformat

import types

import link_layer

const
  ArpHwEthernet = 1'u16
  ArpProtoIPv4  = 0x0800'u16
  ArpOpRequest  = 1'u16
  ArpOpReply    = 2'u16
  EthertypeArp* = 0x0806'u16

type
  ArpFrame* = object
    htype*: uint16         ## 1 = Ethernet
    ptype*: uint16         ## 0x0800 = IPv4
    hlen*: uint8           ## byte 4 on wire
    plen*: uint8           ## byte 5 on wire
    op*: uint16            ## 1 = request, 2 = reply (bytes 6–7, big-endian)
    sha*: MacAddr          ## sender MAC
    spa*: IPv4Addr         ## sender IPv4
    tha*: MacAddr          ## target MAC
    tpa*: IPv4Addr         ## target IPv4


proc `$`(arp: ArpFrame): string =
  let opName =
    if arp.op == ArpOpRequest: "REQ"
    elif arp.op == ArpOpReply: "REP"
    else: "???"
  fmt"ARP {opName}: {arp.spa[0]}.{arp.spa[1]}.{arp.spa[2]}.{arp.spa[3]} ({arp.sha[0]:02x}:{arp.sha[1]:02x}:{arp.sha[2]:02x}:{arp.sha[3]:02x}:{arp.sha[4]:02x}:{arp.sha[5]:02x}) -> {arp.tpa[0]}.{arp.tpa[1]}.{arp.tpa[2]}.{arp.tpa[3]}"

type
  ArpCache* = Table[IPv4Addr, MacAddr]

type
  ArpCtx* = object
    bpf*: BPFLinkLayer
    cache*: ArpCache
    my_ip*: IPv4Addr

proc parse_arp_frame*(frame: link_layer.FrameData): Option[ArpFrame] =
  if frame.payload.len < 28:
    return none(ArpFrame)

  var arp_frame: ArpFrame

  let p = frame.payload
  bigEndian16(addr arp_frame.htype, addr p[0])
  bigEndian16(addr arp_frame.ptype, addr p[2])
  arp_frame.hlen = p[4]
  arp_frame.plen = p[5]
  bigEndian16(addr arp_frame.op, addr p[6])
  copyMem(addr arp_frame.sha[0], addr p[8], 6)
  copyMem(addr arp_frame.spa[0], addr p[14], 4)
  copyMem(addr arp_frame.tha[0], addr p[18], 6)
  copyMem(addr arp_frame.tpa[0], addr p[24], 4)

  if arp_frame.htype != ArpHwEthernet or arp_frame.ptype != ArpProtoIPv4 or arp_frame.hlen != 6'u8 or arp_frame.plen != 4'u8:
    return none(ArpFrame)

  some(arp_frame)

proc build_arp_frame*(arp_frame: ArpFrame): seq[uint8] =
  result.setLen(28)
  bigEndian16(addr result[0], addr arp_frame.htype)
  bigEndian16(addr result[2], addr arp_frame.ptype)
  result[4] = arp_frame.hlen
  result[5] = arp_frame.plen
  bigEndian16(addr result[6], addr arp_frame.op)
  copyMem(addr result[8], addr arp_frame.sha[0], 6)
  copyMem(addr result[14], addr arp_frame.spa[0], 4)
  copyMem(addr result[18], addr arp_frame.tha[0], 6)
  copyMem(addr result[24], addr arp_frame.tpa[0], 4)

proc send_arp_reply*(ctx: var ArpCtx, arp: ArpFrame) =
  var reply: ArpFrame
  reply.htype = ArpHwEthernet
  reply.ptype = ArpProtoIPv4
  reply.hlen = 6
  reply.plen = 4
  reply.op = ArpOpReply
  reply.sha = ctx.bpf.my_mac
  reply.spa = ctx.my_ip
  reply.tha = arp.sha
  reply.tpa = arp.spa

  let arpBytes = build_arp_frame(reply)
  let eth = build_ethernet_frame(arp.sha, ctx.bpf.my_mac, EthertypeArp, arpBytes)
  send_frame(ctx.bpf, eth)

proc handle_arp_ingress*(ctx: var ArpCtx, frame: link_layer.FrameData) =
  if frame.eth_type != EthertypeArp:
    return
  let arpOpt = parse_arp_frame(frame)
  if arpOpt.isNone:
    return
  let arp = get(arpOpt)

  if arp.sha == ctx.bpf.my_mac:
    return  # ignore our own outbound frames captured via BPF loopback

  echo arp
  # Learn from every ARP packet we observe (RFC 826).
  ctx.cache[arp.spa] = arp.sha
  
  case arp.op
  of ArpOpRequest:
    if arp.tpa == ctx.my_ip:
      echo "Sending ARP reply"
      send_arp_reply(ctx, arp)
  of ArpOpReply:
    discard  # Cache already updated above; no further action.
  else:
    discard  # Unknown opcode (RARP, InARP, etc.); ignore.

  echo "ARP ingress handled"


when isMainModule:
  var ctx = ArpCtx(
    bpf: BPFLinkLayer(iface: "feth1"),
    cache: initTable[IPv4Addr, MacAddr](),
    my_ip: [192'u8, 168, 42, 2],
  )
  ctx.bpf.open_bpf()
  for frame in ctx.bpf.read_frames():
    handle_arp_ingress(ctx, frame)
