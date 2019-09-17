#!/usr/bin/python

import socket
import struct
import binascii

while True:
#PF_PACKET we say the kernel to use the packet interface (PF_PACKET) and raw socket (SOCK_RAW)
#0x0800 indicates which protocol are interested in (IP Protocol), for checking the numbers
#cat /usr/include/linux/if_ether.h
    rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))

#read a packet with maximum buffer 65536,32768
    pkt = rawSocket.recvfrom(65536)

##############ethernet header###########################################
#inside the first element of the packet, choose the first 14 bytes
    ethernetHeader = pkt[0][0:14]
#now we should unpack the data we have choosen from the packet
#choose the first 6 bytes then 6 more and last 2 more
    eth_hdr = struct.unpack("!6s6s2s", ethernetHeader)
    binascii.hexlify(eth_hdr[0])
    #source IP address
    binascii.hexlify(eth_hdr[1])
    #destination IP address
    binascii.hexlify(eth_hdr[2])
###############ip header################################################
    ipHeader = pkt[0][14:34]
    ip_hdr = struct.unpack("!12s4s4s", ipHeader)

    #function inet_ntoa print network to ascii
    #print "Source IP address: " + socket.inet_ntoa(ip_hdr[1])

    #print "Destination IP address: " + socket.inet_ntoa(ip_hdr[2])

##############tcp header####################################################
#initial part of the tcp headers

    tcpHeader = pkt[0][34:54]
#for tcp HH-> unsigned short
    tcp_hdr = struct.unpack("!HH16s", tcpHeader)

##############smb2 header####################################################

    #smb2header protocolid -> smb2
    smb2Header1 = pkt[0][58:62]
    #smb2header , command field -> negotiate protocol
    smb2Header2 = pkt[0][80:82]

    #smb2 negotiate protocl , structure size -> RESPONSE
    smb2Negotiate_Protocol_Request = pkt[0][122:124]

    #smb2 negotiate protocol
    smb2Negotiate_Protocol = pkt[0][124:126]

    #Return the hexadecimal representation of the binary data -> string
    smb_packet_header_component = binascii.hexlify(smb2Header1)

    smb_packet_header_command = binascii.hexlify(smb2Header2)

    structure_size = binascii.hexlify(smb2Negotiate_Protocol_Request)

    security_mode = binascii.hexlify(smb2Negotiate_Protocol)

#checking for smb2 protocol, espacially the negotiate protocol response packet only
    if smb_packet_header_component == 'fe534d42' and smb_packet_header_command == '0000' and structure_size == '4100':
        print "#############################################################"
        print "The ProtocolID (Server Component) is: " + smb_packet_header_component
        print "The Command field is: " + smb_packet_header_command
        print "-----------------------------------------------------------"
        #inet_ntoa -> network to ascii
        print "Source IP address: " + socket.inet_ntoa(ip_hdr[1])
        print "Destination IP address: " + socket.inet_ntoa(ip_hdr[2])
        print "-----------------------------------------------------------"

        print "The structure size is: " + structure_size
        print "The security mode is: " + security_mode
        print "############################################################"

    else :
        pass

