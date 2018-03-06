#!/usr/bin/python

import pcapy
import socket
import sys
import re
import time
import json
import cPickle as pickle
import sqlite3
from impacket import ImpactDecoder
from operator import itemgetter
from itertools import groupby
from collections import defaultdict
#from pynput import keyboard
import string
import pdb

# Because everyone needs a cool banner
banner = """
   ___          __       _____        
  / _ \_______ / /  ___ / / (_)______ 
 / ___/ __/ -_) _ \/ -_) / / / __/ _ \\
/_/  /_/  \__/_.__/\__/_/_/_/\__/\___/
"""
print(banner)
time.sleep(1)
print("\nThere is no patch for passive recon. ;)")
time.sleep(3)

# Define some keyboard input listeners to provide the user with dynamic updates - This doesn't appear to work well with xorg.
#def on_press(key):
#    try:
#        print('alphanumeric key {0} pressed'.format(key.char))
#        return False
#    except AttributeError:
#        print('special key {0} pressed'.format(key))
#    else:
#        return False

#def on_release(key):
#    #print('{0} released'.format(key))
#    if key == 'Null':
#        #Stop listener
#        return False 

#def listen():
#    listener = keyboard.Listener(on_press=on_press,on_release = on_release)
#    listener.start()

# This just isn't working now. Need to rethink the data structure
# intelligence = [ {'host':'ip'}, {'hwaddr':'null'}, {'openports':'ports'}, {'os':'null'}, {'trustedhosts','null'}, ('vulns':'null'}, {'updatetime':'null'} ]
# intelligence = [ [ 'host', 'port' ] ]

# Define a data dictionary for open TCP ports using hosts as keys and ports as values
tcpintelligence = defaultdict(set)

# Define a data dictionary for open UDP ports using hsots as keys and ports as values
udpintelligence = defaultdict(set)

# Define a data dictionary for captured SNMP strings using the snmp string as the key and hosts as the value
snmpstrings = defaultdict(set)

# Define a data dictionary for TCP IPID squence numbers to look for zombie hosts
tcpipidnumbers = defaultdict(list)

# Define a data dictionary for zombie hosts
zombiehosts = defaultdict(set)

# Define a data dictonary for arp requests using the IP address as keys and their MAC address as values
arpintelligence = defaultdict(set)

# Define a data dictionary for icmp requests using the IP address as keys 
icmpintelligence = defaultdict(set)

# Define a data dictionary for trusted relationships based upon trusted TCP connections using the ip address of the host responding to a syn request as the key and the trusted host as the value
trustedintelligence = defaultdict(set)

# Define a data dictionary for known networks based upon the networks that source hosts appear to belong to.
knownnets = defaultdict(set)

# Define a data dictionary for external hosts based upon the internet hosts the internal hosts connect to.
externalhosts = defaultdict(set)
tcpnetworkegresspermitted = 0
udpnetworkegresspermitted = 0
icmpnetworkegresspermitted = 0

# Define a data dictionary for SMB Mailslot Browse intelligence using the host IP as the key
mailslotbrowser = defaultdict(set)

# Define a variable to control output of HSRP traffic - This is temporary until this is more built out.
HSRPnotification = 0

# Function to detect the protcol used within the packet to steer accordingly.
def inspectproto(header, data):

	# Start to decode the packet, determine the protocol number and call the appropriate method.
        #print("\nTop of the inspectproto method.\n")
        #sniff.setfilter('ip or ip6 or arp or aarp')
	ethernet_packet = decoder.decode(data)
        protocolnumber = decoder.decode(data).child().child().protocol
        #print ethernet_packet
        #print dir(ethernet_packet)
        #print ethernet_packet.child()
        #print dir(ethernet_packet.child())
        #print ethernet_packet.child().child()
        #print dir(ethernet_packet.child().child())
        #print ethernet_packet.child().child().get_SYN()
        #print ethernet_packet.child().child().get_ACK()
        #print ethernet_packet.child().child().get_ECE()
        #print ethernet_packet.child().child().get_CWR()
        #print ethernet_packet.child().child().get_FIN()
        #print ethernet_packet.child().child().get_PSH()
        #print ethernet_packet.child().child().get_RST()
        #print ethernet_packet.child().child().get_URG()
        #print(dir(header))
        #print header
        #print(dir(data))
        #print data
        #print(dir(ethernet_packet))
        #print ethernet_packet
        #print("The protocol number is %s.") % ( protocolnumber)
        if protocolnumber == 1:
            #print("\nThis is an ICMP packet.")
            #print ethernet_packet.child().child().ICMP_ALTHOSTADDR
            #print ethernet_packet.child().child().ICMP_ECHO
            #print ethernet_packet.child().child().ICMP_ECHOREPLY
            #print ethernet_packet.child().child().ICMP_IREQ
            #print ethernet_packet.child().child().ICMP_IREQREPLY
            #print ethernet_packet.child().child().ICMP_MASKREPLY
            #print ethernet_packet.child().child().ICMP_MASKREQ
            #print ethernet_packet.child().child().ICMP_PARAMPROB
            #print ethernet_packet.child().child().ICMP_PARAMPROB_ERRATPTR
            #print ethernet_packet.child().child().ICMP_PARAMPROB_LENGTH
            #print ethernet_packet.child().child().ICMP_PARAMPROB_OPTABSENT
            #print ethernet_packet.child().child().ICMP_REDIRECT
            #print ethernet_packet.child().child().ICMP_REDIRECT_HOST
            #print ethernet_packet.child().child().ICMP_REDIRECT_NET
            #print ethernet_packet.child().child().ICMP_REDIRECT_TOSHOST
            #print ethernet_packet.child().child().ICMP_REDIRECT_TOSNET
            #print ethernet_packet.child().child().ICMP_ROUTERADVERT
            #print ethernet_packet.child().child().ICMP_ROUTERSOLICIT
            #print ethernet_packet.child().child().ICMP_SOURCEQUENCH
            #print ethernet_packet.child().child().ICMP_TIMXCEED
            #print ethernet_packet.child().child().ICMP_TIMXCEED_INTRANS
            #print ethernet_packet.child().child().ICMP_TIMXCEED_REASS
            #print ethernet_packet.child().child().ICMP_TSTAMP
            #print ethernet_packet.child().child().ICMP_TSTAMPREPLY
            #print ethernet_packet.child().child().ICMP_UNREACH
            #print ethernet_packet.child().child().ICMP_UNREACH_FILTERPROHIB
            #print ethernet_packet.child().child().ICMP_UNREACH_HOST
            #print ethernet_packet.child().child().ICMP_UNREACH_HOST_PRECEDENCE
            #print ethernet_packet.child().child().ICMP_UNREACH_HOST_PROHIB
            #print ethernet_packet.child().child().ICMP_UNREACH_HOST_UNKNOWN
            #print ethernet_packet.child().child().ICMP_UNREACH_ISOLATED
            #print ethernet_packet.child().child().ICMP_UNREACH_NEEDFRAG
            #print ethernet_packet.child().child().ICMP_UNREACH_NET
            #print ethernet_packet.child().child().ICMP_UNREACH_NET_PROHIB
            #print ethernet_packet.child().child().ICMP_UNREACH_NET_UNKNOWN
            #print ethernet_packet.child().child().ICMP_UNREACH_PORT
            #print ethernet_packet.child().child().ICMP_UNREACH_PRECEDENCE_CUTOFF
            #print ethernet_packet.child().child().ICMP_UNREACH_PROTOCOL
            #print ethernet_packet.child().child().ICMP_UNREACH_SRCFAIL
            #print ethernet_packet.child().child().ICMP_UNREACH_TOSHOST
            #print ethernet_packet.child().child().ICMP_UNREACH_TOSNET
            #print ethernet_packet.child().child().isQuery()
            #print ethernet_packet.child().child().isDestinationUnreachable()
            #print ethernet_packet.child().child().isHostUnreachable()
            #print ethernet_packet.child().child().isProtocolUnreachable
            #print ethernet_packet.child().child().get_icmp_type()
            #print("\nThis is the endof of the header.")
            icmpdiscovery(header,data)
            return
        elif protocolnumber == 4:
            #print("\nThis is an IP packet.")
            return
        elif protocolnumber == 6:
            #print("\nThis is a TCP packet.")
            # Pull TCP flags to determine tcp session state so that we can determine what TCP method to call for intel. 
            tcp_syn = ethernet_packet.child().child().get_SYN()
            tcp_ack = ethernet_packet.child().child().get_ACK()
            tcp_ece = ethernet_packet.child().child().get_ECE()
            tcp_cwr = ethernet_packet.child().child().get_CWR()
            tcp_fin = ethernet_packet.child().child().get_FIN()
            tcp_psh = ethernet_packet.child().child().get_PSH()
            tcp_rst = ethernet_packet.child().child().get_RST()
            tcp_urg = ethernet_packet.child().child().get_URG()
            if ( tcp_syn == 1 and tcp_ack == 1 ):
                synackdiscovery(header,data)
            tcpdiscovery(header,data)
            return
        elif protocolnumber == 17:
            #print("\nThis is a UDP packet.")
            udpdiscovery(header,data)
            return
        elif protocolnumber == 41:
            #print("\nThis is an IPv6 encapulated packet.")
            return
        elif protocolnumber == 43:
            #print("\nThis is an IPv6 routing header packet.")
            return
        elif protocolnumber == 44:
            #print("\nThis is an IPv6 fragment header packet.")
            return
        elif protocolnumber == 58:
            #print("\nThis is an IPv6 ICMP packet.")
            return
        elif protocolnumber == 59:
            #print("\nThis is an IPv6 no next header packet.")
            return
        elif protocolnumber == 60:
            #print("\nThis is an IPv6 destination options packet.")
            return
        # This is not an accurate catchall and will more than likely fail at some point
        elif protocolnumber == None:
            #print("\nThis is not an IP packet. More than likely ARP.")
            #arpheader = decoder.decode(data).child().get_op_name()
            #print("\nWe have an arp packet baby: %s!") % ( arpheader )
            return
        else:
            #print("\nThe protocol number in this packet is %s. This is not TCP.") % ( protocolnumber )
            #print("\nEnd of the inspectproto method.\n")
            return
        #pdb.set_trace()
        #sniff.next

# Function designed to sniff out intel tied to ICMP traffic
def icmpdiscovery(header,data):
        #print("\nStart of the icmpdiscovery method.\n")
	ethernet_packet = decoder.decode(data)
        protocolnumber = decoder.decode(data).child().child().protocol
        if protocolnumber != 1:
            return
        ip_hdr = ethernet_packet.child()
        source_ip = ip_hdr.get_ip_src()
        dest_ip = ip_hdr.get_ip_dst()
        icmp_hdr = ethernet_packet.child().child()
        unknownsourcenetwork = 0
        unknowndestnetwork = 0
        unknownexternalhost = 0
        hostexists = 0

        # Work to determine if this is an icmp echo or echo reply. This is important, as it will allow us to determine if ICMP is permitted egress for C2 uses.
        if ( icmp_hdr.get_type_name(icmp_hdr.get_icmp_type()) == "ECHO" ): 
            # For each host listed as a key in our data dictionary, compare the actual host to the key. If it matches, make note of it by setting hostexists to '1'
            for host in tcpintelligence.keys():
                if source_ip == host:
                    hostexists = 1
            for host in udpintelligence.keys():
                if source_ip == host:
                    hostexists = 1
            for host in icmpintelligence.keys():
                if source_ip == host:
                    hostexists = 1
            if ( hostexists == 0 ):
                print("\n-=-ICMP Recon-=-\nIdentified a host through ICMP(%s): %s") % ( icmp_hdr.get_type_name(icmp_hdr.get_icmp_type()), source_ip )
                icmpintelligence[source_ip].update(source_ip)
                #tcpintelligence[source_ip].add()
                #udpintelligence[source_ip].add()


            # Look to see if the IP address appears to belong to a set of known nets. If not alert the user of the known net and update the knownnets datadictionary - there is a bug here - I don't manage IPv6 properly yet.
            rfc1918addressregex = re.compile('^(127\.)|(192\.168\.)|(10\.)|(172\.1[6-9]\.)|(172\.2[0-9]\.)|(172\.3[0-1]\.)')#  Add this when IPv6 is ready: |(::1$)|([fF][cCdD])')
            sourcematch = rfc1918addressregex.match(source_ip)
            #destmatch = rfc1918addressregex.match(dest_ip)
            if sourcematch:# or destmatch:
                source_ip_octets = source_ip.split('.')
                source_network = source_ip_octets[0] + '.' + source_ip_octets[1] + '.' + source_ip_octets [2] + '.1/24'
                #dest_ip_octets = dest_ip.split('.')
                #dest_network = dest_ip_octets[0] + '.' + dest_ip_octets[1] + '.' + dest_ip_octets[2] + '.1/24'
                for known_network in knownnets.keys():
                    if source_network == known_network:
                        unknownsourcenetwork = 1
                #if destmatch:
                    #for known_network in knownnets.keys():
                        #if dest_network == known_network:
                            #unknowndestnetwork = 1
                if unknownsourcenetwork == 0 and sourcematch:
                    print ("\n-=-Network Recon-=-\nA new network has been identified: %s") % (source_network)
                    knownnets[source_network].add(source_ip)
                #if unknowndestnetwork == 0 and destmatch:
                    #if source_network != dest_network:
                        #print ("\n-=-Network Recon-=-\nA new network has been identified: %s") % (dest_network)
                        #knownnets[dest_network].add(dest_ip)

        if ( icmp_hdr.get_type_name(icmp_hdr.get_icmp_type()) == "ECHOREPLY" ): 
            # For each host listed as a key in our data dictionary, compare the actual host to the key. If it matches, make note of it by setting hostexists to '1'
            for host in tcpintelligence.keys():
                if source_ip == host:
                    hostexists = 1
            for host in udpintelligence.keys():
                if source_ip == host:
                    hostexists = 1
            for host in icmpintelligence.keys():
                if source_ip == host:
                    hostexists = 1
            rfc1918addressregex = re.compile('^(127\.)|(192\.168\.)|(10\.)|(172\.1[6-9]\.)|(172\.2[0-9]\.)|(172\.3[0-1]\.)')#  Add this when IPv6 is ready: |(::1$)|([fF][cCdD])')
            sourcematch = rfc1918addressregex.match(source_ip)
            if ( hostexists == 0 and sourcematch):
                print("\n-=-ICMP Recon-=-\nIdentified a host through ICMP(%s): %s") % ( icmp_hdr.get_type_name(icmp_hdr.get_icmp_type()), source_ip)
                icmpintelligence[source_ip].update(source_ip)
                #tcpintelligence[source_ip].add()
                #udpintelligence[source_ip].add()


            # Look to see if the IP address appears to belong to a set of known nets. If not alert the user of the known net and update the knownnets datadictionary - there is a bug here - I don't manage IPv6 properly yet.
            rfc1918addressregex = re.compile('^(127\.)|(192\.168\.)|(10\.)|(172\.1[6-9]\.)|(172\.2[0-9]\.)|(172\.3[0-1]\.)')#  Add this when IPv6 is ready: |(::1$)|([fF][cCdD])')
            sourcematch = rfc1918addressregex.match(source_ip)
            destmatch = rfc1918addressregex.match(dest_ip)
            if sourcematch:#destmatch:
                source_ip_octets = source_ip.split('.')
                source_network = source_ip_octets[0] + '.' + source_ip_octets[1] + '.' + source_ip_octets [2] + '.1/24'
                #dest_ip_octets = dest_ip.split('.')
                #dest_network = dest_ip_octets[0] + '.' + dest_ip_octets[1] + '.' + dest_ip_octets[2] + '.1/24'
                #if sourcematch:
                for known_network in knownnets.keys():
                    if source_network == known_network:
                        unknownsourcenetwork = 1
                #for known_network in knownnets.keys():
                    #if dest_network == known_network:
                        #unknowndestnetwork = 1
                if unknownsourcenetwork == 0 and sourcematch:
                    print ("\n-=-Network Recon-=-\nA new network has been identified: %s") % (source_network)
                    knownnets[source_network].add(source_ip)
                #if unknowndestnetwork == 0 and destmatch:
                    #if source_network != dest_network:
                        #print ("\n-=-Network Recon-=-\nA new network has been identified: %s") % (dest_network)
                        #knownnets[dest_network].add(dest_ip)

            # If a host does not match an RFC1918 address that an RFC1918 address is talking to note the external host and the internal host permitted to talk to it and notify the user about the permitted connection
            if not sourcematch and destmatch:
                global icmpnetworkegresspermitted
                if icmpnetworkegresspermitted == 0:
                    print ("\n-=-Egress Recon-=-\nNetwork egress detected! Internal hosts are permitted to ping the internet.")
                    icmpnetworkegresspermitted = 1
                #for externalhost in externalhosts.keys():
                #    if source_ip == externalhost:
                #        unknownexternalhost = 1
                #if unknownexternalhost == 0 and icmpnetworkegresspermitted == 1:
                #    externalhosts[source_ip].add(dest_ip)
                #    print("\n-=-Egress Recon Update-=-\n%s is permitted to connect to %s on UDP port %s.") % (dest_ip, source_ip, udp_source_port)


        #print("\nEnd of the icmpdiscovery method.\n")

# Function designed to sniff out intel tied to generic UDP intelligence such as SMB and SNMP traffic
def udpdiscovery(header,data):

        #print("\nStart of udpdiscovery method.\n")
        #sniff.setfilter('udp')
       	# Start to decode the packet and determine the protocol number. If not UDP, return as it does not apply here.
	ethernet_packet = decoder.decode(data)
        protocolnumber = decoder.decode(data).child().child().protocol
        if protocolnumber != 17:
            return 
	# Extract relivant data from the ethernet packet
	mac_hdr = ethernet_packet
	source_mac = mac_hdr.as_eth_addr(mac_hdr.get_ether_shost())
	dest_mac = mac_hdr.as_eth_addr(mac_hdr.get_ether_dhost())
	ip_hdr = ethernet_packet.child()
	udp_hdr = ip_hdr.child()
	source_ip = ip_hdr.get_ip_src()
        dest_ip = ip_hdr.get_ip_dst()
        udp_source_port = udp_hdr.get_uh_sport()
        udp_dest_port = udp_hdr.get_uh_dport()

	# Define control variables to control message output of discovered hosts
	hostexists = 0
	portexists = 0
	srcarpexists = 0
	dstarpexists = 0
        unknownsourcenetwork = 0
        unknowndestnetwork = 0
        unknownexternalhost = 0
        notnewsnmpstringhost = 0
        unknownmailslotbrowserhost = 0

        # Look to see if the IP address appears to belong to a set of known nets. If not alert the user of the known net and update the knownnets datadictionary - there is a bug here - I don't manage IPv6 properly yet.
        rfc1918addressregex = re.compile('^(127\.)|(192\.168\.)|(10\.)|(172\.1[6-9]\.)|(172\.2[0-9]\.)|(172\.3[0-1]\.)')#  Add this when IPv6 is ready: |(::1$)|([fF][cCdD])')
        sourcematch = rfc1918addressregex.match(source_ip)
        destmatch = rfc1918addressregex.match(dest_ip)
        if sourcematch or destmatch:
            source_ip_octets = source_ip.split('.')
            source_network = source_ip_octets[0] + '.' + source_ip_octets[1] + '.' + source_ip_octets [2] + '.1/24'
            dest_ip_octets = dest_ip.split('.')
            dest_network = dest_ip_octets[0] + '.' + dest_ip_octets[1] + '.' + dest_ip_octets[2] + '.1/24'
            if sourcematch:
                for known_network in knownnets.keys():
                    if source_network == known_network:
                        unknownsourcenetwork = 1
            if destmatch:
                for known_network in knownnets.keys():
                    if dest_network == known_network:
                        unknowndestnetwork = 1
            if unknownsourcenetwork == 0 and sourcematch:
                print ("\n-=-Network Recon-=-\nA new network has been identified: %s") % (source_network)
                knownnets[source_network].add(source_ip)
            if unknowndestnetwork == 0 and destmatch:
                if source_network != dest_network:
                    print ("\n-=-Network Recon-=-\nA new network has been identified: %s") % (dest_network)
                    knownnets[dest_network].add(dest_ip)

        # If a host does not match an RFC1918 address that an RFC1918 address is talking to note the external host and the internal host permitted to talk to it and notify the user about the permitted connection
        if not sourcematch and destmatch:
            global udpnetworkegresspermitted
            if udpnetworkegresspermitted == 0:
                print ("\n-=-Egress Recon-=-\nNetwork egress detected! Internal hosts are permitted to connect to the internet via UDP.")
                udpnetworkegresspermitted = 1
            for externalhost in externalhosts.keys():
                if source_ip == externalhost:
                        unknownexternalhost = 1
            if unknownexternalhost == 0 and udpnetworkegresspermitted == 1:
                externalhosts[source_ip].add(dest_ip)
                print("\n-=-Egress Recon Update-=-\n%s is permitted to connect to %s on UDP port %s.") % (dest_ip, source_ip, udp_source_port)

	# For each host listed as a key in our host data dictionarys, compare the actual host to the key. If it matches, make note of it by setting hostexists to '1'
        if udp_source_port <= 8000:
            for host in udpintelligence.keys():
                if source_ip == host:
                    hostexists = 1
            for externalhost in externalhosts.keys():
                if source_ip == externalhost:
                    hostexists = 1
            for host in tcpintelligence.keys():
                if source_ip == host:
                    hostexists = 1
        tempdata = udp_hdr.get_data_as_string()
        #print(dir(udp_hdr))
        #print tempdata
        #print("UDP packet header contents:\n%s") % ( udp_hdr)
        #print("\n\nudp_source_port = %s.") % ( udp_source_port)

	# If hostexists 0 and the source port is less than 8000, indicating a new host has been identified, notify the user and add the host and port to the data dictionary using the host as a key value
	if ( hostexists == 0 and udp_source_port <=8000 ):
            print("\n-=-Host Recon-=-\nA new host was identified with an open UDP port: %s:%s") % (source_ip, udp_source_port)
    	    arpintelligence[source_ip].add(source_mac)
	    arpintelligence[dest_ip].add(dest_mac)
	    udpintelligence[source_ip].add(udp_source_port)
	    trustedintelligence[source_ip].add(dest_ip)
        
        # If we have a response from a host on port 161, notify the user and extract the SNMP string - note this is buggy as there is not SNMP packet verification
        if udp_source_port == 161:
            snmppacketfilterregex = re.compile('[a-zA-Z0-9.*].*(?=:)')# Regex to yank data before colon within snmp string data
            snmptempdata = snmppacketfilterregex.findall(tempdata)
            printable = set(string.printable)
            print printable
            communitystring = filter(lambda x: x in printable, snmptempdata[0])
            print communitystring
            communitystring = communitystring[2:]
            if communitystring in snmpstrings.keys():
                for host in snmpstrings[string]:
                    if host == source_ip:
                        notnewsnmpstringhost = 1
                    if notnewsnmpstringhost != 1:
                        snmpstrings[communitystring].add(source_ip)
                        print("\n-=-SNMP Recon Update-=-\n A new host has been identified which uses the '%s' SNMP community string: %s.\nThe following hosts are configured with this SNMP community string:\n") % ( communitystring, source_ip )
                        for host in snmpstrings[string]:
                            print("%s, ") % ( host ),
            else:
                print("\n-=-SNMP Recon-=- We have a new SNMPv1 community string from %s: %s\n") % ( source_ip, communitystring ) 
                snmpstrings[communitystring].add(source_ip)

        # If we have an SMB packet, extract intelligence from this - this is going to be bigger than simply dumping the packets. Going to require classification of types of requests
        if ( udp_source_port == 138 ):
            for knownmailslotbrowserhost in mailslotbrowser.keys():
                if knownmailslotbrowserhost == source_ip:
                    unknownmailslotbrowserhost = 1
            if unknownmailslotbrowserhost == 0:        
                mailslotmatch = re.search("\\MAILSLOT.*BROWSE", ethernet_packet.child().child().child().get_buffer_as_string(), re.MULTILINE)
                if mailslotmatch:
                    mailslotstring = re.findall("(?<=\n\x00)(?!\x03\x90\x00)[\w\-\!\@\$\%\^\&\(\)\+\=\[\]\{\}\'\;\~\`]{1,15}(?=\x00)|(?<=\x0f\x01U\xaa)(?!\x03\x90\x00)[\w\s\:\-\=\_\-\+\[\]\{\}\!\@\#\$\%\^\&\*\(\)\'\"\:\;\~\`]+(?=\x00)", ethernet_packet.child().child().child().get_buffer_as_string(), re.MULTILINE)
                    if len(mailslotstring) == 1:
                        print('\n-=-SMB Recon-=-\nThe hostname for \'%s\' is \'%s\'') % ( source_ip, mailslotstring[0] )
                        mailslotbrowser[source_ip].add(mailslotstring[0])
                    if len(mailslotstring) == 2:
                        print('\n-=-SMB Recon-=-\nThe hostname for \'%s\' is \'%s\' and it describes itself as \'%s\'') % ( source_ip, mailslotstring[0], mailslotstring[1] )
                        mailslotbrowser[source_ip].add(mailslotstring[0])
                        mailslotbrowser[source_ip].add(mailslotstring[1])

        # Work support for HSRP protocol
        global HSRPnotification
        if ( udp_source_port == 1985 and HSRPnotification != 1 ):
            print('\n-=-Layer2/3 Recon-=-\nCisco HSRP is spoken here')
            HSRPnotification = 1
            #print('\n-=-Layer2/3 Recon-=-\nWe have an HSRP packet:\n%s\n\n\n\n%s\n\n\n\n%s\n') % ( ethernet_packet.child().child().child().get_buffer_as_string(), ethernet_packet.child().child().child(), data )
        #print("\nEnd of udpdiscovery method.\n")
        return

#	    # Using the source ip address as a key within the data dictionary, for each port listed see if it matches the source port captured witin the packet. If it is a match, set 'poretexists' to one to indicate we have seen this before.
#        for port in udpintelligence[source_ip]:
# 	        if udp_source_port == port:
#		    portexists = 1
#            for externalhost in externalhosts.keys():
#                if source_ip == externalhost:
#	            portexists = 1


	# If the port from the source host is a new port, notify the user about the connect, update the data dictionary and list all the ports we know are open for this host as well as the hosts permitted to connect to it
#	if portexists == 0:
#            print "\n-=-Host Recon Update-=-\nA new open UDP port was discovered for %s. This host has the following open UDP ports:" % (source_ip),
#    	    udpintelligence[source_ip].add(udp_source_port)
#	    trustedintelligence[source_ip].add(dest_ip)
#	    for port in sorted(udpintelligence[source_ip]):
#		print ("%s,") % ( port ),
#            print "\n\n-=-Trust Intelligence-=-\nThe following host(s) are permitted to talk to %s:" % (source_ip),  
#	    for trust in trustedintelligence[source_ip]:
#		print ("%s,") % ( trust ),
#            print("\n")



#        tempdata = udp_hdr.get_data_as_string()
        #print(dir(udp_hdr))
        #print tempdata
        #print("UDP packet header contents:\n%s") % ( udp_hdr)
        #print("\n\nudp_source_port = %s.") % ( udp_source_port)
        # If we have a response from a host on port 161, notify the user and extract the SNMP string - note this is buggy as there is not SNMP packet verification
#        if udp_source_port == 161:
#            snmppacketfilterregex = re.compile('[a-zA-Z0-9.*].*(?=:)')# Regex to yank data before colon within snmp string data
#            snmptempdata = snmppacketfilterregex.findall(tempdata)
#            printable = set(string.printable)
#            communitystring = filter(lambda x: x in printable, snmptempdata[0])
#            communitystring = communitystring[2:]
#            print("\n-=-SNMP Recon-=- We have a new SNMPv1 community string from %s: %s\n") % ( source_ip, communitystring ) 
#        return

# Function designed to sniff out intel tied to generic TCP intelligence such as predictable IPID numbers        
def tcpdiscovery(header,data):

        #print("\nStart of tcpdiscovery method.\n")
        #sniff.setfilter('tcp')
	# Start to decode the packet and determine the protocol number. If not TCP, return as it does not apply here.
	ethernet_packet = decoder.decode(data)
        protocolnumber = decoder.decode(data).child().child().protocol
        if protocolnumber != 6:
            return 
	# Extract relivant data from the ethernet packet
	mac_hdr = ethernet_packet
	ip_hdr = ethernet_packet.child()
	tcp_hdr = ip_hdr.child()
        source_ip_sequence_number = tcp_hdr.get_th_seq()
	source_ip = ip_hdr.get_ip_src()
        # Get a count of ipid sequence numbers
        ipidcount = len(tcpipidnumbers[source_ip])
        #if source_ip == '10.10.10.10':
            #print("We have %s ipid numbers for %s.") % (ipidcount,source_ip)
            #print tcpipidnumbers[source_ip]
        # Once we have three IPID sequence numbers, look for predictability and clean the list of ipid sequence numbers to preserve memory
        #print("Outside of ipid number count function.")
        if ipidcount == 12:
            #print("Inside ipid number count function.")
            oldzombiehost = 0
            ipiditem = 0
            olddiffipid = 0
            diffpidmatch = 0
            while ipiditem <= 10:
                newdiffipid = tcpipidnumbers[source_ip][ipiditem] - tcpipidnumbers[source_ip][ipiditem + 1]
                if olddiffipid == newdiffipid:
                    diffpidmatch += 1
                    for zombiehost in zombiehosts.keys():
                        if zombiehost == source_ip:
                            oldzombiehost = 1
                olddiffipid = newdiffipid
                ipiditem += 1
            if ( oldzombiehost == 0 and diffpidmatch >= 10 ):
                print("\n-=-Zombie Recon-=-\n%s uses predictible IPID sequence numbers! Last difference:%s. Captured IPID sequence numbers:\n%s\n") % ( source_ip,newdiffipid,tcpipidnumbers[source_ip] )
                for ipidnumber in tcpipidnumbers[source_ip]:
                    zombiehosts[source_ip].add(ipidnumber)
            # Clean the list of ipid sequence numbers to preserve memory
            ipidmaster = tcpipidnumbers[source_ip][11]
            del tcpipidnumbers[source_ip]
            tcpipidnumbers[source_ip].append(ipidmaster)
        if source_ip_sequence_number != 0:
            tcpipidnumbers[source_ip].append(source_ip_sequence_number)
        #print("\nEnd of tcpdiscovery method.\n")
        return

# Function designed to sniff out the TCP syn/ack portion of the three way handshake to enumerate listing services for a host
def synackdiscovery(header, data):

        # Collect keyboard events until released - disabling this now due to xorg issues
        #listen()
	#print("Top of synackdisccovery method.")
	# Filter only for TCP syn/ack packets
	#sniff.setfilter('tcp[tcpflags] & tcp[13] = 18')
	
	# Start to decode the packet and determine the protocol number. If not TCP, return as it does not apply here.
	ethernet_packet = decoder.decode(data)
        protocolnumber = decoder.decode(data).child().child().protocol
        if protocolnumber != 6:
            return 

	# Extract relivant data from the ethernet packet
	mac_hdr = ethernet_packet
	source_mac = mac_hdr.as_eth_addr(mac_hdr.get_ether_shost())
	dest_mac = mac_hdr.as_eth_addr(mac_hdr.get_ether_dhost())
	ip_hdr = ethernet_packet.child()
	tcp_hdr = ip_hdr.child()
        source_port = tcp_hdr.get_th_sport()
        dest_port = tcp_hdr.get_th_dport()
        source_ip_sequence_number = tcp_hdr.get_th_seq()
	source_ip = ip_hdr.get_ip_src()
	dest_ip = ip_hdr.get_ip_dst()

	# Define control variables to control message output of discovered hosts
	hostexists = 0
	portexists = 0
	srcarpexists = 0
	dstarpexists = 0
        unknownsourcenetwork = 0
        unknowndestnetwork = 0
        unknownexternalhost = 0

	#Check to see if a new host via arp has been discovered. If it is a new host store relivant arp intelligence via the arp data dictionary and update the tcpintelligence datadict
	#for src_host in arpintelligence.keys():
	#	if source_ip == src_host:
	#		srcarpexists = 1
	#for dst_host in arpintelligence.keys():
	#	if dest_ip == dst_host:
	#           	dstarpexists = 1

	#arpintelligence[source_ip].add(source_mac)
	#arpintelligence[dest_ip].add(dest_mac)

        # Look to see if the IP address appears to belong to a set of known nets. If not alert the user of the known net and update the knownnets datadictionary - there is a bug here - I don't manage IPv6 properly yet.
        rfc1918addressregex = re.compile('^(127\.)|(192\.168\.)|(10\.)|(172\.1[6-9]\.)|(172\.2[0-9]\.)|(172\.3[0-1]\.)')#  Add this when IPv6 is ready: |(::1$)|([fF][cCdD])')
        sourcematch = rfc1918addressregex.match(source_ip)
        destmatch = rfc1918addressregex.match(dest_ip)
        if sourcematch or destmatch:
            source_ip_octets = source_ip.split('.')
            source_network = source_ip_octets[0] + '.' + source_ip_octets[1] + '.' + source_ip_octets [2] + '.1/24'
            dest_ip_octets = dest_ip.split('.')
            dest_network = dest_ip_octets[0] + '.' + dest_ip_octets[1] + '.' + dest_ip_octets[2] + '.1/24'
            if sourcematch:
                for known_network in knownnets.keys():
                    if source_network == known_network:
                        unknownsourcenetwork = 1
            if destmatch:
                for known_network in knownnets.keys():
                    if dest_network == known_network:
                        unknowndestnetwork = 1
            if unknownsourcenetwork == 0 and sourcematch:
                print ("\n-=-Network Recon-=-\nA new network has been identified: %s") % (source_network)
                knownnets[source_network].add(source_ip)
            if unknowndestnetwork == 0 and destmatch:
                if source_network != dest_network:
                    print ("\n-=-Network Recon-=-\nA new network has been identified: %s") % (dest_network)
                    knownnets[dest_network].add(dest_ip)

        # If a host does not match an RFC1918 address that an RFC1918 address is talking to note the external host and the internal host permitted to talk to it and notify the user about the permitted connection
        if not sourcematch and destmatch:
            global tcpnetworkegresspermitted
            if tcpnetworkegresspermitted == 0:
                print ("\n-=-Egress Recon-=-\nNetwork egress detected! Internal hosts are permitted to connect to the internet via TCP.")
                tcpnetworkegresspermitted = 1
            for externalhost in externalhosts.keys():
                if source_ip == externalhost:
                        unknownexternalhost = 1
            if unknownexternalhost == 0 and tcpnetworkegresspermitted == 1:
                externalhosts[source_ip].add(dest_ip)
                print("\n-=-Egress Recon Update-=-\n%s is permitted to connect to %s on TCP port %s.") % (dest_ip, source_ip, source_port)

	# For each host listed as a key in our data dictionary, compare the actual host to the key. If it matches, make note of it by setting hostexists to '1'
        for host in tcpintelligence.keys():
            if source_ip == host:
                hostexists = 1
        for externalhost in externalhosts.keys():
            if source_ip == externalhost:
	        hostexists = 1
        for host in udpintelligence.keys():
            if source_ip == host:
                hostexists = 1


	# If hostexists 0, indicating a new host has been identified, notify the user and add the host and port to the data dictionary using the host as a key value
	if hostexists == 0:
            print "\n-=-Host Recon-=-\nA new host was identified with an open TCP port: %s:%s" % (source_ip, source_port)
    	    arpintelligence[source_ip].add(source_mac)
	    arpintelligence[dest_ip].add(dest_mac)
	    tcpintelligence[source_ip].add(source_port)
	    trustedintelligence[source_ip].add(dest_ip)
	    return

	# Using the source ip address as a key within the data dictionary, for each port listed see if it matches the source port captured witin the packet. If it is a match, set 'poretexists' to one to indicate we have seen this before.
	for port in tcpintelligence[source_ip]:
 	    if source_port == port:
		portexists = 1
        for externalhost in externalhosts.keys():
            if source_ip == externalhost:
	        portexists = 1

	# If the port from the source host is a new port, notify the user about the connect, update the data dictionary and list all the ports we know are open for this host as well as the hosts permitted to connect to it
	if portexists == 0:
            print "\n-=-Host Recon Update-=-\nA new open TCP port was discovered for %s. This host has the following open TCP ports:" % (source_ip),
    	    tcpintelligence[source_ip].add(source_port)
	    trustedintelligence[source_ip].add(dest_ip)
	    for port in sorted(tcpintelligence[source_ip]):
		print ("%s,") % ( port ),
            print "\n\n-=-Trust Intelligence-=-\nThe following host(s) are permitted to talk to %s:" % (source_ip),  
	    for trust in trustedintelligence[source_ip]:
		print ("%s,") % ( trust ),
            print("\n")
        #with open('prebellico_output.txt', 'w') as outfile:
            #json.dumps(tcpintelligence, outfile, sort_keys=True, indent=4)
            #json.dumps(arpintelligence, outfile, sort_keys=True, indent=4)
            #json.dumps(icmpintelligence, outfile, sort_keys=True, indent=4)
            #json.dumps(trustedintelligence, outfile, sort_keys=True, indent=4)
            #json.dumps(knownnets, outfile, sort_keys=True, indent=4)
            #json.dumps(externalnets, outfile, sort_keys=True, indent=4)
            #json.dumps(, outfile, sort_keys=True, indent=4)

        #with open('prebellico_output.txt', 'w') as outfile:
            #outfile.write(pickle.dumps(tcpintelligence))
            #outfile.write(pickle.dumps(arpintelligence))
            #outfile.write(pickle.dumps(icmpintelligence))
            #outfile.write(pickle.dumps(trustedintelligence))
            #outfile.write(pickle.dumps(knownnets))
            #outfile.write(pickle.dumps(externalnets))

        # The intent with the following line was to reset the filter to capture additional packets but this kind of appears to break prebellico for some reason. Need to look into this.    
        #sniff.setfilter('ip or ip6 or arp or aarp')
        #sniff.setfilter('tcp[tcpflags] & tcp[13] = 18')
        #print("\nEnd of synackdiscovery method.\n")
        return
        #pdb.set_trace()
        #sniff.next
        #return

# Place the ethernet interface in promiscuous mode, capturing one packet at a time with a snaplen of 1500
print("\nPlacing the interface in sniffing mode.")
sniff = pcapy.open_live("eth0", 1500, 1, 100)
time.sleep(1)

# Set a filter for data.
sniff.setfilter('ip or arp or aarp')

# Start the impact packet decoder
print("\nWatching for relivant intelligence.\n")
decoder = ImpactDecoder.EthDecoder()
time.sleep(1)

#print(dir(sniff.loop))
#print(dir(decoder))
#print(dir(decoder.decode))


#print(dir(sniff))
#time.sleep(1)

# Call the inspectproto function to determine protocol support
sniff.loop(0, inspectproto)

