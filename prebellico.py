#!/usr/bin/python

import pcapy
import socket
import netifaces
import sys
import re
import time
import json
import cPickle as pickle
import sqlite3
from impacket import ImpactDecoder
from pcapy import findalldevs, open_live, PcapError
from operator import itemgetter
from itertools import groupby
from collections import defaultdict
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

# Define a data dictionary for TCP ACK's designed to confirm server to client ACK's affiliated with SMB PSH/ACK requests using the host IP as the key
tcppshack = defaultdict(set)

# Function to detect the protcol used within the packet to steer accordingly.
def inspectproto(header, data):

	# Start to decode the packet, determine the protocol number and call the appropriate method.
	#print("\nTop of the inspectproto method.\n")
	ethernet_packet = decoder.decode(data)
	protocolnumber = decoder.decode(data).child().child().protocol
	if protocolnumber == 1:
		#print("\nThis is an ICMP packet.")
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
                if ( tcp_psh == 1 and tcp_ack == 1 or tcp_ack == 1):
                    tcppushdiscovery(header,data)
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
		if sourcematch:# or destmatch:
			source_ip_octets = source_ip.split('.')
			source_network = source_ip_octets[0] + '.' + source_ip_octets[1] + '.' + source_ip_octets [2] + '.1/24'
			for known_network in knownnets.keys():
				if source_network == known_network:
					unknownsourcenetwork = 1
			if unknownsourcenetwork == 0 and sourcematch:
				print ("\n-=-Network Recon-=-\nA new network has been identified: %s") % (source_network)
				knownnets[source_network].add(source_ip)

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

		# Look to see if the IP address appears to belong to a set of known nets. If not alert the user of the known net and update the knownnets datadictionary - there is a bug here - I don't manage IPv6 properly yet.
		rfc1918addressregex = re.compile('^(127\.)|(192\.168\.)|(10\.)|(172\.1[6-9]\.)|(172\.2[0-9]\.)|(172\.3[0-1]\.)')#  Add this when IPv6 is ready: |(::1$)|([fF][cCdD])')
		sourcematch = rfc1918addressregex.match(source_ip)
		destmatch = rfc1918addressregex.match(dest_ip)
		if sourcematch:#destmatch:
			source_ip_octets = source_ip.split('.')
			source_network = source_ip_octets[0] + '.' + source_ip_octets[1] + '.' + source_ip_octets [2] + '.1/24'
			for known_network in knownnets.keys():
				if source_network == known_network:
					unknownsourcenetwork = 1
			if unknownsourcenetwork == 0 and sourcematch:
				print ("\n-=-Network Recon-=-\nA new network has been identified: %s") % (source_network)
				knownnets[source_network].add(source_ip)

		# If a host does not match an RFC1918 address that an RFC1918 address is talking to note the external host and the internal host permitted to talk to it and notify the user about the permitted connection
		if not sourcematch and destmatch:
			global icmpnetworkegresspermitted
			if icmpnetworkegresspermitted == 0:
				print ("\n-=-Egress Recon-=-\nNetwork egress detected! Internal hosts are permitted to ping the internet.")
				icmpnetworkegresspermitted = 1
		#print("\nEnd of the icmpdiscovery method.\n")

# Function designed to sniff out intel tied to generic UDP intelligence such as SMB and SNMP traffic
def udpdiscovery(header,data):

	#print("\nStart of udpdiscovery method.\n")
	# Start to decode the packet and determine the protocol number. If not UDP, return as it does not apply here.
	ethernet_packet = decoder.decode(data)
	protocolnumber = decoder.decode(data).child().child().protocol
	if protocolnumber != 17:
		return 
	# Extract relevant data from the ethernet packet
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
		#print printable
		communitystring = filter(lambda x: x in printable, snmptempdata[0])
		#print communitystring
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

# Function designed to sniff out intel tied to captured TCP PSH requests 
def tcppushdiscovery(header,data):

	#print("\nStart of tcppushdiscovery method.\n")
	# Start to decode the packet and determine the protocol number. If not TCP, return as it does not apply here.
	ethernet_packet = decoder.decode(data)
	protocolnumber = decoder.decode(data).child().child().protocol
	if protocolnumber != 6:
		return 
	# Extract relevant data from the ethernet packet
	mac_hdr = ethernet_packet
	ip_hdr = ethernet_packet.child()
	tcp_hdr = ip_hdr.child()
	source_ip = ip_hdr.get_ip_src()
	source_port = tcp_hdr.get_th_sport()
        dest_ip = ip_hdr.get_ip_dst()
	dest_port = tcp_hdr.get_th_dport()

        # Pull TCP flags to determine tcp session state so that we can determine what TCP method to call for intel. 
	tcp_syn = ethernet_packet.child().child().get_SYN()
	tcp_ack = ethernet_packet.child().child().get_ACK()
	tcp_ece = ethernet_packet.child().child().get_ECE()
	tcp_cwr = ethernet_packet.child().child().get_CWR()
	tcp_fin = ethernet_packet.child().child().get_FIN()
	tcp_psh = ethernet_packet.child().child().get_PSH()
	tcp_rst = ethernet_packet.child().child().get_RST()
	tcp_urg = ethernet_packet.child().child().get_URG()

        if ( tcp_psh == 1 and tcp_ack == 1 ):
            portexists = 0
            #print("\n\nTCP PSH/ACK packet. Source port:%s Dest port:%s") % ( source_port, dest_port )
            if ( source_port <= 1024 and dest_port > 1024 ):
                # Using the source ip address as a key within the data dictionary, for each port listed see if it matches the source port captured witin the packet. If it is a match, set 'poretexists' to one to indicate we have seen this before.
	        for port in tcpintelligence[source_ip]:
		    if source_port == port:
		        portexists = 1
                if portexists == 0:
                    print("\n-=-TCP Push discovery-=-\nThere appears to be an open TCP port on %s:%s, which is talking to %s.") % ( source_ip, source_port, dest_ip )
		    tcpintelligence[source_ip].add(source_port)
		    trustedintelligence[source_ip].add(dest_ip)
                return
            if ( source_port > 1024 and dest_port <= 1024 ):
                # Using the source ip address as a key within the data dictionary, for each port listed see if it matches the source port captured witin the packet. If it is a match, set 'poretexists' to one to indicate we have seen this before.
	        for port in tcpintelligence[dest_ip]:
		    if dest_port == port:
		        portexists = 1
                if portexists == 0:
                    print("\n-=-TCP Push discovery-=-\n%s appears to be talking to an open TCP port - %s:%s.") % ( source_ip, dest_ip, dest_port )
		    tcpintelligence[source_ip].add(source_port)
		    trustedintelligence[source_ip].add(dest_ip)
		tcpintelligence[dest_ip].add(dest_port)
		trustedintelligence[dest_ip].add(source_ip)
                return
            if ( source_port > 1024 and dest_port > 1024 ):
                print("\n-=-TCP Push discovery-=-\nThere appears to be a TCP based conversation between %s:%s and %s:%s. Consulting intelligence to see if we can identify which host has a listening TCP service.") % ( source_ip, source_port, dest_ip, dest_port )
                #Need to work this algorithm a bit more but colon separated datadict values with a split comparison to the host might work. For now we just announce it and return
                #source_ip_and_dest_port = 'source_ip' + ':' + 'dest_port'
                #tcppshack[dest_ip].add(source_ip_adn_dest_port)
                #tcppshack = defaultdict(set)
                return
        #print("\nEnd of tcppushdiscovery method.\n")


# Function designed to sniff out intel tied to generic TCP intelligence such as predictable IPID numbers        
def tcpdiscovery(header,data):

	#print("\nStart of tcpdiscovery method.\n")
	# Start to decode the packet and determine the protocol number. If not TCP, return as it does not apply here.
	ethernet_packet = decoder.decode(data)
	protocolnumber = decoder.decode(data).child().child().protocol
	if protocolnumber != 6:
		return 
	# Extract relevant data from the ethernet packet
	mac_hdr = ethernet_packet
	ip_hdr = ethernet_packet.child()
	tcp_hdr = ip_hdr.child()
	source_ip_sequence_number = tcp_hdr.get_th_seq()
	source_ip = ip_hdr.get_ip_src()
	# Get a count of ipid sequence numbers
	ipidcount = len(tcpipidnumbers[source_ip])
	# Once we have three IPID sequence numbers, look for predictability and clean the list of ipid sequence numbers to preserve memory
	if ipidcount == 12:
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

	#print("Top of synackdisccovery method.")
	# Start to decode the packet and determine the protocol number. If not TCP, return as it does not apply here.
	ethernet_packet = decoder.decode(data)
	protocolnumber = decoder.decode(data).child().child().protocol
	if protocolnumber != 6:
		return 

	# Extract relevant data from the ethernet packet
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
	#with open('prebellico_output.csv', 'w') as outfile:
		#json.dumps(tcpintelligence, outfile, sort_keys=True, indent=4)
		#json.dumps(arpintelligence, outfile, sort_keys=True, indent=4)
		#json.dumps(icmpintelligence, outfile, sort_keys=True, indent=4)
		#json.dumps(trustedintelligence, outfile, sort_keys=True, indent=4)
		#json.dumps(knownnets, outfile, sort_keys=True, indent=4)
		#json.dumps(externalhosts, outfile, sort_keys=True, indent=4)
		#json.dumps(, outfile, sort_keys=True, indent=4)

	#with open('prebellico_output.txt', 'w') as outfile:
		#outfile.write(pickle.dumps(tcpintelligence))
		#outfile.write(pickle.dumps(arpintelligence))
		#outfile.write(pickle.dumps(icmpintelligence))
		#outfile.write(pickle.dumps(trustedintelligence))
		#outfile.write(pickle.dumps(knownnets))
		#outfile.write(pickle.dumps(externalhosts))

	#print("\nEnd of synackdiscovery method.\n")
	return
	#pdb.set_trace()

def getInterface():
    # Grab a list of interfaces that pcap is able to listen on.
    # The current user will be able to listen from all returned interfaces,
    # using open_live to open them.
    print '\nSearching the system for compatible devices.\n'
    ifs = findalldevs()

    # No interfaces available, abort.
    if 0 == len(ifs):
        print "You don't have enough permissions to open any interface on this system."
        sys.exit(1)

    # Only one interface available, use it.
    elif 1 == len(ifs):
        print 'Only one interface present, defaulting to it.'
        return ifs[0]

    # Ask the user to choose an interface from the list.
    else:
        print 'Numerous compatible interfaces identified:\n'
        count = 0
        for iface in ifs:
            try:
                t=open_live(iface, 1500, 0, 100)
                if( t.getnet() != '0.0.0.0' and t.datalink() ==  pcapy.DLT_EN10MB ):
                    print '%i - %s' % (count, iface)
                    count += 1
            except PcapError, e:
                break
    idx = int(raw_input('\nPlease select an interface you would like to use: '))

    return ifs[idx]

# Hunt for compatible devices and ask the user to select a compatible device - Note, this is a bit of a hack, but it works.
dev = getInterface()

# Obtain the selected interface IP to use as a filter, allowing us to pwn all the things without pissing in prebellico's data pool
devip = netifaces.ifaddresses(dev)[2][0]['addr']

# Place the ethernet interface in promiscuous mode, capturing one packet at a time with a snaplen of 1500
print("\nPlacing the interface in sniffing mode.")
sniff = pcapy.open_live(dev, 1500, 1, 100)
print "\nListening on %s: IP = %s, net=%s, mask=%s, linktype=%d" % (dev, devip, sniff.getnet(), sniff.getmask(), sniff.datalink())
time.sleep(1)

# Set a filter for data.
filter = ("ip or arp or aarp and not host %s") % ( devip )
sniff.setfilter(filter)

# Start the impact packet decoder
print("\nWatching for relevant intelligence.\n")
decoder = ImpactDecoder.EthDecoder()
time.sleep(1)

# Call the inspectproto function to determine protocol support
sniff.loop(0, inspectproto)

