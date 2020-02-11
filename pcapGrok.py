#!/usr/bin/python
# -*- coding: utf-8 -*-
from argparse import ArgumentParser

from core import GraphManager
from sources import ScapySource
from scapy.all import *
from scapy.layers.http import HTTP
from scapy.layers.dhcp import DHCP
import os.path
import csv
import copy
import logging
import pathlib
from datetime import datetime
import json
import threading
from queue import Queue
import time
import socket
import subprocess
import sys


LASTPORT=65535
NTHREADS=250
print_lock = threading.Lock()
q = Queue()




DHCP_PORT = 67
BOOT_REQ = 1

DHCPDUMP_FILE = 'pcapgrok_dhcp.json'
dnsCACHEfile = 'pcapgrok_dns_cache.csv'
logFileName = 'pcapgrok.log'
IPBROADCAST = '0.0.0.0'
MACBROADCAST = 'ff:ff:ff:ff:ff:ff'
PRIVATE = 'Local'
SEPCHAR = ','

ip_macdict = {}
mac_ipdict = {}

# put here so we can import it for tests

parser = ArgumentParser(description='Network packet capture (standard .pcap file) topology and message mapper. Optional protocol whitelist or blacklist and mac restriction to simplify graphs. Draws all 3 layers unless a single one is specified')
parser.add_argument('-a', '--append', action='store_true',default=False, required=False, help='Append multiple input files before processing as PcapVis previously did. New default is to batch process each input pcap file separately.')
parser.add_argument('-b', '--blacklist', nargs='*', help='Blacklist of protocols - NONE of the packets having these layers shown eg DNS NTP ARP RTP RIP',required=False)
parser.add_argument('-E', '--layoutengine', default='sfdp', help='Graph layout method - dot, sfdp etc.',required=False)
parser.add_argument('-fi', '--frequent-in', action='store_true', help='Print frequently contacted nodes to stdout',required=False)
parser.add_argument('-fo', '--frequent-out', action='store_true', help='Print frequent source nodes to stdout',required=False)
parser.add_argument('-g', '--graphviz', help='Graph will be exported for downstream applications to the specified file (dot format)',required=False)
parser.add_argument('-G', '--geopath', default='/usr/share/GeoIP/GeoLite2-City.mmdb', help='Path to maxmind geodb data',required=False)
parser.add_argument('-hf', '--hostsfile', required=False, help='Optional hosts file, following the same format as the dns cache file, which will have priority over existing entries in the cache')
parser.add_argument('-i', '--pcaps', nargs='*',help='Mandatory space delimited list of capture files to be analyzed - wildcards work too - e.g. -i Y*.pcap')
parser.add_argument('-k', '--kyddbpath', required=False, default=None, help='Path to KYD database of known fingerbank IoT DHCP signatures to check against any DHCP requests in the packet capture files')
parser.add_argument('-l', '--geolang', default='en', help='Language to use for geoIP names')
parser.add_argument('--layer2', action='store_true', help='Device (mac address) topology network graph')
parser.add_argument('--layer3', action='store_true', help='IP layer message graph. Default')
parser.add_argument('--layer4', action='store_true', help='TCP/UDP message graph')
parser.add_argument('-n', '--nmax', default=100, help='Automagically draw individual protocols if more than --nmax nodes. 100 seems too many for any one graph.')
parser.add_argument('-o', '--outpath', required=False, default = None, help='All outputs will be written to the supplied path. Default (if none supplied) is current working directory')
parser.add_argument('-p', '--pictures', help='Image filename stub for all images - layers and protocols are prepended to make file names. Use (e.g.) .pdf or .png extension to specify the image type. PDF is best for large graphs')
parser.add_argument('-P', '--paralleldns', action='store_false',default=True, help='Turn OFF default to use threading for parallel dns/whois queries')
parser.add_argument('-S', '--squishports', action='store_false',default=True, help='Turn OFF default to simplify layer 4 network diagrams by ignoring ports - all ports for 1.2.3.4 will appear as one node')
parser.add_argument('-r', '--restrict', nargs='*', help='Whitelist of device mac addresses - restrict all graphs to traffic to or device(s). Specify mac address(es) as "xx:xx:xx:xx:xx:xx"')
parser.add_argument('-s', '--shape', default='diamond', help='Graphviz node shape - circle, diamond, box etc.')
parser.add_argument('-w', '--whitelist', nargs='*', help='Whitelist of protocols - only packets matching these layers shown - eg IP Raw HTTP')

args = parser.parse_args()

llook = {'BOOTP':BOOTP,'DNS':DNS,'UDP':UDP,'ARP':ARP,'NTP':NTP,'IP':IP,'TCP':TCP,'Raw':Raw,'HTTP':HTTP,'RIP':RIP,'RTP':RTP}




def doLayer(layer, packets,fname,args,title,dnsCACHE,ip_macdict,mac_ipdict):
	"""
	run a single layer analysis
	"""
	args.nmax = int(args.nmax)
	g = GraphManager(packets, layer, args, dnsCACHE, ip_macdict,mac_ipdict)
	g.title = "Layer %d using packets from %s" % (layer,title)
	nn = len(g.graph.nodes())
	if args.pictures:
		if nn > args.nmax:
			logging.debug('Asked to draw %d nodes with --nmax set to %d. Will also do useful protocols separately' % (nn,args.nmax))
			for kind in llook.keys():
				subset = [x for x in packets if x != None and x.haslayer(kind)]  
				if len(subset) > 0:
					sg = GraphManager(subset,layer, args, dnsCACHE, ip_macdict, mac_ipdict)
					nn = len(sg.graph.nodes())
					if nn > 1:
						ofn = '%s_%dnodes_layer%d_%s_%s' % (kind,nn,layer,title.replace('+','_'),args.pictures)
						if args.outpath:
							ofn = os.path.join(args.outpath,ofn)
						sg.title = '%s Only, Layer %d using packets from %s' % (kind,layer,title)
						sg.draw(filename = ofn)
						logging.debug('drew %s %d nodes' % (ofn,nn))
					else:
						logging.debug('found %d nodes so not a very worthwhile graph' % nn)
		ofn = '%s_layer%d_%s' % (title.replace('+','_'),layer,args.pictures)
		if args.outpath:
			ofn = os.path.join(args.outpath,ofn)
		g.draw(filename=ofn)
	if args.frequent_in:
		g.get_in_degree()

	if args.frequent_out:
		g.get_out_degree()

	if args.graphviz:
		g.get_graphviz_format(args.graphviz)
	dnsCACHE = copy.copy(g.dnsCACHE)
	return(dnsCACHE)

def checkmacs(packets):
	"""best to determine mac/ip associations for local hosts before filtering on layer - layer4 changes the packet....
	"""
	dhcpf = open(DHCPDUMP_FILE,'w')
	for packet in packets:
		macs = packet[0].src.lower()
		if any(map(lambda p: packet.haslayer(p), [TCP, UDP])):
			ips = packet[1].src.lower()
			ip_macdict[ips] = macs
			mac_ipdict[macs] = ips
			if packet.haslayer(DHCP) : # for kyd
				dhcpp = packet.getlayer(DHCP)
				dhcpo = dhcpp.options
				s = str(dhcpo)
				logging.debug('#### found dhcp info = %s' % s)
				dhcpf.write(s)
	dhcpf.close()
	return(ip_macdict,mac_ipdict)


def doPcap(pin,args,title,dnsCACHE):
	"""
	filtering and control for analysis - amalgamated input or not 
	runs all layers if no layer specified
	"""
	bl=[]
	wl=[]
	if args.whitelist != None and args.blacklist != None:
		s = '### Parameter error: Specify --blacklist or specify --whitelist but not both together please.'
		print(s)
		logging.debug(s)
		sys.exit(1)
	packets = pin
	if args.whitelist: 
		wl = [llook[x] for x in args.whitelist]
		packets = [x for x in pin if sum([x.haslayer(y) for y in wl]) > 0 and x != None]  
	elif args.blacklist:
		bl = [llook[x] for x in args.blacklist]
		packets = [x for x in pin if sum([x.haslayer(y) for y in bl]) == 0 and x != None]  
	if (args.blacklist or args.whitelist):
		logging.debug('### Read %d packets. After applying supplied filters %d packets are left. wl=%s bl= %s' % (len(pin),len(packets),wl,bl))
	ip_macdict,mac_ipdict = checkmacs(packets)
	logging.info('$$$$ mac_ipdict = %s' % mac_ipdict)
	if not (args.layer2 or args.layer3 or args.layer4): # none requested - do all
		for layer in [2,3,4]:
			dnsCACHE = doLayer(layer, packets,args.pictures,args,title,dnsCACHE,ip_macdict,mac_ipdict)
	else:
		layer = 3
		if args.layer2:
			layer = 2
		elif args.layer4:
			layer = 4
		dnsCACHE = doLayer(layer,packets,args.outpath,args,title,dnsCACHE,ip_macdict,mac_ipdict)
	return(dnsCACHE)

def readHostsFile(hostfile,dnsCACHE):
	din = csv.reader(open(args.hostsfile,'r'),delimiter=SEPCHAR)
	logging.debug("reading hostsfile %s" % args.hostsfile)
	header = None
	for i,row in enumerate(din):
		if len(row) == 0:
			continue
		elif row[0].lstrip().startswith('#'):
			continue
		elif header == None:
			header = row
			s = '## hostsfile %s header = %s' % (args.hostsfile,header)
			logging.debug(s)
		else:
			k = row[0].lower()
			rest = {}
			for i,tk in enumerate(header):
				if (len(row) > (i)):
					rest[tk] = row[i]
					if i == (len(row) - 1): # mac
						rest[tk] = rest[tk].lower()
				else:
					rest[tk] = ''
					s = '$$$ bad row %d in hostsfile = %s' % (i,row)
					print(s) 
					logging.debug(s)
			if rest['mac'] > '': # make sure there's a mac keyed entry
				mrest = copy.copy(rest)
				mrest['ip'] = rest['mac']
				# mrest['whoname'] = PRIVATE
				dnsCACHE[rest['mac']] = mrest
				logging.debug('### wrote new dnsCACHE mac entry k=%s contents=%s from supplied hostsfile %s' % (k,rest,hostfile))
			dnsCACHE[k] = rest
			logging.debug('### wrote new dnsCACHE entry k=%s contents=%s from supplied hostsfile %s' % (k,rest,hostfile))
	
	if dnsCACHE.get(MACBROADCAST,None) == None:
		mb = {}
		for tk in header:
			mb[tk] = ''
		mb['ip'] = MACBROADCAST
		mb['fqdname'] = 'BROADCAST'
		mb['whoname'] = PRIVATE
		mb['mac'] = MACBROADCAST
		dnsCACHE[MACBROADCAST] = mb
		
	if dnsCACHE.get(IPBROADCAST,None) == None:
		mb = {}
		for tk in header:
			mb[tk] = ''
		mb['ip'] = IPBROADCAST
		mb['fqdname'] = 'BROADCAST'
		mb['mac'] = IPBROADCAST
		mb['whoname'] = PRIVATE
		dnsCACHE[IPBROADCAST] = mb
	return dnsCACHE
	
def readDnsCache(dnsCACHEfile,dnsCACHE):
	din = csv.reader(open(dnsCACHEfile,'r'),delimiter=SEPCHAR)
	logging.info("reading dnsCACHEfile %s" % dnsCACHEfile)
	header = None
	for i,row in enumerate(din):
		if len(row) == 0:
			continue
		elif row[0].lstrip().startswith('#'):
			continue
		elif header == None:
			header = row
			s = '## dnscache %s header = %s' % (dnsCACHEfile,header)
			logging.debug(s)
		else:
			k = row[0].lower()
			# data loaded from hostsfile has priority over data from cachefile
			if dnsCACHE.get(k,None): 
				continue
			rest = {}
			for i,tk in enumerate(header):
				rest[tk] = row[i]
			if len(k.split(':')) == 6: # mac?
				if rest['mac'] == '':
					rest['mac'] = k
				else:
					rest['mac'] = rest['mac'].lower()
			if rest['whoname'] != PRIVATE and rest['whoname'] > '':
				omac = rest['mac']
				rest['mac'] = '' # must be a furriner
				logging.debug('Blew away mac %s since whoname is %s in readdnscache' % (omac,rest['whoname']))
			dnsCACHE[k] = rest
			logging.debug('### wrote new dnsCACHE entry k=%s contents=%s from existing cache' % (k,rest))
	return dnsCACHE



if __name__ == '__main__':
	kydknown = None
	# datetime object containing current date and time
	now = datetime.now()
	dt = now.strftime("%d/%m/%Y %H:%M:%S")
	if args.pcaps:
		if args.outpath:
			if not (os.path.exists(args.outpath)):
				pathlib.Path(args.outpath).mkdir(parents=True, exist_ok=True)
			logging.basicConfig(filename=os.path.join(args.outpath,logFileName),level=logging.DEBUG,filemode='w')
			logging.debug('pcapGrok starting at %s' % dt)
			logging.debug('Made %s for output' % args.outpath)
		else:
			logging.basicConfig(filename=logFileName,level=logging.DEBUG,filemode='w')
			logging.debug('pcapGrok starting at %s' % dt)
		if args.kyddbpath:
			kydknown = {}
			with open(kyddb,'r').readlines() as k:
				for row in k:
					if row.startswith('#'):
						continue
					rowl = row.rstrip().split('\t')
					#fields	DHCP_hash	DHCP_FP	FingerBank_Device_name	Score
					dhcphash,devname,score = rowl
					kydknown[dhcphash] = [devname,score]
		dnsCACHE = {}
		# {'ip':'', 'fqdname':'','whoname':'','city':'','country':'','mac':''} 
		# read in optional hostsfile, which is formatted in same way as dnsCACHE file
		if args.hostsfile:
			if os.path.isfile(args.hostsfile):
				dnsCACHE = readHostsFile(args.hostsfile,dnsCACHE)
			else:
				logging.debug("## Invalid hostsfile %s supplied, skipping" % args.hostsfile)
		else:
			logging.debug("### hostsfile not supplied")
		if os.path.isfile(dnsCACHEfile):
			dnsCACHE = readDnsCache(dnsCACHEfile,dnsCACHE)
		else:
			logging.debug('### No dnsCACHE file %s found. Will create a new one' % dnsCACHEfile)
		if args.restrict:
			r = args.restrict
			rl = [x.lower() for x in r]
			args.restrict = rl
		if args.append: # old style amalgamated input
			pin = ScapySource.load(args.pcaps)
			title = '+'.join([os.path.basename(x) for x in args.pcaps])
			if len(title) > 50:
				title = title[:50] + '_etc'
			if False and args.kyddbpath:
				kydres = kyd(fname)
				logging.debug('Got kyd results %s' % kydres)
			dnsCACHE = doPcap(pin,args,title,dnsCACHE)
		else:
			for fname in args.pcaps:
				if False and args.kyddbpath:
					kydres = kyd(fname)
					logging.info('Got kyd results %s' % kydres)
				pin = rdpcap(fname)
				title = os.path.basename(fname)
				logging.debug("Processing %s. Title is %s" % (fname,title))
				dnsCACHE = doPcap(pin,args,title,dnsCACHE)
		header = ['ip','fqdname','city','country','whoname','mac']	
		with open(dnsCACHEfile,'w') as cached:
			writer = csv.DictWriter(cached,delimiter=SEPCHAR,fieldnames = header)
			writer.writeheader()
			for k in dnsCACHE.keys():
				row = dnsCACHE[k]
				if len(k.split(':')) == 6:
					if row['ip'] == '':
						row['ip'] = ip_macdict.get(k)
						s = '## Added ip %s to mac entry for %s' % (args.row['ip'],k)
						print(s)
						logging.error(s)
				else:
					row['ip'] = k
				writer.writerow(row)
			cached.close()
		logging.debug('wrote %d rows to %s' % (len(dnsCACHE),dnsCACHEfile))
	else:
		print('## input file parameter -i or --pcaps is mandatory - stopping')
		logging.debug('## input file parameter -i or --pcaps is mandatory - stopping')

