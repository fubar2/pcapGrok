#!/usr/bin/python
# -*- coding: utf-8 -*-
from argparse import ArgumentParser

from core import GraphManager
from sources import ScapySource
from scapy.all import *
from scapy.layers.http import HTTP
import os.path
import csv
import copy
import logging
import pathlib

dnsCACHEfile = 'pcapgrok_dns_cache.xls'
logFileName = 'pcapgrok.log'
OUTHOSTFILE = 'pcapgrok_hostinfo.xls'
IPBROADCAST = '0.0.0.0'
MACBROADCAST = 'ff:ff:ff:ff:ff:ff'

logging.basicConfig(filename=logFileName,level=logging.INFO)

ip_macdict = {}

# put here so we can import it for tests

parser = ArgumentParser(description='Network packet capture (standard .pcap file) topology and message mapper. Optional protocol whitelist or blacklist and mac restriction to simplify graphs. Draws all 3 layers unless a single one is specified')
parser.add_argument('-a', '--append', action='store_true',default=False, help='Append multiple input files before processing as PcapVis previously did. New default is to batch process each input pcap file separately.')
parser.add_argument('-i', '--pcaps', nargs='*',help='Mandatory space delimited list of capture files to be analyzed - wildcards work too - e.g. -i Y*.pcap')
parser.add_argument('-p', '--pictures', help='Image filename stub for all images - layers and protocols are prepended to make file names. Use (e.g.) .pdf or .png extension to specify the image type. PDF is best for large graphs')
parser.add_argument('-o', '--outpath', required=False, default = None, help='All outputs will be written to the supplied path. Default (if none supplied) is current working directory')
parser.add_argument('-g', '--graphviz', help='Graph will be exported for downstream applications to the specified file (dot format)')
parser.add_argument('--layer2', action='store_true', help='Device (mac address) topology network graph')
parser.add_argument('--layer3', action='store_true', help='IP layer message graph. Default')
parser.add_argument('--layer4', action='store_true', help='TCP/UDP message graph')
parser.add_argument('-w', '--whitelist', nargs='*', help='Whitelist of protocols - only packets matching these layers shown - eg IP Raw HTTP')
parser.add_argument('-b', '--blacklist', nargs='*', help='Blacklist of protocols - NONE of the packets having these layers shown eg DNS NTP ARP RTP RIP')
parser.add_argument('-r', '--restrict', nargs='*', help='Whitelist of device mac addresses - restrict all graphs to traffic to or device(s). Specify mac address(es) as "xx:xx:xx:xx:xx:xx"')
parser.add_argument('-fi', '--frequent-in', action='store_true', help='Print frequently contacted nodes to stdout')
parser.add_argument('-fo', '--frequent-out', action='store_true', help='Print frequent source nodes to stdout')
parser.add_argument('-G', '--geopath', default='/usr/share/GeoIP/GeoLite2-City.mmdb', help='Path to maxmind geodb data')
parser.add_argument('-l', '--geolang', default='en', help='Language to use for geoIP names')
parser.add_argument('-E', '--layoutengine', default='sfdp', help='Graph layout method - dot, sfdp etc.')
parser.add_argument('-s', '--shape', default='diamond', help='Graphviz node shape - circle, diamond, box etc.')
parser.add_argument('-n', '--nmax', default=100, help='Automagically draw individual protocols if more than --nmax nodes. 100 seems too many for any one graph.')
parser.add_argument('-hf', '--hostsfile', required=False, help='Optional hosts file, following the same format as the dns cache file, which will have priority over existing entries in the cache')

args = parser.parse_args()

llook = {'DNS':DNS,'UDP':UDP,'ARP':ARP,'NTP':NTP,'IP':IP,'TCP':TCP,'Raw':Raw,'HTTP':HTTP,'RIP':RIP,'RTP':RTP}


		
def doLayer(layer, packets,fname,args,title,dnsCACHE,ip_macdict):
	"""
	run a single layer analysis
	"""
	args.nmax = int(args.nmax)
	g = GraphManager(packets, layer, args, dnsCACHE, ip_macdict)
	g.title = "Layer %d using packets from %s" % (layer,title)
	nn = len(g.graph.nodes())
	if args.pictures:
		if nn > args.nmax:
			logging.warning('Asked to draw %d nodes with --nmax set to %d. Will also do useful protocols separately' % (nn,args.nmax))
			for kind in llook.keys():
				subset = [x for x in packets if x != None and x.haslayer(kind)]  
				if len(subset) > 0:
					sg = GraphManager(subset,layer, args, dnsCACHE, ip_macdict)
					nn = len(sg.graph.nodes())
					if nn > 1:
						ofn = '%s_%d_layer%d_%s_%s' % (kind,nn,layer,title.replace('+','_'),args.pictures)
						if args.outpath:
							ofn = os.path.join(args.outpath,ofn)
						sg.title = 'Layer %d using packets from %s' % (layer,title)
						sg.draw(filename = ofn)
						logging.info('drew %s %d nodes' % (ofn,nn))
					else:
						logging.info('found %d nodes so not a very worthwhile graph' % nn)
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
	macs = {}
	fname = OUTHOSTFILE
	f = open(fname,'w')
	for packet in packets:
		macs.setdefault(packet[0].src,[0,'','',''])
		macs[packet[0].src][0] += 1
		macs.setdefault(packet[0].dst,[0,'','',''])
		macs[packet[0].dst][0] += 1
		if any(map(lambda p: packet.haslayer(p), [TCP, UDP])):
			ip = packet[1].src
			d = dnsCACHE.get(ip,None)
			if not d:
				d = dnsCACHE.get(ip.split(':')[0],None)
			if d:
				macs[packet[0].src][2] = d['whoname']
				macs[packet[0].src][3] = d['fqdname']
			macs[packet[0].src][1] = IPBROADCAST
	f.write('# mac\tip\tfqdn\thostinfo\tnpackets\n')
	f.write(''.join(['%s\t%s\t%s\t%s\t%d\n' % (x,macs[x][1],macs[x][3],macs[x][2],macs[x][0]) for x in macs.keys()]))
	f.write('\n')
	f.close()
	return(dnsCACHE)

def checkmacs(packets):
	"""best to determine mac/ip associations for local hosts before filtering on layer - layer4 changes the packet....
	"""
	for packet in packets:
		macs = packet[0].src.lower()
		if packet.haslayer(IP):
			ips = packet[1].src.lower()
			ip_macdict[ips] = macs
	return(ip_macdict)


def doPcap(pin,args,title,dnsCACHE):
	"""
	filtering and control for analysis - amalgamated input or not 
	runs all layers if no layer specified
	"""
	bl=[]
	wl=[]
	if args.whitelist != None and args.blacklist != None:
		print('### Parameter error: Specify --blacklist or specify --whitelist but not both together please.')
		sys.exit(1)
	packets = pin
	if args.whitelist: 
		wl = [llook[x] for x in args.whitelist]
		packets = [x for x in pin if sum([x.haslayer(y) for y in wl]) > 0 and x != None]  
	elif args.blacklist:
		bl = [llook[x] for x in args.blacklist]
		packets = [x for x in pin if sum([x.haslayer(y) for y in bl]) == 0 and x != None]  
	if (args.blacklist or args.whitelist):
		logging.info('### Read', len(pin), 'packets. After applying supplied filters,',len(packets),'are left. wl=',wl,'bl=',bl)
	ip_macdict = checkmacs(packets)		
	if not (args.layer2 or args.layer3 or args.layer4): # none requested - do all
		for layer in [2,3,4]:
			dnsCACHE = doLayer(layer, packets,args.pictures,args,title,dnsCACHE,ip_macdict)
	else:
		layer = 3
		if args.layer2:
			layer = 2
		elif args.layer4:
			layer = 4
		dnsCACHE = doLayer(layer,packets,args.outpath,args,title,dnsCACHE,ip_macdict)
	return(dnsCACHE)

def readHostsFile(hostfile,dnsCACHE):
	din = csv.reader(open(args.hostsfile,'r'),delimiter='\t')
	logging.info("reading hostsfile %s" % args.hostsfile)
	header = None
	for i,row in enumerate(din):
		if len(row) == 0:
			continue
		elif row[0].lstrip().startswith('#'):
			continue
		elif header == None:
			header = row
			s = '## hostsfile %s header = %s' % (args.hostsfile,header)
			logging.info(s)
		else:
			k = row[0].lower()
			rest = {}
			for i,tk in enumerate(header):
				if (len(row) > (i)):
					rest[tk] = row[i]
				else:
					rest[tk] = ''
					print('$$$ bad row %d in hostsfile = %s' % (i,row)) 
			if len(k.split(':')) == 6: # mac?
				if rest['mac'] == '':
					rest['mac'] = k
			dnsCACHE[k] = rest
			logging.info('### wrote new dnsCACHE entry k=%s contents=%s from supplied hostsfile %s' % (k,rest,hostfile))
	return(dnsCACHE)
	
def readDnsCache(dnsCACHEfile,dnsCACHE):
	din = csv.reader(open(dnsCACHEfile,'r'),delimiter='\t')
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
			logging.info(s)
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
			dnsCACHE[k] = rest
			logging.info('### wrote new dnsCACHE entry k=%s contents=%s from existing cache' % (k,rest))
	if dnsCACHE.get(MACBROADCAST,None) == None:
		for i,tk in header:
			mb[tk] = ''
		mb['ip'] = MACBROADCAST
		mb['fqdname'] = 'BROADCAST'
		mb['mac'] = MACBROADCAST
		dnsCACHE[MACBROADCAST] = mb
	if dnsCACHE.get(IPBROADCAST,None) == None:
		for i,tk in header:
			mb[tk] = ''
		mb['ip'] = IPBROADCAST
		mb['fqdname'] = 'BROADCAST'
		mb['mac'] = IPBROADCAST
		dnsCACHE[IPBROADCAST] = mb
	return dnsCACHE



if __name__ == '__main__':
	if args.pcaps:
		if args.outpath != None:
			if not (os.path.exists(args.outpath)):
				pathlib.Path(args.outpath).mkdir(parents=True, exist_ok=True)
				logging.info('Made %s for output' % args.outpath)

		dnsCACHE = {}
		# {'ip':'', 'fqdname':'','whoname':'','city':'','country':'','mac':''} 
		# read in optional hostsfile, which is formatted in same way as dnsCACHE file
		if args.hostsfile:
			if os.path.isfile(args.hostsfile):
				dnsCACHE = readHostsFile(args.hostsfile,dnsCACHE)
			else:
				logging.info("## Invalid hostsfile %s supplied, skipping" % args.hostsfile)
		else:
			logging.info("### hostsfile not supplied")
		if os.path.isfile(dnsCACHEfile):
			dnsCACHE = readDnsCache(dnsCACHEfile,dnsCACHE)
		else:
			print('### No dnsCACHE file',dnsCACHEfile,'found. Will create a new one')
		if args.append: # old style amalgamated input
			pin = ScapySource.load(args.pcaps)
			title = '+'.join([os.path.basename(x) for x in args.pcaps])
			if len(title) > 50:
				title = title[:50] + '_etc'
			dnsCACHE = doPcap(pin,args,title,dnsCACHE)
		else:
			for fname in args.pcaps:
				pin = rdpcap(fname)
				title = os.path.basename(fname)
				logging.info("Processing %s. Title is %s" % (fname,title))
				dnsCACHE = doPcap(pin,args,title,dnsCACHE)
		header = ['ip','fqdname','city','country','whoname','mac']	
		with open(dnsCACHEfile,'w') as cached:
			writer = csv.DictWriter(cached,delimiter='\t',fieldnames = header)
			writer.writeheader()
			for k in dnsCACHE.keys():
				row = dnsCACHE[k]
				if row['mac'] > '':
					if ip_macdict.get(k,None) != row['mac']:
						s = '## inconsistent supplied hostsfile %s says %s mac is %s but data has ip %s as mac %s' % (args.hostsfile,k,row['mac'],k,ip_macdict.get(k,''))
						print(s)
						logging.error(s)
				row['ip'] = k
				writer.writerow(row)
			cached.close()
		logging.info('wrote %d rows to %s' % (len(dnsCACHE),dnsCACHEfile))
	else:
		print('## input file parameter -i or --pcaps is mandatory - stopping')

