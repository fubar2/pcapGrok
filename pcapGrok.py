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
logging.basicConfig(filename='pcapGrok.log',level=logging.DEBUG)

# put here so we can import it for tests

parser = ArgumentParser(description='Network packet capture (standard .pcap file) topology and message mapper. Optional protocol whitelist or blacklist and mac restriction to simplify graphs. Draws all 3 layers unless a single one is specified')
parser.add_argument('-a', '--append', action='store_true',default=False, help='Append multiple input files before processing as PcapVis previously did. New default is to batch process each input pcap file separately.')
parser.add_argument('-i', '--pcaps', nargs='*',help='Mandatory space delimited list of capture files to be analyzed - wildcards work too - e.g. -i Y*.pcap')
parser.add_argument('-p', '--pictures', help='Image filename stub for all images - layers and protocols are prepended to make file names. Use (e.g.) .pdf or .png extension to specify the image type. PDF is best for large graphs')
parser.add_argument('-o', '--outpath', required=False, help='All outputs will be written to the supplied path. Default (if none supplied) is current working directory')
parser.add_argument('-g', '--graphviz', help='Graph will be exported for downstream applications to the specified file (dot format)')
parser.add_argument('--layer2', action='store_true', help='Device (mac address) topology network graph')
parser.add_argument('--layer3', action='store_true', help='IP layer message graph. Default')
parser.add_argument('--layer4', action='store_true', help='TCP/UDP message graph')
parser.add_argument('-d','--DEBUG', action='store_true', help='Show debug messages and other (sometimes) very useful data')
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

args = parser.parse_args()

llook = {'DNS':DNS,'UDP':UDP,'ARP':ARP,'NTP':NTP,'IP':IP,'TCP':TCP,'Raw':Raw,'HTTP':HTTP,'RIP':RIP,'RTP':RTP}

def doLayer(layer, packets,fname,args,title,dnsCACHE):
	"""
	run a single layer analysis
	"""
	args.nmax = int(args.nmax)
	g = GraphManager(packets, layer, args, dnsCACHE)
	g.title = "Layer %d using packets from %s" % (layer,title)
	nn = len(g.graph.nodes())
	if args.pictures:
		if nn > args.nmax:
			logging.warning('Asked to draw %d nodes with --nmax set to %d. Will also do useful protocols separately' % (nn,args.nmax))
			for kind in llook.keys():
				subset = [x for x in packets if x != None and x.haslayer(kind)]  
				if len(subset) > 0:
					sg = GraphManager(subset,layer=layer, args=args, dnsCACHE=dnsCACHE)
					nn = len(sg.graph.nodes())
					if nn > 1:
						ofn = '%s_%d_%s_%s' % (kind,nn,title.replace('+','_'),args.pictures)
						if args.outpath:
							ofn = os.path.join(args.outpath,ofn)
						sg.title = 'Layer %d using packets from %s' % (layer,title)
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
	if args.DEBUG:
		macs = {}
		for packet in packets:
			macs.setdefault(packet[0].src,[0,'',''])
			macs[packet[0].src][0] += 1
			macs.setdefault(packet[0].dst,[0,'',''])
			macs[packet[0].dst][0] += 1
			if any(map(lambda p: packet.haslayer(p), [TCP, UDP])):
				ip = packet[1].src
				d = dnsCACHE.get(ip,None)
				if not d:
					d = dnsCACHE.get(ip.split(':')[0],None)
				if d:
					macs[packet[0].src][2] = d['whoname']
				macs[packet[0].src][1] = ip
		print('# mac\tip\thostinfo\tnpackets')
		print(''.join(['%s\t%s\t%s\t%d\n' % (x,macs[x][1],macs[x][2],macs[x][0]) for x in macs.keys()]))
	return(dnsCACHE)


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
	if args.whitelist: # packets are returned from ScapySource.load as a list so cannot use pcap.filter(lambda...)
		wl = [llook[x] for x in args.whitelist]
		packets = [x for x in pin if sum([x.haslayer(y) for y in wl]) > 0 and x != None]  
	elif args.blacklist:
		bl = [llook[x] for x in args.blacklist]
		packets = [x for x in pin if sum([x.haslayer(y) for y in bl]) == 0 and x != None]  
	if args.DEBUG and (args.blacklist or args.whitelist):
		print('### Read', len(pin), 'packets. After applying supplied filters,',len(packets),'are left. wl=',wl,'bl=',bl)			
	if not (args.layer2 or args.layer3 or args.layer4): # none requested - do all
		for layer in [2,3,4]:
			dnsCACHE = doLayer(layer, packets,args.pictures,args,title,dnsCACHE)
	else:
		layer = 3
		if args.layer2:
			layer = 2
		elif args.layer4:
			layer = 4
		dnsCACHE = doLayer(layer,packets,args.outpath,args,title,dnsCACHE)
	return(dnsCACHE)


if __name__ == '__main__':
	if args.pcaps:
		if args.outpath:
			if not (os.path.exists(args.outpath)):
				pathlib.Path(args.outpath).mkdir(parents=True, exist_ok=True)
				logging.info('Made %s for output' % args.outpath)
		dnsCACHE = {}
		# {'fqdname':'','whoname':'','city':'','country':'','mac':''}
		if os.path.isfile(dnsCACHEfile):
			din = csv.reader(open(dnsCACHEfile,'r'),delimiter='\t')
			for i,row in enumerate(din):
				if i == 0:
					header = row
				else:
					k = row[0]
					rest = {}
					for i,tk in enumerate(header[1:]):
						rest[tk] = row[i+1] 
					dnsCACHE[k] = rest
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
				if args.DEBUG: print("pcap title is " + title)
				dnsCACHE = doPcap(pin,args,title,dnsCACHE)
		header = ['ip','fqdname','city','country','whoname','mac']	
		with open(dnsCACHEfile,'w') as cached:
			writer = csv.DictWriter(cached,delimiter='\t',fieldnames = header)
			writer.writeheader()
			for k in dnsCACHE.keys():
				row = dnsCACHE[k]
				row['ip'] = k
				writer.writerow(row)
			cached.close()
		if args.DEBUG:
			print('wrote',len(dnsCACHE),'rows to',dnsCACHEfile)
	else:
		print('## input file parameter -i or --pcaps is mandatory - stopping')

