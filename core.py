
"""
ross lazarus december 2019 
forked from mateuszk87/PcapViz
changed geoIP lookup to use maxminddb
added reverse DNS lookup and cache with host names added to node labels
added CL parameters to adjust image layout and shapes
added broadcast/igmp annotation
added squishports to simplify layer4 networks so only 1 node per host for all ports

For private networks use:

	Range from 10.0.0.0 to 10.255.255.255 — a 10.0.0.0 network with a 255.0.0.0 or an /8 (8-bit) mask
	Range from 172.16.0.0 to 172.31.255.255 — a 172.16.0.0 network with a 255.240.0.0 (or a 12-bit) mask
	A 192.168.0.0 to 192.168.255.255 range, which is a 192.168.0.0 network masked by 255.255.0.0 or /16
	A special range 100.64.0.0 to 100.127.255.255 with a 255.192.0.0 or /10 network mask; this subnet is recommended according to rfc6598 for use as an address pool for CGN (Carrier-Grade NAT)
privateipstarts = ['10.',192.168.',]
more = ["172.%d" % i for i in range(16,32)]
privatestarts.append(more)
more =  ["100.%d" % i for i in range(64,128)]
privatestarts.append(more)	
if any [x.startswith[y] for y in privateipstarts]: # is private
"""


from collections import OrderedDict

import networkx
import itertools
from networkx import DiGraph

from scapy.layers.inet import TCP, IP, UDP
from scapy.all import *
from scapy.layers.http import *
import logging

import os
import socket
import maxminddb
from ipwhois import IPWhois
from ipwhois import IPDefinedError

from datetime import datetime
import json
import threading
from queue import Queue
import time
import socket
import subprocess
import sys
# wordclouds
from wordcloud import WordCloud
from collections import Counter
from random import randint
import matplotlib
from matplotlib import cm
from matplotlib.colors import ListedColormap, LinearSegmentedColormap

matplotlib.use('Agg')
import matplotlib.pyplot as plt
import ipaddress



protos = {'BOOTP':BOOTP,'DNS':DNS,'UDP':UDP,'ARP':ARP,'NTP':NTP,'IP':IP,'TCP':TCP,'Raw':Raw,'HTTP':HTTP,'RIP':RIP,'RTP':RTP}


MULTIMAC = "01:00:5e"
UNIMAC = "00:00:5e"
BROADCASTMAC = "ff:ff:ff:ff:ff:ff"
ROUTINGDISCOVERY = "224.0.0."
ALLBC = ['multicast','igmp','unicast','broadcast','broadcasthost',"routingdiscovery"]

PRIVATE = 'Local'

NTHREADS=250

class parDNS():
	""" dns/whois lookups parallel for speed
	filter with ipaddress module
	"""

	def __init__(self,lookmeup,privates,ip_macdict,geo_ip,geo_lang):
		self.lookmeup = lookmeup
		self.drec =  {'ip':'','fqdname':'','whoname':'','city':'','country':'','mac':''}
		self.drecs = {}
		self.dnsq_lock = threading.Lock()
		self.dnsq = Queue()
		self.privates = privates
		self.ip_macdict = ip_macdict
		self.geo_ip = geo_ip
		self.geo_lang = geo_lang
		self.logger = logging.getLogger('pardns')
		self.logger.setLevel(logging.DEBUG)


		
	def lookup(self,ip):
			ddict = copy.copy(self.drec)
			ddict['ip'] = ip
			whoname = ''
			mymac = self.ip_macdict.get(ip,None)
			fqdname = ''
			city = ''
			country = ''	
			ns = ip.split(':')
			iptrim = ip
			if len(ns) <= 2:
				iptrim = ns[0]
			elif len(ns) == 6: # mac
				iptrim = None
				whoname = PRIVATE		
			if iptrim:
				try:
					ipa = ipaddress.ip_address(iptrim)
				except:
					ipa == None
				if ipa:
					if ipa.is_local:
						whoname = PRIVATE
						fqdname = 'LocalNetwork'
					if ipa.is_multicast:
						whoname = PRIVATE
						fqdname = 'Multicast'
					if ipa.is_link_local or ipa.is_private:
						whoname = PRIVATE
						fqdname = 'LinkLocal'
					if ipa.is_loopback:
						whoname = PRIVATE
						fqdname = 'Loopback'
					if ipa.is_global:
						whoname = PRIVATE
						fqdname = 'Global'
					if ipa.is_reserved:
						whoname = PRIVATE
						fqdname = 'Reserved'
					if ipa.is_unspecified:
						whoname = PRIVATE
						fqdname = 'Unspecified'
			if whoname == '': # not yet found so try lookup		
				if ip > '' and not (':' in ip):
					fqdname = socket.getfqdn(ip)
					try:
						who = IPWhois(ip)
						qry = who.lookup_rdap(depth=1)
						whoname = qry['asn_description']
					except Exception as e:
						whoname = PRIVATE
						with self.dnsq_lock: # make sure no race
							self.logger.debug('#### IPwhois failed ?timeout? for ip = %s = %s' % (ip,e))
					fullname = '%s\n%s' % (fqdname,whoname)
					if ip > '' and self.geo_ip and ddict['whoname'] != PRIVATE and (':' not in ip):			
						mmdbrec = self.geo_ip.get(ip)
						if mmdbrec != None:
							countryrec = mmdbrec.get('country',None)
							cityrec = mmdbrec.get('city',None)
							if countryrec: # some records have one but not the other....
								country = countryrec['names'].get(self.geo_lang,None)
							if cityrec:
								city =  cityrec['names'].get(self.geo_lang,None)
						else:
							self.logger.error("could not load GeoIP data for ip %s" % ip)
			ddict['city'] = city
			ddict['country'] = country
			ddict['whoname'] = whoname
			ddict['fqdname'] = fqdname
			ddict['mac'] = mymac
			with self.dnsq_lock: # make sure no race
				self.drecs[ip] = ddict
				self.logger.debug('fast got city country %s,%s fqdname %s for ip %s' % (city,country,ddict['fqdname'],ip))
		
	def threader(self):
		while True:
			ip = self.dnsq.get()
			self.lookup(ip)
			self.dnsq.task_done()
		

	def doRun(self):
		self.started = time.time()
		for x in range(NTHREADS):
			 t = threading.Thread(target=self.threader)
			 # classify as a daemon, so they will die when the main dies
			 t.daemon = True
			 # begins, must come after daemon definition
			 t.start()
		for ip in self.lookmeup:
			self.dnsq.put(ip)
		# wait until the q terminates.
		self.dnsq.join()
		dur = time.time() - self.started
		self.logger.info('IP lookup n= %d for cache took %.2f seconds' % (len(self.lookmeup),dur))
		return self.drecs



class GraphManager(object):
	""" Generates and processes the graph based on packets
	reusable version
	"""

	def __init__(self,args, dnsCACHE,ip_macdict,mac_ipdict,glabel,filesused):
		""" reset as needed once created
		"""
		self.logger = logging.getLogger("graphmanager")
		self.logger.setLevel(logging.DEBUG)
		self.args = args
		try:
			self.geo_ip = maxminddb.open_database(self.args.geopath) # command line -G
		except:
			self.logger.warning("### non fatal but annoying error: could not load GeoIP data from supplied parameter geopath %s so no geographic data can be shown in labels" % self.args.geopath)
		self.graph = DiGraph()
		self.agraph = None
		self.geo_ip = None
		self.geo_lang = args.geolang
		self.args = args
		self.filesused = filesused
		self.glabel = glabel
		self.data = {}
		self.ip_macdict = ip_macdict
		self.mac_ipdict = mac_ipdict
		self.dnsCACHE = dnsCACHE
		self.squishPorts = args.squishportsON == True
		self.parallelDNS = args.paralleldnsOFF == False

		
	
	def reset(self, packets, layer, gtitle):
		""" get rid of large structures and reuse between layers and separate protocol runs
		"""
		del self.graph
		del self.data
		del self.agraph
		self.agraph=None
		self.gtitle = gtitle
		self.data = {}
		self.graph = DiGraph() # make a new one
		assert layer in [2,3,4],'###GraphManager __init__ got layer = %s. Must be 2,3 or 4' % str(layer)
		assert len(packets) > 0, '###GraphManager __init__ got empty packets list - nothing useful can be done'
		self.layer = layer		
		if self.args.restrict:
			packetsr = [x for x in packets if ((x[0].src in self.args.restrict) or (x[0].dst in self.args.restrict))]
			if len(packetsr) == 0:
				self.logger.critical('### warning - no packets left after filtering on %s - nothing to plot' % self.args.restrict)
				return
			else:
				self.logger.info('%d packets filtered leaving %d with restrict = %s' % (len(packets) - len(packetsr),len(packetsr),self.args.restrict))
				packets = packetsr
		#self.checkmacs(packets)
		if self.layer == 2:
			edges = map(self._layer_2_edge, packets)
		elif self.layer == 3:
			edges = map(self._layer_3_edge, packets)
		elif self.layer == 4:
			edges = map(self._layer_4_edge, packets)
		else:
			raise ValueError("Other layers than 2,3 and 4 are not supported yet!")

		for src, dst, packet in filter(lambda x: not (x is None), edges):
			if self.layer == 4 and self.squishPorts: # squish networks by ignoring port
				if len(src.split(':')) == 2:
					src = src.split(':')[0]
				if len(dst.split(':')) == 2:
					dst = dst.split(':')[0]

			if src in self.graph and dst in self.graph[src]:
				self.graph[src][dst]['packets'].append(packet)
			else:
				self.graph.add_edge(src, dst)
				self.graph[src][dst]['packets'] = [packet]

		if self.parallelDNS:
			self._fast_retrieve_node_info()
		else:
			for node in self.graph:
				self._retrieve_node_info(node)

		for src, dst in self.graph.edges():
			self._retrieve_edge_info(src, dst)



	def get_in_degree(self, print_stdout=True):
		unsorted_degrees = self.graph.in_degree()
		return self._sorted_results(unsorted_degrees, print_stdout)

	def get_out_degree(self, print_stdout=True):
		unsorted_degrees = self.graph.out_degree()
		return self._sorted_results(unsorted_degrees, print_stdout)

	def _sorted_results(self,unsorted_degrees, print_stdout):
		sorted_degrees = OrderedDict(sorted(list(unsorted_degrees), key=lambda t: int(t[1]), reverse=True))
		for i in sorted_degrees:
			isplit = i.split(':')
			if len(isplit) == 2:
				useip = isplit[0] # port
			else:
				useip = i
			if print_stdout and i != None:
				nn = self.dnsCACHE.get(useip,{'ip':'unknown'})['ip']
				if nn:
					f = self.dnsCACHE[useip]['fqdname']
					w = self.dnsCACHE[useip]['whoname']
				else:
					f = '%s not in dnscache' % i
					w = '%s whoname - not in dnscache' % i
				if (nn == i):
					print('\t'.join([str(sorted_degrees[i]), str(i), f, w]))
				else:
					print('\t'.join([str(sorted_degrees[i]),str(i), nn, f, w]))
		return sorted_degrees

	def isLocal(self,ip):
		res = any ([ip.startswith(y) for y in self.privates]) # is private
		return res

	def _fast_retrieve_node_info(self):				
		"""parallel all (slow!) fqdn reverse dns lookups from ip"""
		lookmeup = [] # parallel for ip not in cache yet
		for node in self.graph.nodes:
			ns = node.split(':')
			if len(ns) <= 2: # has a port - not a mac or ipv6 address
				ip = ns[0]
				ddict = self.dnsCACHE.get(ip,None) # index is unadorned ip or mac
				if ddict == None:
					lookmeup.append(ip)
			else:
				ip = node # might be ipv6 or mac - use as key
		if len(lookmeup) > 0:
			fastdns = parDNS(lookmeup,self.privates,self.ip_macdict,self.geo_ip,self.geo_lang)
			drecs = fastdns.doRun()
			kees = drecs.keys()
			for k in kees:
				if self.dnsCACHE.get(k,None):
					self.logger.warning('Odd - key %s was already in self.dnsCACHE after fast lookup = %s - fast = %s - not replaced' % (k,self.dnsCACHE[k],drecs[k]))
				else:
					self.dnsCACHE[k] = drecs[k]
					self.logger.debug('## fast looked up %s and added %s' % (k,drecs[k]))
		else:
			self.logger.debug('_fast_retrieve_node found no ip addresses missing from dnsCACHE')
		

		
	def _retrieve_node_info(self, node):				
		"""cache all (slow!) fqdn reverse dns lookups from ip"""
		drec = {'ip':'','fqdname':'','whoname':'','city':'','country':'','mac':''}
		ns = node.split(':')
		if len(ns) <= 2: # has a port - not a mac or ipv6 address
			ip = ns[0]
		else:
			ip = node # might be ipv6 or mac - use as key
		ddict = self.dnsCACHE.get(ip,None) # index is unadorned ip or mac
		if ddict == None: # never seen - ignore ports because annotation is always the same
			ddict = copy.copy(drec)
			ddict['ip'] = ip	
			city = ''
			country = ''
			localip = self.isLocal(ip)
			mymac = self.ip_macdict.get(ip,None)
			if mymac and localip:
				ddict['mac'] = mymac
			if ip.startswith('240.0'): # is igmp
				ddict['fqdname'] = 'Multicast'
				ddict['whoname'] = 'IGMP'
			if ip.startswith(MULTIMAC):
				ddict['fqdname'] = 'Multicast'
				ddict['whoname'] = 'IGMP'
			elif ip.startswith(UNIMAC):
				ddict['fqdname'] = 'Unicast'
				ddict['whoname'] = 'IGMP'
			elif ip == BROADCASTMAC:
				ddict['fqdname'] = 'Broadcast'
				ddict['whoname'] = 'Local'
			elif ip.startswith(ROUTINGDISCOVERY):
				ddict['fqdname'] = 'Routingdiscovery'
				ddict['whoname'] = 'Local'
			elif ip == '0.0.0.0':
				ddict['whoname'] = 'Local'
			elif localip:
				ddict['whoname'] = 'Local'
			else:
				if ip > '' and not (':' in ip) and not localip:
					fqdname = socket.getfqdn(ip)
					ddict['fqdname'] = fqdname
					try:
						who = IPWhois(ip)
						qry = who.lookup_rdap(depth=1)
						whoname = qry['asn_description']
					except Exception as e:
						whoname = PRIVATE
						self.logger.warning('#### IPwhois failed ?timeout? for ip = %s = %s' % (ip,e))
					ddict['whoname'] = whoname
					fullname = '%s\n%s' % (fqdname,whoname)
				else:
					ddict['fqdname'] = ''
					if len(ns) == 6 and ddict['mac'] == '':
						ddict['mac'] = ip
				city = ''
				country = ''
				if ip > '' and self.geo_ip and ddict['whoname'] != PRIVATE and (':' not in ip):			
					mmdbrec = self.geo_ip.get(ip)
					if mmdbrec != None:
						countryrec = mmdbrec.get('country',None)
						cityrec = mmdbrec.get('city',None)
						if countryrec: # some records have one but not the other....
							country = countryrec['names'].get(self.args.geolang,None)
						if cityrec:
							city =  cityrec['names'].get(self.args.geolang,None)
					else:
						self.logger.error("could not load GeoIP data for ip %s" % ip)
			ddict['city'] = city
			ddict['country'] = country
			self.dnsCACHE[node] = ddict
			self.logger.info('## looked up %s and added %s' % (node,ddict))
		


	def _retrieve_edge_info(self, src, dst):
		edge = self.graph[src][dst]
		if edge:
			packets = edge['packets']
			edge['layers'] = set(list(itertools.chain(*[set(GraphManager.get_layers(p)) for p in packets])))
			edge['transmitted'] = sum(len(p) for p in packets)
			edge['connections'] = len(packets)

	@staticmethod
	def get_layers(packet):
		return list(GraphManager.expand(packet))

	@staticmethod
	def expand(x):
		yield x.name
		while x.payload:
			x = x.payload
			yield x.name

	@staticmethod
	def _layer_2_edge(packet):
		return packet[0].src, packet[0].dst, packet

	@staticmethod
	def _layer_3_edge(packet):
		if packet.haslayer(IP):
			return packet[1].src, packet[1].dst, packet

	@staticmethod
	def _layer_4_edge(packet):
		if any(map(lambda p: packet.haslayer(p), [TCP, UDP])):
			src = packet[1].src
			dst = packet[1].dst
			try: # fails with mirai sample 
				sp = str(packet[2].sport)
			except:
				sp = 'malformed'
			try: # fails with mirai sample 
				dp = str(packet[2].dport)
			except:
				dp = 'malformed'
			return "%s:%s" % (src, sp), "%s:%s" % (dst, dp), packet

	def draw(self, filename):
		emptyrec = {'ip':'','fqdname':'','whoname':'','city':'','country':'','mac':''}
		graph = self.get_graphviz_format()
		graph.graph_attr['label'] = self.glabel
		graph.graph_attr['labelloc'] = 't'
		graph.graph_attr['fontsize'] = 35
		graph.graph_attr['fontcolor'] = 'indigo'
		graph.graph_attr['size'] = "1000,1000"
		graph.graph_attr['resolution'] = 72
		graph.graph_attr['bgcolor'] = "#FFFFFFFF"
		graph.graph_attr['font.family'] = ['DejaVu Sans'] #['Tahoma', 'DejaVu Sans', 'Lucida Grande', 'Verdana']
		graph.graph_attr['font.font'] = ['DejaVu Sans']
		for node in graph.nodes():
			snode = str(node)
			ssnode = snode.split(':') # look for mac or a port on the ip
			if len(ssnode) <= 2:
				ip = ssnode[0]
				ddict = self.dnsCACHE.get(ip,emptyrec)
				if ddict['fqdname'] == '':
					ddict['fqdname'] = ip
					self.logger.debug('Odd. No dnsCACHE entry for snode %s, node %s in draw' % (snode,node))
			else:
				ip = snode
				ddict = self.dnsCACHE.get(snode,emptyrec)
				if ddict['fqdname'] == '':
					ddict['fqdname'] = ip
					self.logger.debug('Odd. No dnsCACHE entry for snode %s, node %s in draw' % (snode,node))
			node.attr['shape'] = self.args.shape
			node.attr['font.family'] = 'sans-serif'
			node.attr['font.sans-serif'] = ['Verdana']
			node.attr['fontsize'] = '11'
			node.attr['width'] = '0.5'
			node.attr['color'] = 'yellowgreen' # assume all are local hosts
			node.attr['fontcolor'] = 'darkgreen'
			node.attr['style'] = 'rounded' ## filled,
			country = ddict['country']
			city = ddict['city']
			fqdname = ddict['fqdname']
			mac = ddict['mac']
			whoname = ddict['whoname']
			if whoname != '' and whoname != PRIVATE:
				node.attr['color'] = 'violet' # remote hosts
				node.attr['fontcolor'] = 'darkviolet'
			if ddict['fqdname'].lower() in ALLBC or whoname == PRIVATE:
				node.attr['color'] = 'yellowgreen' # broad/multicast/igmp
				node.attr['fontcolor'] = 'darkgreen' # broad/multicast/igmp
			nodelabel = [node,]
			if fqdname > '' and fqdname != ip:
				nodelabel.append('\n')
				nodelabel.append(fqdname)
			if city > '' or country > '':
				nodelabel.append('\n')
				nodelabel.append('%s %s' % (city,country))
			if whoname and whoname > '':
				nodelabel.append('\n')
				if len(whoname) > 30:
					l = len(whoname)
					pos = l // 2
					whoname = whoname[:pos] + '\n' + whoname[pos:]
				nodelabel.append(whoname)
			ns = ''.join(nodelabel)
			node.attr['label'] = ns
			
			
		for edge in graph.edges():
			connection = self.graph[edge[0]][edge[1]]
			edge.attr['label'] = 'transmitted: %i bytes\n%s ' % (connection['transmitted'], ' | '.join(connection['layers']))
			edge.attr['fontsize'] = '8'
			edge.attr['minlen'] = '2'
			edge.attr['penwidth'] = min(max(0.05,connection['connections'] * 1.0 / len(self.graph.nodes())), 2.0)
		graph.layout(prog=self.args.layoutengine)
		#graph.draw(filename)
		dotfilename = '%s.dot' % filename
		graph.write(dotfilename)
		os.system('sfdp -x -Goverlap=scale -Tpdf %s > %s' % (dotfilename,filename))
		os.system('rm %s' % dotfilename)
		self.agraph = graph

	def get_graphviz_format(self, filename=None):
		agraph = networkx.drawing.nx_agraph.to_agraph(self.graph)
		# remove packet information (blows up file size)
		for edge in agraph.edges():
			del edge.attr['packets']
		if filename:
			agraph.write(filename)
		return agraph


	def random_color_func(self, word=None, font_size=None, position=None,  orientation=None, font_path=None, random_state=None):
		"""https://stackoverflow.com/questions/43043263/word-cloud-in-python-with-customised-colour"""
		h = int(360.0 * 21.0 / 255.0) # orange base
		s = int(100.0 * 255.0 / 255.0)
		l = int(100.0 * float(randint(60, 120)) / 255.0)

		return "hsl({}, {}%, {}%)".format(h, s, l)		
			
	def wordClouds(self,outfname,protoc):
		graph = self.agraph # assume already drawn
		totalbytes = 0
		weights = {}
		for edge in graph.edges():
			src = edge[0]
			weights[src] = {}
			for dest in self.graph[edge[0]].keys():
				cnx = self.graph[src][dest]
				tb = cnx['transmitted']
				totalbytes += tb
				if weights[src].get(dest,None):
					weights[src][dest] += tb
				else:
					weights[src][dest] = tb
		for node in graph.nodes():
			snode = str(node)
			dnrec = self.dnsCACHE.get(snode,None)
			if dnrec:
				fqname = dnrec['fqdname']
				whoname = dnrec['whoname']
				city = dnrec['city']
				country = dnrec['country']
			else:
				self.logger.warning('Odd: no dnsCACHE record for node %s found in wordcloud generation' % (snode))
				fqname = node
				whoname = ''
				city = ''
				country = ''
			wts = weights.get(snode,None)
			if wts:
				annowts = {}
				for dest in wts.keys():
					byts = wts[dest]
					dnrec = self.dnsCACHE.get(snode,None)
					if dnrec:
						fqname = dnrec['fqdname']
						whoname = dnrec['whoname']
						city = dnrec['city']
						country = dnrec['country']
					else:
						fqname = node
						whoname = ''
						city = ''
						country = ''

					fullname = ' \n'.join([x for x in (node,fqname,whoname,city,country) if x > ''])
					annowts[fullname] = byts
				nn = len(annowts.keys())
				if nn > 2:
					destfqlist = annowts.keys()
					longname = ' '.join([x for x in (node,fqname,whoname,city,country) if x > ''])
					wc = WordCloud(background_color="black",width=1200, height=1000,max_words=200,
					 min_font_size=20, color_func = self.random_color_func).generate_from_frequencies(annowts)
					f = plt.figure(figsize=(10, 10))
					plt.imshow(wc, interpolation='bilinear')
					plt.axis('off')
					plt.title('%s %s traffic destinations' % (longname,protoc), color="indigo")
					ofss = outfname.split('destwordcloud') # better be there
					ofn = '%s%ddest_wordcloud_%s%s' % (ofss[0],nn,fqname,ofss[1])
					f.savefig(ofn, bbox_inches='tight')
					self.logger.info('Wrote wordcloud with %d entries for %s' % (nn,longname))
					plt.close(f) 
				
				
	def oldwordClouds(self,outfname,protoc):
		ipfq = {}
		graph = self.agraph # assume already drawn
		for node in self.graph.nodes():
			dnrec = self.dnsCACHE.get(node,None)
			if dnrec:
				fq = dnrec['fqdname']
				if len(fq) > 0:
					ipfq[node] = fq
				else:
					ipfq[node] = node
			else:
				ipfq[node] = node
		totalbytes = 0
		weights = {}
		for edge in graph.edges():
			src = edge[0]
			weights[src] = {}
			for dest in self.graph[edge[0]].keys():
				destk = ipfq.get(dest,dest)
				cnx = self.graph[edge[0]][destk]
				tb = cnx['transmitted']
				totalbytes += tb
				if weights[srck].get(destk,None):
					weights[srck][destk] += tb
				else:
					weights[srck][destk] = tb
		for node in graph.nodes():
			snode = str(node)
			dnrec = self.dnsCACHE.get(snode,None)
			if dnrec:
				fqname = dnrec['fqdname']
				whoname = dnrec['whoname']
				city = dnrec['city']
				country = dnrec['country']
			else:
				fqname = node
				whoname = ''
				city = ''
				country = ''
			wts = weights.get(fqname,None)
			if wts and len(wts.keys()) >= 1:
				nn = len(wts.keys())
				destfqlist = wts.keys()
				longname = ' '.join([x for x in (node,fqname,whoname,city,country) if x > ''])
				wc = WordCloud(background_color="black",width=1200, height=1000,max_words=200,
				 min_font_size=20, color_func = self.random_color_func).generate_from_frequencies(wts)
				f = plt.figure(figsize=(10, 10))
				plt.imshow(wc, interpolation='bilinear')
				plt.axis('off')
				plt.title('%s %s traffic destinations' % (longname,protoc), color="indigo")
				ofss = outfname.split('destwordcloud') # better be there
				ofn = '%s%ddest_wordcloud_%s%s' % (ofss[0],nn,fqname,ofss[1])
				f.savefig(ofn, bbox_inches='tight')
				plt.close(f) 




