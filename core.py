
"""
ross lazarus december 2019 
forked from mateuszk87/PcapViz
changed geoIP lookup to use maxminddb
added reverse DNS lookup and cache with host names added to node labels
added CL parameters to adjust image layout and shapes
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

class GraphManager(object):
	""" Generates and processes the graph based on packets
	"""

	def __init__(self, packets, layer, args, dnsCACHE):
		assert layer in [2,3,4],'###GraphManager __init__ got layer = %s. Must be 2,3 or 4' % str(layer)
		assert len(packets) > 0, '###GraphManager __init__ got empty packets list - nothing useful can be done'
		self.graph = DiGraph()
		self.layer = layer
		self.geo_ip = None
		self.args = args
		self.data = {}
		self.dnsCACHE = dnsCACHE
		self.title = 'Title goes here'
		try:
			self.geo_ip = maxminddb.open_database(self.args.geopath) # command line -G
		except:
			if self.args.DEBUG:
				print("### non fatal but annoying error: could not load GeoIP data from supplied parameter geopath %s so no geographic data can be shown in labels" % self.args.geopath)
		if self.args.restrict:
			packetsr = [x for x in packets if ((x[0].src in self.args.restrict) or (x[0].dst in self.args.restrict))]
			if len(packetsr) == 0:
				print('### warning - no packets left after filtering on %s - nothing to plot' % self.args.restrict)
				return
			else:
				if self.args.DEBUG:
					print('%d packets filtered with restrict = ' % (len(packets) - len(packetsr)),self.args.restrict)
				packets = packetsr
		if self.layer == 2:
			edges = map(self._layer_2_edge, packets)
		elif self.layer == 3:
			edges = map(self._layer_3_edge, packets)
		elif self.layer == 4:
			edges = map(self._layer_4_edge, packets)
		else:
			raise ValueError("Other layers than 2,3 and 4 are not supported yet!")

		for src, dst, packet in filter(lambda x: not (x is None), edges):
			if src in self.graph and dst in self.graph[src]:
				self.graph[src][dst]['packets'].append(packet)
			else:
				self.graph.add_edge(src, dst)
				self.graph[src][dst]['packets'] = [packet]

		for node in self.graph.nodes():
			self._retrieve_node_info(node,packet)

		for src, dst in self.graph.edges():
			self._retrieve_edge_info(src, dst)


	def get_in_degree(self, print_stdout=True):
		unsorted_degrees = self.graph.in_degree()
		return self._sorted_results(unsorted_degrees, print_stdout)

	def get_out_degree(self, print_stdout=True):
		unsorted_degrees = self.graph.out_degree()
		return self._sorted_results(unsorted_degrees, print_stdout)

	def _sorted_results(self,unsorted_degrees, print_stdout):
		sorted_degrees = OrderedDict(sorted(list(unsorted_degrees), key=lambda t: t[1], reverse=True))
		for i in sorted_degrees:
			if print_stdout:
				nn = self.dnsCACHE[i]['ip']
				if (nn == i):
					print(sorted_degrees[i], i)
				else:
					print(sorted_degrees[i],i,nn)
		return sorted_degrees


	def _retrieve_node_info(self, node, packet):				
		"""cache all (slow!) fqdn reverse dns lookups from ip"""
		self.data[node] = {'packet':packet}
		drec = {'ip':None,'fqdname':None,'whoname':None,'city':None,'country':None,'mac':None}
		ns = node.split(':')
		if len(ns) <= 2: # has a port - not a mac or ipv6 address
			ip = ns[0]
		else:
			ip = node
		if packet[0].src:
			mac = packet[0].src
		else:
			mac = None
		ddict = self.dnsCACHE.get(ip,None)
		if ddict == None: # never seen
			ddict = copy.copy(drec)
			ddict['ip'] = node
			if mac != None:
				ddict['mac'] = mac
			city = ''
			country = ''
			if self.geo_ip and (':' not in ip):			
				mmdbrec = self.geo_ip.get(ip)
				if mmdbrec != None:
					countryrec = mmdbrec.get('country',None)
					cityrec = mmdbrec.get('city',None)
					if countryrec: # some records have one but not the other....
						country = countryrec['names'].get(self.args.geolang,None)
						self.data[node]['country'] = country
					if cityrec:
						city =  cityrec['names'].get(self.args.geolang,None)
						self.data[node]['city'] = city
				else:
					if self.args.DEBUG:
						print("could not load GeoIP data for ip %s" % ip)
			ddict['city'] = city
			ddict['country'] = country
			if not (':' in ip):
				fqdname = socket.getfqdn(ip)
				if self.args.DEBUG:
					print('##ip',ip,' = fqdname',fqdname)
				ddict['fqdname'] = fqdname
				try:
					who = IPWhois(ip)
					qry = who.lookup_rdap(depth=1)
					whoname = qry['asn_description']
				except IPDefinedError:
					whoname = '(Private LAN address)'
				ddict['whoname'] = whoname
				fullname = '%s\n%s' % (fqdname,whoname)
			else:
				ddict['fqdname'] = ''
			self.dnsCACHE[node] = ddict
			if self.args.DEBUG:
				print('## looked up',node,'and added',ddict)
		


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
			_ = packet[2]
			return "%s:%i" % (src, _.sport), "%s:%i" % (dst, _.dport), packet

	def draw(self, filename=None):
		graph = self.get_graphviz_format()
		graph.graph_attr['label'] = self.title
		graph.graph_attr['labelloc'] = 't'
		graph.graph_attr['fontsize'] = 20
		graph.graph_attr['fontcolor'] = 'blue'
		for node in graph.nodes():
			if node not in self.data:
				# node might be deleted, because it's not legit etc.
				continue
			snode = str(node)
			ssnode = snode.split(':') # look for mac or a port on the ip
			if len(ssnode) <= 2:
				ip = ssnode[0]
				ddict = self.dnsCACHE[ip]
			else:
				ip = snode
				ddict = self.dnsCACHE[snode] 
			node.attr['shape'] = self.args.shape
			node.attr['fontsize'] = '11'
			node.attr['width'] = '0.5'
			node.attr['color'] = 'powderblue' # assume all are local hosts
			node.attr['style'] = 'filled,rounded'
			country = ddict['country']
			city = ddict['city']
			fqdname = ddict['fqdname']
			mac = ddict['mac']
			whoname = ddict['whoname']
			if whoname != None and whoname != '(Private LAN address)':
				node.attr['color'] = 'violet' # remote hosts
			nodelabel = [node,]
			if fqdname > '' and fqdname != ip:
				nodelabel.append('\n')
				nodelabel.append(fqdname)
			if city > '' or country > '':
				nodelabel.append('\n')
					
				nodelabel.append('%s %s' % (city,country))
			if whoname and whoname > '':
				nodelabel.append('\n')
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
		graph.draw(filename)

	def get_graphviz_format(self, filename=None):
		agraph = networkx.drawing.nx_agraph.to_agraph(self.graph)
		# remove packet information (blows up file size)
		for edge in agraph.edges():
			del edge.attr['packets']
		if filename:
			agraph.write(filename)
		return agraph
