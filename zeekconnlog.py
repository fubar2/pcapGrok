# zeek conn log to graphs?
# ts,uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto,service,duration,orig_bytes,resp_bytes,conn_state,local_orig,local_resp,missed_bytes,history,orig_pkts,orig_ip_bytes,resp_pkts,resp_ip_bytes,tunnel_parents,orig_l2_addr,resp_l2_addr,vlan,inner_vlan
# "1258790493.773208","CcH8zVkCER7UopU1j","192.168.1.104",137,"192.168.1.255",137,"udp","dns",3.748891,350,0,"S0",False,False,0,"D",7,546,0,0,"","00:0b:db:4f:6b:10","ff:ff:ff:ff:ff:ff","",""
"""
ross lazarus december 2019 
forked from mateuszk87/PcapViz
changed geoIP lookup to use maxminddb
added reverse DNS lookup and cache with host names added to node labels
added CL parameters to adjust image layout and shapes
"""

from collections import OrderedDict
from argparse import ArgumentParser
import networkx
import itertools
from networkx import DiGraph

import logging
import sys
import os
import socket
import maxminddb
from ipwhois import IPWhois
from ipwhois import IPDefinedError
import copy
import csv
import threading
from queue import Queue
import logging
import argparse
import ipaddress
import pathlib


from json import loads, dumps
from elasticsearch import Elasticsearch, helpers
from datetime import datetime
from traceback import print_exc
import gzip
import time

DHCP_PORT = 67
BOOT_REQ = 1

DHCPDUMP_FILE = 'pcapgrok_dhcp.json'
dnsCACHEfile = 'pcapgrok_dns_cache.csv'
logFileName = 'zeekconlog.log'
IPBROADCAST = '0.0.0.0'
MACBROADCAST = 'ff:ff:ff:ff:ff:ff'
PRIVATE = '(Private LAN address)'
SEPCHAR = ','

logging.basicConfig(filename=logFileName,level=logging.INFO,filemode='w')


MULTIMAC = "01:00:5e"
UNIMAC = "00:00:5e"
BROADCASTMAC = "ff:ff:ff:ff:ff:ff"
ALLBC = ['multicast','igmp','unicast','broadcast','broadcasthost']

PRIVATE = '(Private LAN address)'

NTHREADS = 100


class ParseZeekLogs(object):
	"""
	Modified to deal with .gz compressed logs. Ross Lazarus feb 2020. Need to deal with bytes rather
	than strings as that's what gzip gives.
	Class that parses Zeek logs and allows log data to be output in CSV or json format.
	Attributes:
		filepath: Path of Zeek log file to read
	"""

	def __init__(self, filepath, batchsize=500, fields=None, output_format=None, ignore_keys=[], meta={}, safe_headers=False):
		if filepath.endswith('.gz'):
			self.fd = gzip.open(filepath, 'rb')
		else:
			self.fd = open(filepath,"rb")
		self.options = OrderedDict()
		self.firstRun = True
		self.filtered_fields = fields
		self.batchsize = batchsize
		self.output_format = output_format
		self.ignore_keys = ignore_keys
		self.meta = meta
		self.safe_headers = safe_headers

		# Convert ' to " in meta string
		meta = loads(dumps(meta).replace("'", '"'))

		# Read the header option lines
		l = self.fd.readline().strip()
		while l != None and l.startswith(b'#'):
			ld = l.decode('unicode_escape')
			# Parse the options out
			if ld.startswith('#separator'):
				key = ld[1:].split(" ")[0]
				value = ld[1:].split(" ")[1]
				self.options[key] = value
				# Read the next line
				l = self.fd.readline().strip()
			elif ld.startswith("#"):
				lsp = ld[1:].split(self.options.get('separator'))
				key = lsp[0]
				value = lsp[1:]
				self.options[key] = value
				# Read the next line
				l = self.fd.readline().strip()

		self.firstLine = l.decode('unicode_escape')
		# Save mapping of fields to values:
		self.fields = self.options['fields']
		self.types = self.options['types']

		# Convert field names if safe_headers is enabled
		#if self.safe_headers is True:
		#    for i, val in enumerate(self.fields):
		#        self.fields[i] = self.fields[i].replace(".", "_")

		self.data_types = {}
		for i, val in enumerate(self.fields):
			# Convert field names if safe_headers is enabled
			if self.safe_headers is True:
				self.fields[i] = self.fields[i].replace(".", "_")

			# Match types with each other
			self.data_types[self.fields[i]] = self.types[i]

	def __del__(self):
		self.fd.close()

	def __iter__(self):
		return self

	def __next__(self):
		retVal = ""
		if self.firstRun is True:
			retVal = self.firstLine
			self.firstRun = False
		else:
			retVal = self.fd.readline().strip().decode('unicode_escape')

		# If an empty string is returned, readline is done reading
		if retVal == "" or retVal is None:
			raise StopIteration

		# Split out the data we are going to return
		retVal = retVal.split(self.options.get('separator'))

		record = None
		# Make sure we aren't dealing with a comment line
		if len(retVal) > 0 and not str(retVal[0]).strip().startswith("#") \
				and len(retVal) is len(self.options.get("fields")):
			record = OrderedDict()
			# Prepare fields for conversion
			for x in range(0, len(retVal)):
				if self.safe_headers is True:
					converted_field_name = self.options.get("fields")[x].replace(".", "_")
				else:
					converted_field_name = self.options.get("fields")[x]
				if self.filtered_fields is None or converted_field_name in self.filtered_fields:
					# Translate - to "" to fix a conversation error
					if retVal[x] == "-":
						retVal[x] = ""
					# Save the record field if the field isn't filtered out
					record[converted_field_name] = retVal[x]

			# Convert values to the appropriate record type
			record = self.convert_values(record, self.ignore_keys, self.data_types)

			if record is not None and self.output_format == "json":
				# Output will be json

				# Add metadata to json
				for k, v in self.meta.items():
					record[k] = v

				retVal = dumps(record)
			elif record is not None and self.output_format == "csv":
				retVal = ""
				# Add escaping to csv format
				for k, v in record.items():
					# Add escaping to string values
					if isinstance(v, str):
						retVal += str("\"" + str(v).strip() + "\"" + ",")
					else:
						retVal += str(str(v).strip() + ",")
				# Remove the trailing comma
				retVal = retVal[:-1]
		else:
			retVal = None

		return retVal

	def convert_values(self, data, ignore_keys=[], data_types={}):
		keys_to_delete = []
		for k, v in data.items():
			# print("evaluating k: " + str(k) + " v: " + str(v))

			if isinstance(v, dict):
				data[k] = self.convert_values(v)
			else:
				if data_types.get(k) is not None:
					if (data_types.get(k) == "port" or data_types.get(k) == "count"):
						if v != "":
							data[k] = int(v)
						else:
							keys_to_delete.append(k)
					elif (data_types.get(k) == "double" or data_types.get(k) == "interval"):
						if v != "":
							data[k] = float(v)
						else:
							keys_to_delete.append(k)
					elif data_types.get(k) == "bool":
						data[k] = bool(v)
					else:
						data[k] = v

		for k in keys_to_delete:
			del data[k]

		return data

	def get_fields(self):
		"""Returns all fields present in the log file
		Returns:
			A python list containing all field names in the log file
		"""
		field_names = ""
		if self.output_format == "csv":
			for i, v in enumerate(self.fields):
				if self.filtered_fields is None or v in self.filtered_fields:
					field_names += str(v) + ","
			# Remove the trailing comma
			field_names = field_names[:-1].strip()
		else:
			field_names = []
			for i, v in enumerate(self.fields):
				if self.filtered_fields is None or v in self.filtered_fields:
					field_names.append(v)
		return field_names

	@staticmethod
	def bulk_to_elasticsearch(es, bulk_queue):
		try:
			helpers.bulk(es, bulk_queue)
			return True
		except:
			print(print_exc())
			return False

	@staticmethod
	def batch_to_elk(filepath=None, batch_size=500, fields=None, elk_ip="127.0.0.1", index="zeeklogs", meta={},
					 ignore_keys=[]):
		# Create handle to ELK
		es = Elasticsearch([elk_ip])

		# Create a handle to the log data
		dataHandle = ParseZeekLogs(filepath, fields=fields, output_format="json", meta=meta)

		# Begin to process and output data
		dataBatch = []
		for record in dataHandle:
			try:
				record = loads(record)

				if isinstance(record, dict):
					record["_index"] = index
					record["_type"] = index
					try:
						record['timestamp'] = datetime.utcfromtimestamp(float(record['ts'])).isoformat()
					except:
						pass

					dataBatch.append(record)

					if len(dataBatch) >= batch_size:
						# Batch the queue to ELK
						# print("Batching to elk: " + str(len(dataBatch)))
						dataHandle.bulk_to_elasticsearch(es, dataBatch)
						# Clear the data queue
						dataBatch = []
			except:
				pass

		# Batch the final data to ELK
		# print("Batching final data to elk: " + str(len(dataBatch)))
		dataHandle.bulk_to_elasticsearch(es, dataBatch)
		# Clear the data queue
		dataBatch = []

	def __str__(self):
		return dumps(self.data)


class parDNS():
	""" dns/whois lookups parallel for speed
	filter with ipaddress module
	"""

	def __init__(self,lookmeup,ip_macdict,geo_ip,geo_lang):
		self.lookmeup = lookmeup
		self.drec =  {'ip':'','fqdname':'','whoname':'','city':'','country':'','mac':''}
		self.drecs = {}
		self.dnsq_lock = threading.Lock()
		self.dnsq = Queue()
		self.ip_macdict = ip_macdict
		self.geo_ip = geo_ip
		self.geo_lang = geo_lang
		self.logger = logging.getLogger('pardns')
		self.logger.setLevel(logging.DEBUG)


		
	def lookup(self,ip):
			ddict = copy.copy(self.drec)
			ddict['ip'] = ip
			whoname = None
			mymac = self.ip_macdict.get(ip,None)
			fqdname = ''
			city = ''
			country = ''	
			ns = ip.split(':')
			iptrim = ip
			if len(ns) <= 2:
				iptrim = ns[0]
				if iptrim.lower() in ['0.0.0.0','ff.ff.ff.ff','255.255.255.255']:
					whoname = PRIVATE
					fqdname = 'Broadcast'			
			elif len(ns) == 6: # mac
				iptrim = None
				whoname = 'MAC'
				fqdname = ip
				mymac = ip
			ipa = None
			if iptrim != None and fqdname == '': # not broadcast
				try:
					ipa = ipaddress.ip_address(iptrim)
				except:
					ipa == None
					self.logger.debug('ip %s not convertable to ipaddress in lookup' % ip)
				if ipa != None:
					if ipa.is_multicast:
						whoname = 'Multicast'
						fqdname = 'Multicast_IP'
					if ipa.is_link_local:
						whoname = PRIVATE
						fqdname = 'LinkLocal_IP'
					if ipa.is_loopback:
						whoname = PRIVATE
						fqdname = 'Loopback_IP'
					if ipa.is_reserved:
						whoname = PRIVATE
						fqdname = 'Reserved_IP'
					if ipa.is_unspecified:
						whoname = PRIVATE
						fqdname = 'Unspecified_IP'
					if ipa.is_private:
						whoname = PRIVATE
						fqdname = 'Local_LAN_IP'
			if whoname == None and ipa != None and ipa.is_global: # not yet found and not mac	
				fqdname = socket.getfqdn(iptrim)
				try:
					who = IPWhois(iptrim)
					qry = who.lookup_rdap(depth=1)
					whoname = qry['asn_description']
				except Exception as e:
					whoname = PRIVATE
					with self.dnsq_lock: # make sure no race
						self.logger.debug('#### IPwhois failed ?timeout? for ip = %s = %s' % (iptrim,e))
				fullname = '%s\n%s' % (fqdname,whoname)
				if iptrim > '' and self.geo_ip and whoname != PRIVATE:			
					mmdbrec = self.geo_ip.get(iptrim)
					if mmdbrec != None:
						countryrec = mmdbrec.get('country',None)
						cityrec = mmdbrec.get('city',None)
						if countryrec: # some records have one but not the other....
							country = countryrec['names'].get(self.geo_lang,None)
						if cityrec:
							city =  cityrec['names'].get(self.geo_lang,None)
					else:
						self.logger.warning("could not load GeoIP data for ip %s" % iptrim)
			else:
				self.logger.debug('ip %s has whoname %s and is not a global address so no lookups' % (ip,whoname))
			ddict['city'] = city
			ddict['country'] = country
			ddict['whoname'] = whoname
			ddict['fqdname'] = fqdname
			ddict['mac'] = mymac
			with self.dnsq_lock: # make sure no race
				self.drecs[iptrim] = ddict
				self.logger.debug('fast got city country %s,%s fqdname %s for ip %s' % (city,country,ddict['fqdname'],iptrim))
		
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




class ZeekConnGraphManager(object):
	""" Generates and processes the graph based on packets
	"""

	def __init__(self, args, dnsCACHE,ip_macdict,mac_ipdict):
		self.logger = logging.getLogger("zeekConnGraphManager")
		self.logger.setLevel(logging.DEBUG)
		self.graph = DiGraph()
		self.squishPorts = args.squishPorts
		self.geo_ip = None
		self.geo_lang = args.geolang
		self.args = args
		self.data = {}
		self.ip_macdict = ip_macdict
		self.mac_ipdict = mac_ipdict
		self.dnsCACHE = dnsCACHE
		try:
			self.geo_ip = maxminddb.open_database(self.args.geopath) # command line -G
		except:
			logger.warning("### non fatal but annoying error: could not load GeoIP data from supplied parameter geopath %s so no geographic data can be shown in labels" % self.args.geopath)

	def reset(self, packets, layer, title):
		""" recycle large structures between plots
		"""
		del self.graph
		del self.data
		self.graph = DiGraph()
		self.data = {}
		assert layer in [2,3,4],'###GraphManager reset got layer = %s. Must be 2,3 or 4' % str(layer)
		assert len(packets) > 0, '###GraphManager reset got empty packets list - nothing useful can be done'
		self.layer = layer
		self.title = title
		if self.args.restrict:
			packetsr = [x for x in packets if ((x['orig_l2_addr'] in self.args.restrict) or (x['orig_l2_addr'].dst in self.args.restrict))]
			if len(packetsr) == 0:
				logger.warning('### warning - no packets left after filtering on %s - nothing to plot' % self.args.restrict)
				return
			else:
				logger.info('%d packets filtered leaving %d with restrict = %s' % (len(packets) - len(packetsr),len(packetsr),self.args.restrict))
				packets = packetsr
		if self.layer == 2:
			edges = map(self._layer_2_edge, packets)
		elif self.layer == 3:
			edges = map(self._layer_3_edge, packets)
		elif self.layer == 4:
			edges = map(self._layer_4_edge, packets)
		else:
			raise ValueError("Only layers 2,3 and 4 supported")
		for (src, dst, packet) in edges:
			if src == '':
				logger.debug('empty src in edges for packet = %s' % packet)
				continue
			if self.layer == 4 and self.squishPorts:
				if len(src.split(':')) == 2:
					src = src.split(':')[0]
				if len(dst.split(':')) == 2:
					dst = dst.split(':')[0]
			if src in self.graph and dst in self.graph[src]:
				self.graph[src][dst]['packets'].append(packet)
			else:
				self.graph.add_edge(src, dst)
				self.graph[src][dst]['packets'] = [packet,]
		self._fast_retrieve_node_info()
		for src, dst in self.graph.edges():
			self._retrieve_edge_info(src, dst)
		# print('end init, graph nodes=',self.graph.nodes)

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


	def checkmacdict(self,ip,mac):
		""" keep dict for accounting
		"""
		amac = self.ip_macdict.get(ip,None)
		anip = self.mac_ipdict.get(mac,None)
		if not amac: # not there yet
			if (len(ip.split(':')) == 1 or len(ip.split('::')) == 1) and len(mac.split(':')) == 6 : # mac - not ipv6
				self.ip_macdict[ip] = mac
				self.mac_ipdict[mac] = ip

	def _fast_retrieve_node_info(self):				
		"""parallel all (slow!) fqdn reverse dns lookups from ip"""
		lookmeup = [] # parallel for ip not in cache yet
		for node in self.graph.nodes:
			ns = node.split(':')
			ip = ns[0]
			if len(ns) == 8:
				ip = node # ipv6?
			if len(ns) == 6: # mac
				continue # no point
			ddict = self.dnsCACHE.get(ip,None) # index is unadorned ip or mac
			if ddict == None:
				try:
					ipa = ipaddress.ip_address(ip)
				except:
					logger.warning('IP address %s does not convert using ip_address()' % ip)
					continue
				if ipa.is_global:
					lookmeup.append(ip)
		if len(lookmeup) > 0:
			fastdns = parDNS(lookmeup,self.ip_macdict,self.geo_ip,self.geo_lang)
			drecs = fastdns.doRun()
			kees = drecs.keys()
			for k in kees:
				if self.dnsCACHE.get(k,None):
					self.logger.warning('Odd - key %s was already in self.dnsCACHE after fast lookup = %s - fast = %s - not replaced' % (k,self.dnsCACHE[k],drecs[k]))
				else:
					self.dnsCACHE[k] = copy.copy(drecs[k])
					self.logger.debug('## fast looked up %s and added %s' % (k,drecs[k]))
		else:
			self.logger.debug('_fast_retrieve_node found no ip addresses missing from dnsCACHE')



	def _retrieve_node_info(self, node, packet):				
		"""cache all (slow!) fqdn reverse dns lookups from ip"""
		self.data[node] = {'packet':packet}
		drec = {'ip':'','fqdname':'','whoname':'','city':'','country':'','mac':''}
		ns = node.split(':')
		if len(ns) <= 2: # has a port - not a mac or ipv6 address
			ip = ns[0]
		else:
			ip = node # might be ipv6 or mac - use as key
		city = ''
		country = ''
		ddict = self.dnsCACHE.get(ip,None) # index is unadorned ip or mac
		mymac = packet.get('orig_l2_addr',None)
		if ddict == None: # never seen - ignore ports because annotation is always the same
			ddict = copy.copy(drec)
			ddict['ip'] = ip # was ip	
			if mymac:
				ddict['mac'] = mymac
			if ip.startswith('240.0'): # is igmp
				ddict['fqdname'] = 'Multicast'
				ddict['whoname'] = 'IGMP'
			if ip.startswith(MULTIMAC):
				ddict['fqdname'] = 'Multicast'
			elif ip.startswith(UNIMAC):
				ddict['fqdname'] = 'Unicast'
			elif ip == BROADCASTMAC:
				ddict['fqdname'] = 'Broadcast'
			else:
				if ip > '' and not (':' in ip):
					fqdname = socket.getfqdn(ip)
					ddict['fqdname'] = fqdname
					try:
						who = IPWhois(ip)
						qry = who.lookup_rdap(depth=1)
						whoname = qry['asn_description']
					except Exception as e:
						whoname = PRIVATE
						logger.debug('#### IPwhois failed ?timeout? for ip = %s = %s' % (ip,e))
					ddict['whoname'] = whoname
					fullname = '%s\n%s' % (fqdname,whoname)
				else:
					ddict['fqdname'] = ''
				city = ''
				country = ''
				if ip > '' and self.geo_ip and ddict['whoname'] != PRIVATE and (':' not in ip):			
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
						logger.error("could not load GeoIP data for ip %s" % ip)
			ddict['city'] = city
			ddict['country'] = country
			self.dnsCACHE[node] = ddict
			self.checkmacdict(ddict['ip'],ddict['mac'])
			logger.info('## looked up %s and added %s' % (node,ddict))
		else: # exists - add to ip_macdict etc
			if mymac != ddict['mac']:
				logger.debug('hum. mymac %s ddict mac %s for %s' % (mymac,ddict['mac'],ddict['ip']))
			if ddict['mac'] > '' and ddict['mac'] != ddict['ip']:
				self.checkmacdict(ddict['ip'],ddict['mac'])		
			


	def _retrieve_edge_info(self, src, dst):
		edge = self.graph[src][dst]
		if edge:
			packets = edge['packets']
			edge['layers'] = []
			for p in packets:
				for l in p['layers']:
					if not l in edge['layers']:
						edge['layers'].append(l) 
			edge['transmitted'] = sum(x['bytes'] for x in packets)
			edge['connections'] = len(packets)

	@staticmethod
	def get_layers(packet):
		return packet['layers']


	@staticmethod
	def _layer_2_edge(packet):
		b1 = packet.get('orig_bytes',0)
		b2 = packet.get('resp_bytes',0)
		if b1 and b1 != 'False' and b1 != "True":
			packet['bytes'] += int(b1)
		if b2 and b2 != 'False' and b2 != "True":
			packet['bytes'] += int(b2)
		src = packet.get('orig_l2_addr','')	
		dst = packet.get('resp_l2_addr','NODESTMAC')
		return (src, dst, packet)
			
	@staticmethod
	def _layer_3_edge(packet):
		src = ''
		dst = ''
		if packet.get('proto','') > '':
			proto =  packet['proto']
			src = packet.get('id.orig_h','')
			dst = packet.get('id.resp_h','NODESTIP')
			b1 = packet.get('orig_bytes','0')
			b2 = packet.get('resp_bytes','0')
			if b1 and b1 != 'False' and b1 != "True":
				packet['bytes'] += int(b1)
			if b2 and b2 != 'False' and b2 != "True":
				packet['bytes'] += int(b2)
			if not proto in packet['layers']:
				packet['layers'].append(proto)
		else:
			print('#### empty proto for packet',packet)
		return (src, dst, packet)

	@staticmethod
	def _layer_4_edge(packet):
		src = ''
		dst = ''
		if packet.get('proto','') > '':
			if any(map(lambda p: packet['proto'], ['TCP', 'UDP'])):
				b1 = packet.get('orig_bytes',0)
				b2 = packet.get('resp_bytes',0)
				if b1 and b1 != 'False' and b1 != "True":
					packet['bytes'] += int(b1)
				if b2 and b2 != 'False' and b2 != "True":
					packet['bytes'] += int(b2)
				service = packet.get('service','')
				proto = packet['proto']
				if not proto in packet['layers']:
					packet['layers'].append(proto)
				if not service in packet['layers']:
					packet['layers'].append(service)
				src = packet.get('id.orig_h',None)
				dst = packet.get('id.resp_h',None)
				sp = packet.get('id.orig_p','')
				dp = packet.get('id.resp_p','')
				if sp > '':
					src = '%s:%s' % (src,sp)
				if dp > '':
					dst = '%s:%s' % (dst,dp)
			else:
				print('#### got different proto',packet['proto'])
		return (src, dst, packet)

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
			snodes = snode.split(':')
			if len(snodes) == 2: # need to strip port in layer 4 for dnscache lookup
				ddict = self.dnsCACHE[snodes[0]]
			else:
				ddict = self.dnsCACHE[snode]
			ip = ddict['ip']
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
			if whoname != None and whoname != PRIVATE:
				node.attr['color'] = 'violet' # remote hosts
			if ddict['fqdname'].lower() in ALLBC:
				node.attr['color'] = 'lightyellow' # broad/multicast/igmp
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
			
		totalbytes = 0
		for edge in graph.edges():
			connection = self.graph[edge[0]][edge[1]]
			totalbytes += int(connection['transmitted'])
		for edge in graph.edges():
			connection = self.graph[edge[0]][edge[1]]	
			edge.attr['label'] = 'transmitted: %i bytes\n%s ' % (connection['transmitted'], ' | '.join(connection['layers']))
			edge.attr['fontsize'] = '11'
			edge.attr['minlen'] = '2'
			edge.attr['penwidth'] = min(max(0.05,8*connection['transmitted']/float(totalbytes)), 8.0)
		for eng in self.args.layoutengine:
			fs = filename[:-4]
			ext = filename[-4:]
			ofname = '%s%s%s' % (fs,eng,ext)
			self.logger.debug('Layout = %s to %s for %s' % (eng,ofname,filename))
			graph.layout(prog=eng)
			graph.draw(ofname)
		self.agraph = graph

	def get_graphviz_format(self, filename=None):
		agraph = networkx.drawing.nx_agraph.to_agraph(self.graph)
		# remove packet information (blows up file size)
		for edge in agraph.edges():
			del edge.attr['packets']
		if filename:
			agraph.write(filename)
		return agraph



def saveDNS(d,ip_macdict):
	header = ['ip','fqdname','city','country','whoname','mac']	
	with open(dnsCACHEfile,'w') as cached:
		writer = csv.DictWriter(cached,delimiter=SEPCHAR,fieldnames = header)
		writer.writeheader()
		for k in d.keys():
			row =d[k]
			if len(k.split(':')) == 6:
				if row['ip'] == '':
					row['ip'] = ip_macdict.get(k)
					s = '## Added ip %s to mac entry for %s' % (args.row['ip'],k)
					print(s)
					logger.error(s)
			else:
				row['ip'] = k
			writer.writerow(row)
		cached.close()
	logger.info('wrote %d rows to %s' % (len(d),dnsCACHEfile))
	


def readHostsFile(hostfile,dnsCACHE):
	din = csv.reader(open(args.hostsfile,'r'),delimiter=SEPCHAR)
	logger.info("reading hostsfile %s" % args.hostsfile)
	header = None
	for i,row in enumerate(din):
		if len(row) == 0:
			continue
		elif row[0].lstrip().startswith('#'):
			continue
		elif header == None:
			header = row
			s = '## hostsfile %s header = %s' % (args.hostsfile,header)
			logger.info(s)
		else:
			k = row[0].lower()
			rest = {}
			for i,tk in enumerate(header):
				if (len(row) > (i)):
					rest[tk] = row[i]
				else:
					rest[tk] = ''
					print('$$$ bad row %d in hostsfile = %s' % (i,row)) 
			if rest['mac'] > '': # make sure there's a mac keyed entry
				mrest = copy.copy(rest)
				mrest['ip'] = rest['mac']
				mrest['whoname'] = ''
				dnsCACHE[rest['mac']] = mrest
				logger.info('### wrote new dnsCACHE mac entry k=%s contents=%s from supplied hostsfile %s' % (k,rest,hostfile))
			dnsCACHE[k] = rest
			logger.info('### wrote new dnsCACHE entry k=%s contents=%s from supplied hostsfile %s' % (k,rest,hostfile))
	
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
	logger.info("reading dnsCACHEfile %s" % dnsCACHEfile)
	header = None
	for i,row in enumerate(din):
		if len(row) == 0:
			continue
		elif row[0].lstrip().startswith('#'):
			continue
		elif header == None:
			header = row
			s = '## dnscache %s header = %s' % (dnsCACHEfile,header)
			logger.info(s)
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
			
			logger.info('### dnsCACHE entry k=%s contents=%s from existing cache' % (k,rest))
	return dnsCACHE

def prepipmacdicts(dnscache):
	ipm = {}
	mip = {}
	for k in dnscache.keys():
		d = dnscache[k]
		amac = d.get('mac',None)
		anip = d.get('ip',None)
		if amac and anip and (len(anip.split(':')) == 1 or len(anip.split('::')) == 1) and len(amac.split(':')) == 6 and amac != anip: # mac - not ipv6
			ipm[anip] = amac
			mip[amac] = anip
	# print('ipm=',ipm,'\nmip=',mip)
	return ipm,mip

DHCP_PORT = 67
BOOT_REQ = 1

DHCPDUMP_FILE = 'pcapgrok_dhcp.json'
dnsCACHEfile = 'pcapgrok_dns_cache.csv'
logFileName = 'pcapgrok.log'
IPBROADCAST = '0.0.0.0'
MACBROADCAST = 'ff:ff:ff:ff:ff:ff'
PRIVATE = '(Private LAN address)'
SEPCHAR = ','

logging.basicConfig(filename=logFileName,level=logging.INFO,filemode='w')


# put here so we can import it for tests

parser = ArgumentParser(description='Network Zeek conn log topology and message mapper. Optional protocol whitelist or blacklist and mac restriction to simplify graphs. Draws all 3 layers unless a single one is specified')
parser.add_argument('-a', '--append', action='store_true',default=True, required=False, help='Append multiple input files before processing as PcapVis previously did. New default is to batch process each input pcap file separately.')
parser.add_argument('-b', '--blacklist', nargs='*', help='Blacklist of protocols - NONE of the packets having these layers shown eg DNS NTP ARP RTP RIP',required=False)
parser.add_argument('-E', '--layoutengine', nargs="*", help='Graph layout method - dot, sfdp etc.',required=False)
parser.add_argument('-fi', '--frequent-in', action='store_true', help='Print frequently contacted nodes to stdout',required=False)
parser.add_argument('-fo', '--frequent-out', action='store_true', help='Print frequent source nodes to stdout',required=False)
parser.add_argument('-g', '--graphviz', help='Graph will be exported for downstream applications to the specified file (dot format)',required=False)
parser.add_argument('-G', '--geopath', default='/usr/share/GeoIP/GeoLite2-City.mmdb', help='Path to maxmind geodb data',required=False)
parser.add_argument('-hf', '--hostsfile', required=False, help='Optional hosts file, following the same format as the dns cache file, which will have priority over existing entries in the cache')
parser.add_argument('-i', '--connlog', nargs='*',help='Mandatory space delimited list of zeek conn.log files to be analyzed - wildcards work too - e.g. -i Y*.log',required=True)
parser.add_argument('-l', '--geolang', default='en', help='Language to use for geoIP names')
parser.add_argument('--layer2', action='store_true', help='Device (mac address) topology network graph')
parser.add_argument('--layer3', action='store_true', help='IP layer message graph. Default')
parser.add_argument('--layer4', action='store_true', help='TCP/UDP message graph')
parser.add_argument('-n', '--nmax', default=100, help='Automagically draw individual protocols if more than --nmax nodes. 100 seems too many for any one graph.')
parser.add_argument('-o', '--outpath', required=False, default = None, help='All outputs will be written to the supplied path. Default (if none supplied) is current working directory')
parser.add_argument('-p', '--pictures', help='Image filename stub for all images - layers and protocols are prepended to make file names. Use (e.g.) .pdf or .png extension to specify the image type. PDF is best for large graphs')
parser.add_argument('-r', '--restrict', nargs='*', help='Whitelist of device mac addresses - restrict all graphs to traffic to or device(s). Specify mac address(es) as "xx:xx:xx:xx:xx:xx"')
parser.add_argument('-s', '--shape', default='diamond', help='Graphviz node shape - circle, diamond, box etc.')
parser.add_argument('-S', '--squishPorts', action='store_true', help='Amalgamate all host ports to simplify - only works for layer 4. Default is True',required=False,default=True)
parser.add_argument('-w', '--whitelist', nargs='*', help='Whitelist of protocols - only packets matching these layers shown - eg IP Raw HTTP')

args = parser.parse_args()


if __name__ == "__main__":
	dnsCACHE = {}
	ip_macdict = {}
	mac_ipdict = {}
	if not args.layoutengine or len(args.layoutengine) < 1:
		args.layoutengine = ['sfdp']
	if len(args.connlog) > 0:
		if args.outpath:
			if not (os.path.exists(args.outpath)):
				pathlib.Path(args.outpath).mkdir(parents=True, exist_ok=True)
			logging.basicConfig(filename=os.path.join(args.outpath,logFileName),filemode='w')
		else:
			logging.basicConfig(filename=logFileName,filemode='w')
		logger = logging.getLogger('zeekconnlog')

		if args.hostsfile:
			if os.path.isfile(args.hostsfile):
				dnsCACHE = readHostsFile(args.hostsfile,{})
			else:
				logger.info("## Cannot open hostsfile %s supplied on command line - skipping" % args.hostsfile)
		else:
			logger.info("### hostsfile not supplied")
		if os.path.isfile(dnsCACHEfile):
			dnsCACHE = readDnsCache(dnsCACHEfile,dnsCACHE)
			ip_macdict,mac_ipdict = prepipmacdicts(dnsCACHE)
		else:
			logger.info('### No dnsCACHE file %s found. Will create a new one' % dnsCACHEfile)
	else:
		logger.critical('### No zeek conn log file supplied --connlog is mandatory - stopping')
		sys.exit(1)
	g = ZeekConnGraphManager(args = args, dnsCACHE=dnsCACHE,ip_macdict=ip_macdict,mac_ipdict=mac_ipdict )
	packets = []
	if args.append:
		for zeekconn in args.connlog:
			log_iterator = ParseZeekLogs(zeekconn, output_format="csv", safe_headers=False)
			header = log_iterator.get_fields().split(',')
			for log_record in log_iterator:
				if log_record is not None:
					lrs = log_record.replace('"','').split(',')
					lr = dict(zip(header,lrs))
					lr['bytes'] = 0
					lr['layers'] = []
					packets.append(lr)
		fs = '_'.join(args.connlog)[:50]

		for layer in [2,3,4]:
			titl = 'Layer %d for data from Zeek connection log %s' % (layer,fs)
			squishPorts = False
			args.squishPorts = squishPorts
			g.reset(packets, layer=layer, title=titl )
			fn = 'conn_layer%d.pdf' % layer
			if args.outpath:
				fn = os.path.join(args.outpath,fn)
			g.draw(filename=fn)
			dnsCACHE = copy.copy(g.dnsCACHE)
			mac_ipdict = copy.copy(g.mac_ipdict) # these may have been added to...
			ip_macdict = copy.copy(g.ip_macdict)
	else:
		for zeekconn in args.connlog:
			log_iterator = ParseZeekLogs(zeekconn, output_format="csv", safe_headers=False)
			header = log_iterator.get_fields().split(',')
			for log_record in log_iterator:
				if log_record is not None:
					lrs = log_record.replace('"','').split(',')
					lr = dict(zip(header,lrs))
					lr['bytes'] = 0
					lr['layers'] = []
					packets.append(lr)
			fs = zeekconn

			for layer in [2,3,4]:
				titl = 'Layer %d for data from Zeek connection log %s' % (layer,fs)
				squishPorts = False
				args.squishPorts = squishPorts
				g.reset(packets, layer=layer, title=titl )
				fn = '%s_conn_layer%d.pdf' % (fs,layer)
				if args.outpath:
					fn = os.path.join(args.outpath,fn)
				g.draw(filename=fn)
				dnsCACHE = copy.copy(g.dnsCACHE)
				mac_ipdict = copy.copy(g.mac_ipdict) # these may have been added to...
				ip_macdict = copy.copy(g.ip_macdict)
		
	print('ip_macdict',ip_macdict)
	print('mac_ipdict',mac_ipdict)
	saveDNS(dnsCACHE,ip_macdict)


