#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# extract all packets within a time window as a pcap file from a folder of rotated pcap logs 
# ross lazarus
# FSDTFORMAT should correspond to the suffix of the filename made by tcpdump
# tcpdump -i en0 -w "testbed_%Y-%m-%d-%H:%M:%S.pcap" -G 3600 
# for example. Use whatever you want before the underscore 
# and anything you like as the extension
# mismatched timezone settings between capture and analysis 
# images will cause the obvious consequences. 

import os
import sys
from datetime import datetime
from time import localtime,time
import dateutil
from scapy.all import *
import bisect
import pathlib
import logging
from subprocess import check_output,Popen, PIPE
from argparse import ArgumentParser
logFileName = 'pcap_period_extract.log'
logging.basicConfig(filename=logFileName,filemode='w')
FSDTFORMAT = '%Y-%m-%d-%H:%M:%S'

class pcapStore():
	""" find all subdirs and read within a time window
		# - use  (eg) tcpdump -i en0 -w "testbed_%Y-%m-%d-%H:%M:%S.pcap" -G 3600 
		The underscore allows easy trimming of the file name prefix part
	"""
	
	def __init__(self,pcapsFolder):
		self.pcapsFolder = pcapsFolder
		self.pcapfnames = []
		self.pcaptds = []

	def isScapypcap(self,ppath):
		"""test path to see if can be read
		"""
		ok = False
		try:
			foo = scapy.utils.PcapReader(ppath)
			ok = True
		except:
			s = str(ppath) + 'is not a valid pcap file'
			logging.debug(s)
		
		return ok 
		
		
	def readFolder(self):
		""" 
		index complex folders of pcaps on start date
		using fugly metadata in filename so a time window 
		of packets can be extracted
		"""
		pcapfnames = []
		pcaptds = [] # date time started
		pcapinfo = []
		for dirName, subdirList, fileList in os.walk(self.pcapsFolder):	
			for pfn in fileList:
				fs = pfn.split('_') # assume name works this way...
				if len(fs) == 2:
					fn = fs[1] 
					ppath = os.path.join(dirName, pfn)
					if self.isScapypcap(ppath):
						fstartdate = fn.split('.')[0] # date
						try:
							fsdt = datetime.strptime(fstartdate,FSDTFORMAT)
							fsdtt = int(time.mktime(fsdt.timetuple()))
							pcapinfo.append([fsdtt,ppath])
						except:
							logging.warning('Found pcap file name %s in path %s - expected %s preceded by an underscore - ignoring' % (pfn,self.pcapsFolder,FSDTFORMAT))
					else:
						logging.warning('File name %s in path %s is NOT a valid pcap file with _%s - ignoring' % (pfn,self.pcapsFolder,FSDTFORMAT))
		pcapinfo.sort() # files might turn up in any old order in complex archives
		self.pcapfnames = [x[1] for x in pcapinfo]
		self.pcaptds = [x[0] for x in pcapinfo]
		
		
	def writePeriod(self,sdt,edt,pcapdest):
		"""write packets in a datetime window into pcapdest as pcap
		"""
		self.readFolder() # in case any new ones since object instantiated
		respcap = []
		edtt = time.mktime(edt.timetuple()) # as seconds since epoch
		sdtt = time.mktime(sdt.timetuple())
		try:
			enddt = edt.strftime('%Y-%m-%d-%H:%M:%S')
			startdt = sdt.strftime('%Y-%m-%d-%H:%M:%S')
		except:
			logging.warning('##Problem with start and end datetimes in writePeriod - %s and %s - expected datetimes' % (sdt,edt))
			return False
		firstfi = bisect.bisect_left(self.pcaptds,int(sdtt))
		lastfi = min(bisect.bisect_right(self.pcaptds,int(edtt)) + 1, len(self.pcaptds)-1)
		acted = False
		npkt = 0
		for fnum in range(firstfi, lastfi):
			rdfname = self.pcapfnames[fnum]
			try:
				lsout=Popen(['lsof', '-t',rdfname],stdout=PIPE, shell=False)
				if lsout > "":
					logging.debug('file %s in use so not read' % rdfname)
			except:
				pin = rdpcap(rdfname)
				if (len(pin) > 0):
					mint = min([x.time for x in pin])
					maxt = max([x.time for x in pin])
					logging.debug('file %s has min %.2f and max %.2f' % (rdfname,mint,maxt))
					pin = [x for x in pin if int(x.time) >= sdtt and int(x.time) <= edtt] # gotta love scapy 
					if len(pin) > 0:
						npkt += len(pin)
						wrpcap(pcapdest, pin, append=True) #appends packets to output file
						acted = True
						logging.info('wrote %d packets to %s' % (len(pin),pcapdest))
					else:
						logging.debug('writePeriod got zero packets filtering by start %s end %s on pcap %s ' % (sdtt,edtt,rdfname))
				logging.debug('writePeriod got an empty pcap file at path %s - this happens...' % rdfname)
		logging.info('writePeriod filtered %d packets from %d packet files using window %s - %s to %s' % (npkt,lastfi-firstfi+1,startdt,enddt,pcapdest))
		return acted
		
if __name__ == "__main__": # testing testbed_2020-02-03-18:42:00.pcap
	
	parser = ArgumentParser(description='Pcap extractor from a folder of specifically named pcap packet capture files')
	parser.add_argument('-p','--pcappath', help='Path to root of capture file directory - all files are considered',required=True)
	parser.add_argument('-o','--outpath', help='output pcap path and file name for your analysis - eg /foo/bar/testpcap.pcap',required=True)
	parser.add_argument('-s', '--startdate', help='Start date/time - must be something like 2020-02-03-18:30:00 for example',required=True)
	parser.add_argument('-e', '--enddate', help='End date/time - must be something like 2020-02-03-19:00:00 for example',required=True)
	args = parser.parse_args()
	assert os.path.isdir(args.pcappath),'Path to pcaps %s not a valid path' % args.pcappath
	assert os.path.isdir(args.pcappath),'Path to pcaps %s not a valid path' % args.pcappath
	assert datetime.strptime(args.startdate, FSDTFORMAT),'Supplied start date %s does not parse with %s' % (args.startdate, FSDTFORMAT)
	assert datetime.strptime(args.enddate, FSDTFORMAT),'Supplied end %s does not parse with %s' % (args.enddate, FSDTFORMAT)
	outdir = os.path.dirname(args.outpath)
	if not (os.path.exists(outdir)):
		pathlib.Path(outdir).mkdir(parents=True, exist_ok=True)	
	ps = pcapStore(pcapsFolder = args.pcappath)
	dest = args.outpath
	sdt = datetime.strptime(args.startdate, FSDTFORMAT)
	edt = datetime.strptime(args.enddate, FSDTFORMAT)
	ok = ps.writePeriod(sdt,edt,dest)
	if not ok:
		sys.exit(1)
