import unittest
import sys
import os
from argparse import ArgumentParser
# finesse the imports - ugh - so we can run from the tests directory

PACKAGE_PARENT = '..'
SCRIPT_DIR = os.path.dirname(os.path.realpath(os.path.join(os.getcwd(), os.path.expanduser(__file__))))
sys.path.append(os.path.normpath(os.path.join(SCRIPT_DIR, PACKAGE_PARENT)))

from pcapviz.core import GraphManager
from pcapviz.sources import ScapySource

import os

parser = ArgumentParser(description='Network packet capture (standard .pcap file) topology and message mapper. Optional protocol whitelist or blacklist and mac restriction to simplify graphs. Draws all 3 layers unless a single one is specified')
parser.add_argument('-i', '--pcaps', nargs='*',help='Mandatory space delimited list of capture files to be analyzed - wildcards work too - e.g. -i Y*.pcap')
parser.add_argument('-o', '--out', help='Each topology will be drawn and saved using this filename stub. Use a .pdf or .png filename extension to specify image type')
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
parser.add_argument('-a', '--append', action='store_true',default=False, help='Append multiple input files before processing as PcapVis previously did. New default is to batch process each input pcap file separately.')

args = parser.parse_args()

class PcapProcessingTests(unittest.TestCase):

    def test_load_pcap(self):
        loaded = ScapySource.load(['test.pcap', 'test.pcap'])
        self.assertEqual(282, len(loaded))

    def test_build_graph_layer2(self):
        packets = ScapySource.load(['test.pcap'])
        g = GraphManager(packets, layer=2,args=args)
        self.assertEqual(3, g.graph.number_of_edges())

    def test_build_graph_layer3(self):
        packets = ScapySource.load(['test.pcap'])
        g = GraphManager(packets,args=args)
        self.assertEqual(8, g.graph.number_of_edges())

    def test_build_graph_layer4(self):
        packets = ScapySource.load(['test.pcap'])
        g = GraphManager(packets, layer=4,args=args)
        self.assertEqual(36, g.graph.number_of_edges())

    def test_get_frequent_ips_in(self):
        packets = ScapySource.load(['test.pcap'])
        g = GraphManager(packets, layer=3, args=args)
        ips = g.get_in_degree(print_stdout=True)
        self.assertIsNotNone(ips)

    def test_get_frequent_ips_out(self):
        packets = ScapySource.load(['test.pcap'])
        g = GraphManager(packets, layer=3, args=args)
        ips = g.get_out_degree(print_stdout=True)
        self.assertIsNotNone(ips)

    def _draw(self, png, layer):
        try:
            os.remove(png)
        except OSError:
            pass
        packets = ScapySource.load(['test.pcap'])
        g = GraphManager(packets, layer=layer, args=args)
        g.draw(filename=png)
        self.assertTrue(os.path.exists(png))

    def test_layer2(self):
        self._draw('test2.png', 2)

    def test_layer3(self):
        self._draw('test3.png', 3)

    def test_layer4(self):
        self._draw('test4.png', 4)

    def test_retrieve_geoip2(self):
        packets = ScapySource.load(['test.pcap'])
        g = GraphManager(packets, layer=2, args=args)
        node = list(g.data.keys())[0]
        g._retrieve_node_info(node)
        self.assertNotIn('country', g.data[node])

    def test_retrieve_geoip3(self):
        packets = ScapySource.load(['test.pcap'])
        g = GraphManager(packets, layer=3, args=args)
        node = list(g.data.keys())[0]
        g._retrieve_node_info(node)
        self.assertIn('country', g.data[node])

    def test_retrieve_geoip4(self):
        packets = ScapySource.load(['test.pcap'])
        g = GraphManager(packets, layer=4, args=args)
        node = list(g.data.keys())[0]
        g._retrieve_node_info(node)
        self.assertIn('country', g.data[node])

    def test_graphviz(self):
        packets = ScapySource.load(['test.pcap'])
        g = GraphManager(packets, layer=3,args=args)
        self.assertIsNotNone(g.get_graphviz_format())


if __name__ == '__main__':
    unittest.main()
