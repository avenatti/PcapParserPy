import os,sys,inspect
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0,parentdir) 
import pcapparser




# pcap_file = 'connect_scan.pcap' # test producing 1654 refused + 6 connect --> 1660
# connect_scan.pcap Wireshark --> 1661 conversations (tcp and ip.src==192.168.1.100) packet 3&4 are not connect scan there for 1660
# pcap_file = 'halfopen.pcap' # test producing 1654 refused + 6 connect --> 1660
# halfopen.pcap Wireshark --> 1661 conversations (tcp and ip.src==192.168.1.100)
# pcap_file = 'udp_scan.pcap' # tested producing 1440 results (1456 total UDP)
# udp_scan.pcap Wireshark udp and ip.src == 192.168.1.100 --> view conversations 1427
# pcap_file = 'xmas_scan.pcap' # tested producing 1668 results (3328 total TCP)
# xmas_scan.pcap Wireshark filter tcp.flags==0X029 --> 1668
# pcap_file = 'null_scan.pcap' # tested producing 1668 results (3328 total TCP)
# null_scan.pcap Wireshark filter tcp.flags==0x000 --> 1668
# pcap_file = 'combo_scan.pcap' # merged null + xmas + udp + stealth


