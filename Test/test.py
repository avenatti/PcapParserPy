import os,sys,inspect
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0,parentdir) 
import pcapparser

# CONNECT SCAN TEST
# pcap_file = 'connect_scan.pcap' # test producing 1654 refused + 6 connect --> 1660
# connect_scan.pcap Wireshark --> 1661 conversations (tcp and ip.src==192.168.1.100) packet 3&4 are not connect scan there for 1660
connect_result = connect_scan('connect_scan.pcap')
print('ConnectScanTest: ' + ('Pass' if connect_result == 1660 else 'Fail'))

# STEALTH/HALFOPEN SCAN TEST
# pcap_file = 'halfopen_scan.pcap' # test producing 1654 refused + 6 connect --> 1660
# halfopen.pcap Wireshark --> 1661 conversations (tcp and ip.src==192.168.1.100)
stealth_result = halfopen_scan('halfopen_scan.pcap')
print('StealthScanTest: ' + ('Pass' if stealth_result == 1660 else 'Fail'))

# UDP SCAN TEST
# pcap_file = 'udp_scan.pcap' # tested producing 1440 results (1456 total UDP)
# udp_scan.pcap Wireshark udp and ip.src == 192.168.1.100 --> view conversations 1427
udp_result = udp_scan('udp_scan.pcap')
print('UDPScanTest: ' + ('Pass' if udp_result == 1440 else 'Fail'))

# XMAS SCAN TEST
# pcap_file = 'xmas_scan.pcap' # tested producing 1668 results (3328 total TCP)
# xmas_scan.pcap Wireshark filter tcp.flags==0X029 --> 1668
xmas_result = xmas_scan('xmas_scan.pcap')
print('XmasScanTest: ' + ('Pass' if xmas_result == 1668 else 'Fail'))

# NULL SCAN TEST
# pcap_file = 'null_scan.pcap' # tested producing 1668 results (3328 total TCP)
# null_scan.pcap Wireshark filter tcp.flags==0x000 --> 1668
null_result = null_scan('null_scan.pcap')
print('NullScanTest: ' + ('Pass' if null_result == 1668 else 'Fail'))

# NO METHOD TO TEST AS OF 12/17/2019 TODO
# pcap_file = 'combo_scan.pcap' # merged null + xmas + udp + stealth


