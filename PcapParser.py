# Pcap Parser Python
# MIT License - Copyright (c) 2019 Bernard Avenatti

import io, socket, datetime, configparser
import dpkt
from dpkt.compat import compat_ord

debug = False

# Load the configuration file
with open('config.ini') as f:
  parser_config = f.read()
  config = configparser.ConfigParser(allow_no_value=True)
  config.read_string(parser_config)
  # Set config values
  debug = config.getboolean('mode', 'debug')
  debug = False if debug is None else debug

# check file
def check_file(filename, extension):
  file_okay = 'Yes'
  if len(filename) < 6:
    file_okay =  'Your input file has an invalid name. Check input and try again.'
  elif not filename.endswith(extension):
    file_okay =  'Your file has an unknown extension! Please input ' + extension + ' files only.'
  return file_okay
    
# define scan type class
class scan_type(object):
  def __init__(self, null=False, xmas=False, udp=False, half=False, con=False):
    self.is_null_scan = null
    self.is_xmas_scan = xmas
    self.is_udp_scan = udp
    self.is_halfopen_scan = half
    self.is_connect_scan = con

# define tcp flags
class tcp_flags(object):
  def __init__(self, fin=None, syn=None, rst=None, psh=None, ack=None, urg=None, ece=None, cwr=None):
    self.fin = fin
    self.syn = syn
    self.rst = rst
    self.psh = psh
    self.ack = ack
    self.urg = urg
    self.ece = ece
    self.cwr = cwr

class ip_count(object):
  def __init__(self,ip,cnt=0):
    self.ip = ip
    self.count = cnt

# define generic packet class
class generic_packet(object): 
  def __init__(self, packet_type=None, time=None, src_mac=None, src=None, src_port=None, dst_mac=None, dst=None, 
    dst_port=None, seq=None, ack=None, flags=None, options=None, data=None):
    self.packet_type = packet_type
    self.timestamp = time
    self.scan_categories = scan_type()
    self.source_mac = src_mac
    self.source_ip = src
    self.source_port = src_port
    self.destination_mac = dst_mac
    self.destination_ip = dst
    self.destination_port = dst_port
    self.sequence = seq
    self.acknowledge = ack
    self.flags = flags # tcp_flags(flags)
    self.options = options
    self.data = data

# define connect scan class
class tcp_conversation(object):
  def __init__(self, type=None, src_ip=None, dst_ip=None, dst_port=None, src_syn=None, src_syn_time=None, dst_synack=None, dst_synack_time=None, src_ack=None, src_ack_time=None, src_rst=None, src_rst_time=None, dst_rst=None, dst_rst_time=None):
    self.type = scan_type
    self.source_ip = src_ip
    self.destination_ip = dst_ip
    self.destination_port = dst_port
    self.source_syn = src_syn
    self.source_syn_time = src_syn_time
    self.destination_synack = dst_synack
    self.destination_synack_time = dst_synack_time
    self.source_ack = src_ack
    self.source_ack_time = src_ack_time
    self.source_rst = src_rst
    self.source_rst_time = src_rst_time
    self.destination_rst = dst_rst
    self.destination_rst = dst_rst_time

# define scan class
class scan(object):
  def __init__(self, scan=False, desc=None, r=None, o=None, s=None, f=None ):
    self.scanfound = scan
    self.description = desc
    self.refused = r
    self.open = o
    self.stealth_connect = s
    self.full_connect = f
    self.results = dict()

# convert a MAC address to a readable/printable string
def mac_addr(address):
    return ':'.join('%02x' % compat_ord(b) for b in address)

# convert inet object to a string
def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# convert protocol number to friendly name
def protocol_num_to_name(protocol):
  switcher={
                6:'TCP',
                17:'UDP'
             }
  return switcher.get(protocol,"Unknown")

# format tcp flags to be human readable from dpkt tcp packets
def format_tcp_flags(dpkt_tcp):
  fin = ( dpkt_tcp.flags & dpkt.tcp.TH_FIN ) != 0
  syn = ( dpkt_tcp.flags & dpkt.tcp.TH_SYN ) != 0
  rst = ( dpkt_tcp.flags & dpkt.tcp.TH_RST ) != 0
  psh = ( dpkt_tcp.flags & dpkt.tcp.TH_PUSH) != 0
  ack = ( dpkt_tcp.flags & dpkt.tcp.TH_ACK ) != 0
  urg = ( dpkt_tcp.flags & dpkt.tcp.TH_URG ) != 0
  ece = ( dpkt_tcp.flags & dpkt.tcp.TH_ECE ) != 0
  cwr = ( dpkt_tcp.flags & dpkt.tcp.TH_CWR ) != 0
  return tcp_flags(fin, syn, rst, psh, ack, urg, ece, cwr)

# parse out information about each packet in a pcap
def get_packets(pcap, packet_dictionary):
    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:
      # get timestamp
      t = str(datetime.datetime.utcfromtimestamp(timestamp))
      # unpack the ethernet frame 
      eth = dpkt.ethernet.Ethernet(buf)
      # make sure the Ethernet data contains an IP packet
      if not isinstance(eth.data, dpkt.ip.IP):
        continue
      ip = eth.data
      # make sure inner packet is TCP/UDP before construction
      proto = protocol_num_to_name(ip.p)
      # create a generic packet if TCP/UDP...for now skip others
      if proto == 'TCP':
        tcp = ip.data
        flags = format_tcp_flags(tcp)
        p = generic_packet(protocol_num_to_name(ip.p), t, mac_addr(eth.src), inet_to_str(ip.src), tcp.sport, 
          mac_addr(eth.dst),inet_to_str(ip.dst), tcp.dport, tcp.seq, tcp.ack, flags, tcp.opts, tcp.data)
      elif proto == 'UDP':
        udp = ip.data
        p = generic_packet(protocol_num_to_name(ip.p), t, mac_addr(eth.src), inet_to_str(ip.src), udp.sport, mac_addr(eth.dst), inet_to_str(ip.dst), udp.dport, '', '', '', '', udp.data)
        # print(str(protocol_num_to_name(ip.p)) + ' ' +  str(inet_to_str(ip.src)) + ' ' + str(udp.sport) + ' ' + str(inet_to_str(ip.dst)) + ' ' + str(udp.dport) + ' ' + str(udp.data))
      else:
        # not TCP/UDP skip
        continue
      packet_dictionary[t] = p

# determine if a connect/stealth scan takes place
def tcp_conversation_exist(packets):
  s = scan(False, None, 0, 0, 0, 0)
  # 1. grab all TCP syn
  for key, value in packets.items():
    # add tcp packets with syn that are not already entered
    if ( value.packet_type == 'TCP'
        and value.source_ip 
        and value.destination_ip 
        and value.destination_port 
        and value.flags.syn
        and value.flags.ack == False
        and value.flags.rst == False
        and value.flags.fin == False):
      s.results[str(value.source_ip) + '|'+ str(value.destination_ip) + '|' + str(value.destination_port)] = tcp_conversation(None,value.source_ip, value.destination_ip, value.destination_port, True, value.timestamp, None, None, None, None, None, None)
  # 2. iterate over all TCP syn looking for matching syn/ack
  for skey, svalue in s.results.items():
    for key, value in packets.items():
      if (value.packet_type == 'TCP'
        and  str(svalue.source_ip) + '|' + str(svalue.destination_ip) + '|' + str(svalue.destination_port) in s.results
        and value.destination_ip == svalue.source_ip
        and value.source_ip == svalue.destination_ip
        and value.source_port == svalue.destination_port
        and svalue.destination_synack is None
        and svalue.destination_rst is None):
        if (value.flags.syn and value.flags.ack):
        # and datetime.datetime(value.timestamp) > datetime.datetime(svalue.source_syn_time)
        # update scan result with cooresponding syn/ack
          s.results[str(svalue.source_ip) + '|' + 
                    str(svalue.destination_ip) + '|' + 
                    str(svalue.destination_port)].destination_synack = True
          s.results[str(svalue.source_ip) + '|'+ 
                    str(svalue.destination_ip) + '|' + 
                    str(svalue.destination_port)].destination_synack_time = value.timestamp
          s.open = s.open + 1
          # print('open!')
        elif (value.flags.rst and value.flags.ack):
          # and datetime.datetime(value.timestamp) > datetime.datetime(svalue.source_syn_time)
          # update scan result with cooresponding rst/ack
          s.results[str(svalue.source_ip) + '|' + 
                    str(svalue.destination_ip) + '|' + 
                    str(svalue.destination_port)].destination_rst = True
          s.results[str(svalue.source_ip) + '|'+ 
                    str(svalue.destination_ip) + '|' + 
                    str(svalue.destination_port)].destination_rst_time = value.timestamp
          s.refused = s.refused + 1
          # print('closed!')
  # 3. iterate over all TCP syn looking for matching ack or rst
  for skey, svalue in s.results.items():
    for key, value in packets.items():
      if ( value.packet_type == 'TCP'
        and value.source_ip == svalue.source_ip
        and value.destination_ip == svalue.destination_ip
        and value.destination_port == svalue.destination_port
        and svalue.source_ack is None 
        and svalue.destination_synack is not None):
        if (value.flags.syn == False and value.flags.ack and value.flags.rst == False and value.flags.fin == False):
          # and value.timestamp > svalue.source_synack_time
          # update scan result with cooresponding ack
          s.results[str(svalue.source_ip) + '|' + 
                    str(svalue.destination_ip) + '|' + 
                    str(svalue.destination_port)].source_ack = True
          s.results[str(svalue.source_ip) + '|'+ 
                    str(svalue.destination_ip) + '|' + 
                    str(svalue.destination_port)].source_ack_time = value.timestamp
          s.results[str(svalue.source_ip) + '|'+ 
                    str(svalue.destination_ip) + '|' + 
                    str(svalue.destination_port)].type = 'connect'
          s.full_connect = s.full_connect + 1
          # print('connect!')
        elif value.flags.rst:
          # and value.timestamp > svalue.source_synack_time
          # update scan result with cooresponding rst
          s.results[str(svalue.source_ip) + '|' + 
                    str(svalue.destination_ip) + '|' + 
                    str(svalue.destination_port)].source_rst = True
          s.results[str(svalue.source_ip) + '|'+ 
                    str(svalue.destination_ip) + '|' + 
                    str(svalue.destination_port)].source_rst_time = value.timestamp
          s.results[str(svalue.source_ip) + '|'+ 
                    str(svalue.destination_ip) + '|' + 
                    str(svalue.destination_port)].type = 'stealth'
          s.stealth_connect = s.stealth_connect + 1
          # print('stealth!')
  # 5. checking...
  # print('stealth: ' + str(s.stealth_connect))
  # print('connect: ' + str(s.full_connect))
  # print('refused: ' + str(s.refused))
  # print('open: ' + str(s.open))
  return s

# count udp ports scanned
def udp_scan(pcap_file):
  packets = dict()
  unique_udp_ports = 0 # only count UDP packets where no payload 
  with open(pcap_file, 'rb') as f:
    pcap = dpkt.pcap.Reader(f)
    get_packets(pcap, packets)
    for key in packets:
      packet = packets[key]
      if packet.packet_type == 'UDP' and len(packet.data) == 0:
        packets[key].scan_categories.is_udp_scan = True
        unique_udp_ports = unique_udp_ports + 1
  return 0 if unique_udp_ports is None else unique_udp_ports

# count null ports scanned
def null_scan(pcap_file):
  if check_file(pcap_file,'py') == 'yes':
    packets = dict()
    unique_null_ports = 0
    with open(pcap_file, 'rb') as f:
      pcap = dpkt.pcap.Reader(f)
      get_packets(pcap, packets) 
      for key in packets:
        packet = packets[key]
        if packet.packet_type == 'TCP':
          # is it TCP > null scan ?
          packets[key].scan_categories.is_null_scan = (True if ( packet.flags.fin == False and packet.flags.urg == False and packet.flags.psh == False and packet.flags.syn == False and packet.flags.rst == False and packet.flags.ack == False and packet.flags.ece == False and packet.flags.cwr == False ) else False)
          unique_null_ports = unique_null_ports + (1 if packets[key].scan_categories.is_null_scan else 0)
  return 0 if unique_null_ports is None else unique_null_ports

# count xmas ports scanned
def xmas_scan(pcap_file):
  if check_file(pcap_file,'py') == 'yes':
    packets = dict()
    unique_xmas_ports = 0
    with open(pcap_file, 'rb') as f:
      pcap = dpkt.pcap.Reader(f)
      get_packets(pcap, packets) 
      for key in packets:
        packet = packets[key]
        if packet.packet_type == 'TCP':
          # is it TCP > XMAS scan ?
          packets[key].scan_categories.is_xmas_scan = True if packet.flags.fin and packet.flags.urg and packet.flags.psh else False
          unique_xmas_ports = unique_xmas_ports + (1 if packets[key].scan_categories.is_xmas_scan else 0)
  return 0 if unique_xmas_ports is None else unique_xmas_ports

# count stealth/halfopen ports scanned
def halfopen_scan(pcap_file):
  if check_file(pcap_file,'py') == 'yes':
    packets = dict()
    unique_halfopen_ports = 0
    with open(pcap_file, 'rb') as f:
      pcap = dpkt.pcap.Reader(f)
      get_packets(pcap, packets)
      tcp_scan = tcp_conversation_exist(packets)
      unique_halfopen_ports = (tcp_scan.stealth_connect + tcp_scan.refused if tcp_scan.full_connect < tcp_scan.stealth_connect else 0)
  return 0 if unique_halfopen_ports is None else unique_halfopen_ports

# count connect ports scanned
def connect_scan(pcap_file):
  if check_file(pcap_file,'py') == 'yes':
    packets = dict()
    unique_connect_ports = 0
    with open(pcap_file, 'rb') as f:
      pcap = dpkt.pcap.Reader(f)
      get_packets(pcap, packets)
      tcp_scan = tcp_conversation_exist(packets)
      unique_connect_ports = (tcp_scan.full_connect + tcp_scan.refused if tcp_scan.full_connect > tcp_scan.stealth_connect else 0)
  return 0 if unique_connect_ports is None else unique_connect_ports
