#!/usr/bin/python3

from scapy.all import *
import pcapy
import argparse
import re
import base64

incident_count = 0
user = ' '

def packetcallback(packet):
  try:
    # The following is an example of Scapy detecting HTTP traffic
    # Please remove this case in your actual lab implementation so it doesn't pollute the alerts
    # if packet[TCP].dport == 80:
    #   print("HTTP (web) traffic detected!")

    global incident_count

    # scan TCP flag headers for 'FPU' signs of XMAS scan, print alert if found
    if packet[TCP].flags.F & packet[TCP].flags.U & packet[TCP].flags.P:
      incident_count += 1
      print("ALERT #" + str(incident_count) + ": Xmas scan is detected from " + str(packet[IP].src) + " (" + str(packet[TCP].dport) + "!)")
    # scan TCP flag headers for signs of NULL scan, print alert if found
    elif packet[TCP].flags == 0:
      incident_count += 1
      print("ALERT #" + str(incident_count) + ": NULL scan is detected from #" + str(packet[IP].src) + " (" + str(packet[TCP].dport) + "!)")
    # scan TCP flag headers for 'F' signs of FIN scan, print alert if found
    elif packet[TCP].flags.F:
      if packet[TCP].flags.A == 0:
        incident_count += 1 
        print("ALERT #" + str(incident_count) + ": FIN scan is detected from " + str(packet[IP].src) + " (" + str(packet[TCP].dport) + "!)")

    try:

      p = packet[TCP].load.decode("ascii")

      # check for Nikto scan, print alert if found
      if 'Nikto' in p:
        incident_count += 1
        print("ALERT #" + str(incident_count) + ": Nikto scan is detected from " + str(packet[IP].src) + " (" + str(packet[TCP].dport) + "!)")

      # determine protocol according to ports and sniff for credentials

      # SMB protocol
      # check for activity
      if packet[TCP].sport == 139 or packet[TCP].sport == 445 or packet[TCP].dport == 139 or packet[TCP].dport == 445:
        proto = "SMB"
        incident_count += 1
        print("ALERT #" + str(incident_count) + ": SMB scan detected from " + str(packet[IP].src) + " (" + str(packet[TCP].dport) + "!)")

      # FTP protocol
      if packet.haslayer(TCP) and packet[TCP].dport == 21:
        global user
        proto = "FTP"

        # find user credentials
        if "USER" in p:
          user = str(p)
          user = user.lstrip("USER ")
              
        # find password credentials
        if "PASS" in p:
          password = str(p)
          password = password.lstrip("PASS ")
          incident_count += 1
          print("ALERT #" + str(incident_count) + " Usernames and passwords sent in-the-clear (" + proto + ") from " + str(packet[IP].src) + " {username: " + user + ", password: " + password + "}")

      # HTTP protocol
      if packet.haslayer(TCP) and packet[TCP].dport == 80:
        proto = "HTTP"
        if 'Authorization: Basic' in p: 
        # iterate through each line of the packet
          for line in p.splitlines():
          # find line with credentials
            if 'Authorization: Basic' in line:
              line2 = line.strip('Authorization: Basic')
              # decode credentials
              line2 = base64.b64decode(line2)
              #clean up string
              line2_string = str(line2)     
              line2_string = line2_string.lstrip("b'")
              line2_string = line2_string.rstrip("'")
              line2_string = line2_string.split(":")
              # incident count + 1
              incident_count += 1
              # print alert with protocol
              print("ALERT #" + str(incident_count) + " Usernames and passwords sent in-the-clear (" + proto + ") from " + str(packet[IP].src) + "{username: " + line2_string[0] + ", password: " + line2_string[1] + "}")

      # IMAP protocol
      if packet[TCP].dport == 143 or packet[TCP].dport == 993:
        proto = "IMAP"

        if "LOGIN" in p:
          imap_packet = str(p)
          imap_packet = imap_packet.lstrip("3 LOGIN ")
          imap_packet = imap_packet.split(" ")
          imap_packet[1] = imap_packet[1].lstrip('"')
          imap_packet[1] = imap_packet[1].rstrip('"')
          incident_count += 1
          # print alert with protocol
          print("ALERT #" + str(incident_count) + " Usernames and passwords sent in-the-clear (" + proto + ") from " + str(packet[IP].src) + "{username: " + imap_packet[0] + ", password: " + imap_packet[1] + "}")

    except:
      pass;

  except:
    pass;

parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except pcapy.PcapError:
    print("Sorry, error opening network interface %(interface)s. It does not exist." % {"interface" : args.interface})
  except:
    print("Sorry, can\'t read network traffic. Are you root?")