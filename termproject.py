#!/usr/bin/env python3
from kamene.all import rdpcap
from collections import Counter
from packet import Packet
import sqlite3
import os

def logDarkData(src_ipdr,src_port,dst_ipdr,dst_port):
    #print(src_ipdr.replace(".","-"))
    #print(src_port)
    #print(dst_ipdr.replace(".","-"))
    #print(dst_port)
    sqlcmd = 'insert into data (srcip, srcport, dstip, dstport) values ("' +src_ipdr+ '","' +src_port+ '","' +dst_ipdr+ '","'+dst_port+'")'
        
    db = sqlite3.connect('dark_data.db')
    cn = db.cursor()
    try:
        cn.execute('create table data (srcip text, srcport text, dstip text, dstport text)')
    except sqlite3.OperationalError:
        cn.execute(sqlcmd)
        
    db.commit()
    cn.close()
    return
        
p = rdpcap('set0.pcap')

#for i in range(0,20):
    #test = p[i].summary()
    #print(test)

src_iplist=[]
dst_iplist=[]

src_portlist=[]
dst_portlist=[]

packetlist = []

for i in range(0,len(p)):
    full_summary = p[i].summary()
    mystring = full_summary.split(" ")
    src_ip_and_port = mystring[5].split(":", 1)
    dst_ip_and_port = mystring[7].split(":", 1)
    try:
        src_ipdr = src_ip_and_port[0]
        src_iplist.append(src_ipdr)
        
        src_port = src_ip_and_port[1]
        src_portlist.append(src_port)
        
        dst_ipdr = dst_ip_and_port[0]
        dst_iplist.append(dst_ipdr)
        
        dst_port = dst_ip_and_port[1]
        dst_portlist.append(dst_port)

        pkt = Packet(src_ipdr,src_port,dst_ipdr,dst_port)
        packetlist.append(pkt)
        logDarkData(src_ipdr,src_port,dst_ipdr,dst_port)
    except IndexError:
        logDarkData(src_ipdr,src_port,dst_ipdr,dst_port)
        continue
    
print(Counter(src_iplist))

#Horizontal Scan- Scan against a group of IPs for a single port
#Vertical   Scan- Single IP scanned for multiple ports
#Strobe(Box)Scan- Horizontal and Vertical combined


#Horizontal Scan SRC
print("Horizontal Scan")
for i in range(0,len(packetlist)):
    if packetlist[i].SRC_PORT() == "http":
        packetlist[i].print_IP_ONLY()

#Vertical Scan SRC
print("Vertical Scan")
for i in range(0,len(packetlist)):
    if packetlist[i].SRC_IP() == "178.33.33.74":
        packetlist[i].print_PORT_ONLY()

#Strobe Scan SRC
print("Strobe Scan")
for i in range(0,len(packetlist)):
    if packetlist[i].SRC_IP() == "37.139.6.111" and packetlist[i].SRC_PORT() == "http":
        packetlist[i].printallInfo()
 
#Horizontal Scan DST
print("Horizontal Scan")
for i in range(0,len(packetlist)):
    if packetlist[i].DST_PORT() == "http":
        packetlist[i].print_IP_ONLY()

#Vertical Scan DST
print("Vertical Scan")
for i in range(0,len(packetlist)):
    if packetlist[i].DST_IP() == "178.33.33.74":
        packetlist[i].print_PORT_ONLY()

#Strobe Scan DST
print("Strobe Scan")
for i in range(0,len(packetlist)):
    if packetlist[i].DST_IP() == "37.139.6.111" and packetlist[i].DST_PORT() == "http":
        packetlist[i].printallInfo()
