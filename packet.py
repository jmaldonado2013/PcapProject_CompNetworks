#!/usr/bin/env python3

class Packet:
    def __init__(self,src_ip,src_port,dst_ip,dst_port):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port

    def SRC_IP(self):
        return self.src_ip

    def DST_IP(self):
        return self.dst_ip

    def SRC_PORT(self):
        return self.src_port

    def DST_PORT(self):
        return self.dst_port

    def printallInfo(self):
        print("SRC IP: "+ self.SRC_IP()+" SRC PORT: " + self.SRC_PORT())
        print("DST IP: "+ self.DST_IP()+" DST PORT: " + self.DST_PORT())
        print()

    def print_IP_ONLY(self):
        print("SRC IP: "+ self.SRC_IP()+" DST IP: " + self.DST_IP())

    def print_PORT_ONLY(self):
        print("SRC PORT: "+ self.SRC_PORT()+" DST PORT: " + self.DST_PORT())
