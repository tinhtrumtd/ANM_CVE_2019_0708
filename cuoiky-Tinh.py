from asyncio import protocols
import csv
import logging
from re import I
import sys
import time
import warnings 
import pyshark
from scapy.utils import RawPcapReader
import os
#cap = pyshark.FileCapture('C:\\Users\\azhel\\Downloads\\capture.pcap')
#Bai1() Nhập đường dẫn đến tshark sau đó nhập đường dẫn đến file .pcap
#os.system("D:\\Users\\Program\\Wireshark\\tshark.exe -r C:\\Users\\azhel\\Desktop\\hehehe.pcap -T fields -e _ws.col.No. -e _ws.col.Time -e ip.src -e ip.dst -e _ws.col.Protocol -e frame.len -e _ws.col.Info -e tcp.payload -E separator=, -E occurrence=f > traffic.csv")

#Bai2 bắt gói trên card Ethernet và xuất ra file outBai2.pcap

def capture_on_interface(interface, name, timeout):
    """
    :param interface: The name of the interface on which to capture traffic
    :param name: The name of the capture file
    :param timeout: A limit in seconds specifying how long to capture traffic
    """

    if timeout < 15:
        logging.error("Timeout must be over 15 seconds.")
        return
    if not sys.warnoptions:
        warnings.simplefilter("ignore")
    start = time.time()

    capture = pyshark.LiveCapture(interface=interface, output_file=os.path.join(name))
    pcap_size = 0
    for i, packet in enumerate(capture.sniff_continuously()):
        # progress.update(i)
        if os.path.getsize(os.path.join(name)) != pcap_size:
            pcap_size = os.path.getsize(os.path.join(name))
        if not isinstance(packet, pyshark.packet.packet.Packet):
            continue
        if time.time() - start > timeout:
            break

    capture.clear()
    capture.close()
    return pcap_size
capture_on_interface("VMware Network Adapter VMnet8", 'test.pcapng',150)
os.system('C:\\"Program Files"\\Wireshark\\tshark.exe -r test.pcapng -T fields -e _ws.col.No. -e _ws.col.Time -e ip.src -e ip.dst -e _ws.col.Protocol -e frame.len -e _ws.col.Info -E separator=, -E occurrence=f > traffic.csv')
# def for_signature():
#     signature = ['Unknown TPDU type (0xb)Continuation', 'Unknown TPDU type (0x9)Continuation', 'Unknown TPDU type (0x3)Continuation', 'Unknown TPDU type (0xa)Continuation','Unknown TPDU type (0x0)Continuation']
#         for i in signature:           
def main_attack_detect():
    signature = ['Unknown TPDU type (0xb)Continuation', 'Unknown TPDU type (0x9)Continuation', 'Unknown TPDU type (0x3)Continuation', 'Unknown TPDU type (0xa)Continuation','Unknown TPDU type (0x0)Continuation','Application Data']
    for i in signature:
        with open("traffic.csv") as csv_file:
            reader = csv.reader(csv_file, delimiter=',')
            for row in reader:
                if i == row[6]:
                    print('Phat hien tan cong CVE-2019-0708 ')
                # else:
                #     print('khong phat hien')
main_attack_detect()