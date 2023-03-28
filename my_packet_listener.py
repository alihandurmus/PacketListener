import scapy.all as scapy
from scapy_http import http
def listen_packets(interface):
    scapy.sniff(iface=interface,store=False,prn=analyze_packets)
    #prn = callback function
def analyze_packets(packet):
    #packet.show()
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            print(packet[scapy.Raw].load)
            # Burada filtreleme işlemini yaptık hangi katmanda hangi paketi arıyorsan onu filtreleyebilirsin.
listen_packets("eth0")