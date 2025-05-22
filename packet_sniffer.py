from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
  try:
    if not packet.haslayer(IP):
        return
   
        
    ip_layer = packet[IP]
    protocol = ip_layer.proto
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

        
    protocol_names = {
        1:"ICMP",
        6: "TCP",
        17:"UDP"
    }
    protocol_num = ip_layer.proto
    protocol_name = protocol_names.get(ip_layer.proto, "Unkown Protocol dumbass")


    details = {}
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        details.update({"src_port": tcp.sport, "dst_port": tcp.dport})
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        details.update({"src_port": udp.sport, "dst_port": udp.dport})
    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        details.update({"type": icmp.type, "code": icmp.code})

    print(f"Protocol: {protocol_name}")
    print(f"Source IP: {src_ip}:{details.get('src_port' , '')}")
    print(f"Destination IP: {dst_ip}:{details.get('dst_port', '')}")
    if "type" in details:
        print(f"ICMP Type/Code: {details['type']}/{details['code']}")

    print("-" * 50)
   
  except Exception as e:

    print(f"Error processing packet: {e}")

def main():
    
    sniff(
        prn=packet_callback, 
        filter="ip",
        store=0,
        iface=None
        )

if __name__ == "__main__":
    main()  