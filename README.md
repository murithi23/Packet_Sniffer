# Packet Sniffer
 Its a lightweight  packet sniffer for capturing and anlayzing network trafic in real-time 
 Built with python and Scapy

 # Features
It captures live network traffic ie. TCP ,UDP ICMP . Filters packet by protocol  source/destination  ip or port
Displays packet headers and payloads  in human-readable format and can save the captured packets to a '.pcap' file fo later analysis
supported across all platforms (Linux, windows Macos)

# installation
you can install it by cloning the repository
  bash 
     git clone https://github.com/murithi23/Packet_Sniffer.git
     cd Packet_Sniffer


# install dependecies
 pip install  requirements.txt


  USAGE

  Basic packet capture
 

  In the directory you've installed the program run the following for a basic capture
  
   python3 packet_sniifer.py --interface eth0 --count 100
      
    -- interface : ntework interface to sniff (eg eth0, wlan0)
    --count : number of packets you want to capture ideally the deafualt is   infinite

  Filter by  Protocol/IP/PORT
   bash
    python3 packet_sniffer.py --filter "tcp and host 192.268.1.1 and port 80"

   Save to PCAP File 
  bash 
   python3 packet_sniffer.py --output capture.pcap



Dependecies
 Scapy (pip install scapy or  apt install python3-scapy)



!!!!!DISCLAIMER !!!!!
 The tool is for educational purposes research and ethical purposes 
 Unauthorized network monitoring may violate privacy laws use responsibles and only on networks you own or have permissions




DEMO
 packet sniffer demo 
 the output should look something of the sort


![Screenshot at 2025-05-22 17-54-19](https://github.com/user-attachments/assets/4de12588-00fd-4b0d-b151-adabecd99d5f)



 
