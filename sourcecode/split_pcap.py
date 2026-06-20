from scapy.all import rdpcap, wrpcap

pcap_file = "../evidence/traffic.pcapng"

packets = rdpcap(pcap_file)

targets = [30, 50, 70, 90, 100]

for i, count in enumerate(targets, start=1):
    output_file = f"../evidence/PCAP0{i}_23040700076.pcapng"
    wrpcap(output_file, packets[:count])
    print(f"{output_file} berhasil dibuat ({count} paket)")