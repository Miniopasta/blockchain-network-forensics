import hashlib
import os
from datetime import datetime
from scapy.all import rdpcap

class Block:
    def __init__(self,index,timestamp,evidence_file,packet_count,evidence_hash,previous_hash):
        self.index=index
        self.timestamp=timestamp
        self.evidence_file=evidence_file
        self.packet_count=packet_count
        self.evidence_hash=evidence_hash
        self.previous_hash=previous_hash
        self.block_hash=self.calculate_hash()

    def calculate_hash(self):
        data = (
            str(self.index)
            + self.timestamp
            + self.evidence_file
            + str(self.packet_count)
            + self.evidence_hash
            + self.previous_hash
        )
        return hashlib.sha256(data.encode()).hexdigest()


def file_sha256(filename):
    sha256 = hashlib.sha256()

    with open(filename,"rb") as f:
        while True:
            data = f.read(4096)

            if not data:
                break

            sha256.update(data)

    return sha256.hexdigest()


def validate_chain(chain):

    for i in range(1,len(chain)):

        current = chain[i]
        previous = chain[i-1]

        if current.previous_hash != previous.block_hash:
            return False

        if current.calculate_hash() != current.block_hash:
            return False

    return True


pcap_files = [
    "../evidence/PCAP01_23040700076.pcap",
    "../evidence/PCAP02_23040700076.pcap",
    "../evidence/PCAP03_23040700076.pcap",
    "../evidence/PCAP04_23040700076.pcap",
    "../evidence/PCAP05_23040700076.pcap"
]

blockchain=[]

genesis = Block(
    0,
    str(datetime.now()),
    "GENESIS",
    0,
    "0",
    "0"
)

blockchain.append(genesis)

for i,file in enumerate(pcap_files,start=1):

    packets = rdpcap(file)

    packet_count = len(packets)

    file_hash = file_sha256(file)

    file_size = os.path.getsize(file)

    print("="*60)
    print("Nama File :",os.path.basename(file))
    print("Jumlah Paket :",packet_count)
    print("Ukuran File :",file_size,"bytes")
    print("SHA256 :",file_hash)

    block = Block(
        i,
        str(datetime.now()),
        os.path.basename(file),
        packet_count,
        file_hash,
        blockchain[-1].block_hash
    )

    blockchain.append(block)

print("\n===== BLOCKCHAIN =====")

for block in blockchain:

    print("\nIndex :",block.index)
    print("Evidence :",block.evidence_file)
    print("Packet :",block.packet_count)
    print("Previous Hash :",block.previous_hash)
    print("Block Hash :",block.block_hash)

print("\n===== VALIDATION =====")

if validate_chain(blockchain):
    print("Blockchain Validation : VALID")
else:
    print("Blockchain Validation : INVALID")