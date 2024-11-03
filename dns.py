"""
DNS Server Implementation following RFC 1035

This module implements a simple DNS server that handles basic DNS queries
by loading zone files and responding to A record requests.
"""

import glob
import time
from dataclasses import dataclass
import socket
import struct
import yaml
from rich import print

# DNS Record Types mapping
DNS_TYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
}


@dataclass
class DNSHeader:
    """DNS Header structure as per RFC 1035"""

    id: int
    qr: int  # Query/Response flag
    opcode: int  # Operation code
    aa: int  # Authoritative Answer
    tc: int  # Truncation flag
    rd: int  # Recursion Desired
    ra: int  # Recursion Available
    z: int  # Reserved
    rcode: int  # Response code
    qdcount: int  # Question count
    ancount: int  # Answer count
    nscount: int  # Name server count
    arcount: int  # Additional record count


@dataclass
class DNSQuestion:
    """DNS Question section structure"""

    domain_name: str
    qtype: int
    qclass: int


@dataclass
class DNSAnswer:
    """DNS Answer section structure"""

    name: bytes
    type: int
    class_: int
    ttl: int
    rdlength: int
    rdata: str


class DNSServer:
    def __init__(self, ip: str = "127.0.0.1", port: int = 53153):
        self.ip = ip
        self.port = port
        self.zones = self._load_zones()
        self.socket = None

    def _load_zones(self) -> dict:
        """
        Load DNS zone files from the zones directory
        """
        zones = {}
        try:
            for zonefile in glob.glob("zones/*.yml"):
                with open(zonefile, "r") as f:
                    zone = yaml.safe_load(f)
                    zone["soa"]["serial"] = int(time.time())
                    zones[zone["origin"]] = zone
            return zones
        except (yaml.YAMLError, IOError) as e:
            print(f"Error loading zone files: {e}")
            return {}

    def decode_header(self, data: bytes) -> DNSHeader:
        """Decode DNS header from received data"""
        try:
            header_format = "!6H"
            id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
                header_format, data[:12]
            )
            return DNSHeader(
                id=id,
                qr=flags >> 15,
                opcode=(flags >> 11) & 0xF,
                aa=(flags >> 10) & 0x1,
                tc=(flags >> 9) & 0x1,
                rd=(flags >> 8) & 0x1,
                ra=(flags >> 7) & 0x1,
                z=(flags >> 4) & 0x7,
                rcode=flags & 0xF,
                qdcount=qdcount,
                ancount=ancount,
                nscount=nscount,
                arcount=arcount,
            )
        except struct.error as e:
            print(f"Error decoding header: {e}")
            return None

    def decode_question(
        self, data: bytes
    ) -> tuple[DNSQuestion | None, int, tuple[int, int]]:
        """Decode DNS question section from received data"""
        try:
            domain_name = ""
            offset = 12  # Header length is 12 bytes

            while data[offset] != 0:
                length = data[offset]
                name_part = data[offset + 1 : offset + length + 1]
                domain_name += name_part.decode("utf-8") + "."
                offset += length + 1

            end = offset
            qtype, qclass = struct.unpack("!2H", data[offset + 1 : offset + 5])

            return (
                DNSQuestion(domain_name=domain_name, qtype=qtype, qclass=qclass),
                offset + 5,
                (12, end),
            )
        except (struct.error, IndexError) as e:
            print(f"Error decoding question: {e}")
            return None, 0, (0, 0)

    def encode_answer(self, answer: DNSAnswer) -> bytes:
        """Encode DNS answer section"""
        try:
            if answer.type == DNS_TYPES["A"]:
                rdata_encoded = b"".join(
                    [bytes([int(part)]) for part in answer.rdata.split(".")]
                )
            else:
                rdata_encoded = answer.rdata.encode("ascii")

            rdlength = len(rdata_encoded)
            answer_format = "!HHIH"

            res = struct.pack(
                answer_format,
                answer.type,
                answer.class_,
                answer.ttl,
                rdlength,
            )
            return answer.name + res + rdata_encoded
        except (struct.error, ValueError) as e:
            print(f"Error encoding answer: {e}")
            return b""

    def encode_header(self, header: DNSHeader) -> bytes:
        """Encode DNS header"""
        try:
            header.qr = 1  # This is a response
            flags = (
                (header.qr << 15)
                | (header.opcode << 11)
                | (header.aa << 10)
                | (header.tc << 9)
                | (header.rd << 8)
                | (header.ra << 7)
                | (header.z << 4)
                | header.rcode
            )
            header.arcount = 0

            return struct.pack(
                "!6H",
                header.id,
                flags,
                header.qdcount,
                header.ancount,
                header.nscount,
                header.arcount,
            )
        except struct.error as e:
            print(f"Error encoding header: {e}")
            return b""

    def get_records(self, question: DNSQuestion) -> tuple[list, str, str]:
        """Get DNS records for the requested domain"""
        try:
            record_type = "a" if question.qtype == DNS_TYPES["A"] else "unknown"
            zone = self.zones.get(question.domain_name, {})
            return (zone.get(record_type, []), record_type, question.domain_name)
        except Exception as e:
            print(f"Error getting records: {e}")
            return ([], "unknown", "")

    def build_response(
        self,
        header: DNSHeader,
        question: DNSQuestion,
        answer: DNSAnswer,
        data: bytes,
        qoffset: int,
    ) -> bytes:
        """Build DNS response packet"""
        try:
            zone, record_type, domain_name = self.get_records(question)
            if not zone:
                return b""

            header.ancount = len(zone)
            response = self.encode_header(header)
            response += data[12:qoffset]  # Add question section

            for record in zone:
                # Use DNS name compression (RFC 1035 section 4.1.4)
                name = (3 << 14) | 12
                name = struct.pack("!H", name)

                ans = DNSAnswer(
                    name=name,
                    type=DNS_TYPES.get(record_type.upper(), 0),
                    class_=answer.class_,
                    ttl=record["ttl"],
                    rdlength=len(record["value"]),
                    rdata=record["value"],
                )
                response += self.encode_answer(ans)

            return response
        except Exception as e:
            print(f"Error building response: {e}")
            return b""

    def run(self):
        """Start the DNS server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind((self.ip, self.port))
            print(f"DNS Server running on {self.ip}:{self.port}")

            while True:
                try:
                    data, addr = self.socket.recvfrom(
                        512
                    )  # DNS messages are limited to 512 bytes
                    print(f"Received request from {addr}")

                    header = self.decode_header(data)
                    if not header:
                        continue

                    question, qoffset, (start, end) = self.decode_question(data)
                    if not question:
                        continue

                    # Create default answer
                    answer = DNSAnswer(
                        name=data[start:end],
                        type=DNS_TYPES["A"],
                        class_=1,  # IN class
                        ttl=60,
                        rdlength=4,  # IPv4 address length
                        rdata="0.0.0.0",
                    )

                    response = self.build_response(
                        header, question, answer, data, qoffset
                    )
                    if response:
                        self.socket.sendto(response, addr)

                except Exception as e:
                    print(f"Error processing request: {e}")
                    continue

        except Exception as e:
            print(f"Server error: {e}")
        finally:
            if self.socket:
                self.socket.close()


def main():
    server = DNSServer()
    try:
        server.run()
    except KeyboardInterrupt:
        print("\nShutting down DNS server...")
        if server.socket:
            server.socket.close()


if __name__ == "__main__":
    main()
