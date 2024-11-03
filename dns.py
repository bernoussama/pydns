"""
Dns server

RFC 1035: https://datatracker.ietf.org/doc/html/rfc1035
"""

import glob
import time
from rich import print
import yaml
import socket
import struct
from dataclasses import dataclass


def loadZones():
    """
    Load zone files
    """
    zones = {}
    for zonefile in glob.glob("zones/*.yml"):
        with open(zonefile, "r") as f:
            zone = yaml.safe_load(f)
            zones[zone["origin"]] = zone
    for zone in zones:
        zones[zone]["soa"]["serial"] = int(time.time())
    return zones


zonedata = loadZones()

qtypes = {
    "a": 1,
    "ns": 2,
    "md": 3,
    "mf": 4,
    "cname": 5,
    "soa": 6,
    "mb": 7,
    "mg": 8,
    "mr": 9,
    "null": 10,
    "wks": 11,
    "ptr": 12,
    "hinfo": 13,
    "minfo": 14,
    "mx": 15,
    "txt": 16,
}


@dataclass
class DNSHeader:
    id: int
    qr: int
    opcode: int
    aa: int
    tc: int
    rd: int
    ra: int
    z: int
    rcode: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int


def decodeHeader(data: bytes) -> DNSHeader:
    """
    Decodes a DNS header from a datagram.
    """

    # Header format: 6 16bits shorts in network byte order
    header_format = "!6H"
    id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
        header_format, data[:12]
    )
    return DNSHeader(
        id=id,
        qr=flags >> 15,
        opcode=flags >> 11 & 0xF,
        aa=flags >> 10 & 0x1,
        tc=flags >> 9 & 0x1,
        rd=flags >> 8 & 0x1,
        ra=flags >> 7 & 0x1,
        z=flags >> 4 & 0x7,
        rcode=flags & 0xF,
        qdcount=qdcount,
        ancount=ancount,
        nscount=nscount,
        arcount=arcount,
    )


@dataclass
class DNSQuestion:
    domainName: str
    qtype: int
    qclass: int


def decodeQuestion(data: bytes):
    """
    Decodes DNS question section
    """
    dn = ""
    offset = 12
    while data[offset] != 0:
        byte = data[offset]
        len = byte
        name = data[offset + 1 : offset + len + 1]
        dn += name.decode("utf-8") + "."
        offset += len + 1
    end = offset
    qformat = "!2H"
    qtype, qclass = struct.unpack(qformat, data[offset + 1 : offset + 5])
    return (
        DNSQuestion(domainName=dn, qtype=qtype, qclass=qclass),
        offset + 5,
        (12, end),
    )


@dataclass
class DNSAnswer:
    name: bytes
    type: int
    class_: int
    ttl: int
    rdlength: int
    rdata: str


def encodeAnswer(answer: DNSAnswer):
    """
    Encodes a DNS answer
    """
    # name = answer.name + b"\x00"
    name = answer.name
    rdata_encoded = answer.rdata.encode("ascii")
    if answer.type == 1:
        rdata_encoded = b"".join(
            [bytes([int(part)]) for part in answer.rdata.split(".")]
        )

    rdlength = len(rdata_encoded)
    print("rdlength: ", rdlength)
    print("rdata_encoded: ", rdata_encoded)

    answer_format = "!HHIH"
    res = struct.pack(
        answer_format,
        answer.type,
        answer.class_,
        answer.ttl,
        rdlength,
        # b"".join([answer.rdata.encode("utf-8"), b"\x00"]),
    )
    res = name + res + rdata_encoded
    print(res)
    return res


def encodeHeader(header: DNSHeader):
    """
    Encodes a DNS header
    """
    header.qr = 1
    flags = (
        (header.qr << 15)
        | (header.opcode << 11)
        | (header.aa << 10)
        | (header.tc << 9)
        | (header.rd << 8)
        | (header.ra << 7)
        | (header.z << 4)
        | (header.rcode)
    )
    header.arcount = 0
    header_format = "!6H"
    res = struct.pack(
        header_format,
        header.id,
        flags,
        header.qdcount,
        header.ancount,
        header.nscount,
        header.arcount,
    )
    return res


def getZone(domainName: str):
    global zonedata
    return zonedata[domainName]


def getRecords(question: DNSQuestion):
    if question.qtype == 1:
        qt = "a"
    zone = getZone(question.domainName)
    return (zone[qt], qt, question.domainName)


def buildResponse(
    header: DNSHeader, question: DNSQuestion, answer: DNSAnswer, data: bytes, qoffset
):
    """
    Builds a DNS response
    """
    res = b""
    zone, qt, dn = getRecords(question)
    header.ancount = len(zone)
    head = encodeHeader(header)
    res += head
    q = data[12:qoffset]
    res += q
    for record in zone or []:
        # if record.name == "@"

        # compressed name format
        name = (3 << 14) | 12
        name = struct.pack("!H", name)
        ans = DNSAnswer(
            name=name,
            type=qtypes[qt],
            class_=answer.class_,
            ttl=record["ttl"],
            rdlength=len(record["value"]),
            rdata=record["value"],
        )
        res += encodeAnswer(ans)
    return res


if __name__ == "__main__":

    port = 53153
    ip = "127.0.0.1"
    getRecords(DNSQuestion(domainName="bernoussama.com.", qtype=1, qclass=1))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))

    while True:
        try:
            data, addr = sock.recvfrom(512)
            print(addr)
            header = decodeHeader(data)
            print(header)
            q, qoffset, (start, end) = decodeQuestion(data)
            print(q)
            resAddress = "255.255.255.255"
            answer = DNSAnswer(
                name=data[start:end],
                type=1,
                class_=1,
                ttl=60,
                rdlength=len(resAddress),
                rdata=resAddress,
            )
            print(answer)
            res = buildResponse(header, q, answer, data, qoffset)
            sent = sock.sendto(res, addr)
            print(sent)
        except KeyboardInterrupt:
            sock.close()
            exit(0)
