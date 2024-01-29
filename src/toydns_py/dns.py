"""A simple DNS resolver inspired by "Implement DNS in a weekend" by Julia Evans."""

from __future__ import annotations

import random
import socket
import struct
from dataclasses import astuple, dataclass
from io import BytesIO

TYPE_A = 1
TYPE_NS = 2
TYPE_TXT = 16
CLASS_IN = 1


@dataclass
class DNSHeader:
    """
    Represents a DNS header.

    Attributes
    ----------
    id (int): An identifier assigned by the program that generates any kind of query.
    flags (int): Control flags for the DNS query.
    num_questions (int): The number of questions in the DNS query. Default is 0.
    num_answers (int): The number of answers in the DNS query. Default is 0.
    num_authorities (int): The number of authority records in the DNS query. Default is 0.
    num_additionals (int): The number of additional records in the DNS query. Default is 0.
    """

    id: int
    flags: int
    num_questions: int = 0
    num_answers: int = 0
    num_authorities: int = 0
    num_additionals: int = 0


@dataclass
class DNSQuestion:
    """
    Represents a DNS question section.

    Attributes
    ----------
    name (bytes): The domain name being queried, in bytes.
    type_ (int): The type of the DNS query (e.g., A, NS, CNAME).
    class_ (int): The class of the DNS query (usually IN for internet).
    """

    name: bytes
    type_: int
    class_: int


@dataclass
class DNSRecord:
    """
    Represents a DNS record.

    Attributes
    ----------
    name (bytes): The domain name associated with the record.
    type_ (int): The type of the DNS record (e.g., A, NS, CNAME).
    class_ (int): The class of the DNS record (usually IN for internet).
    ttl (int): Time to live - the time period that the record may be cached.
    data (bytes): The data of the DNS record (e.g., IP address, another domain name).
    """

    name: bytes
    type_: int
    class_: int
    ttl: int
    data: bytes


def header_to_bytes(header: DNSHeader) -> bytes:
    """
    Convert a DNSHeader object into a byte sequence suitable for a DNS packet.

    Args:
    ----
    header (DNSHeader): The DNSHeader object to convert.

    Returns:
    -------
    bytes: The byte representation of the DNSHeader.
    """
    fields = astuple(header)
    return struct.pack("!HHHHHH", *fields)


def question_to_bytes(question: DNSQuestion) -> bytes:
    """
    Convert a DNSQuestion object into a byte sequence suitable for a DNS packet.

    Args:
    ----
    question (DNSQuestion): The DNSQuestion object to convert.

    Returns:
    -------
    bytes: The byte representation of the DNSQuestion.
    """
    return question.name + struct.pack("!HH", question.type_, question.class_)


def encode_dns_name(domain_name: str) -> bytes:
    """
    Encode a domain name into a format suitable for a DNS query.

    Args:
    ----
    domain_name (str): The domain name to encode.

    Returns:
    -------
    bytes: The encoded domain name in DNS query format.
    """
    encoded = b""
    for part in domain_name.encode("ascii").split(b"."):
        encoded += bytes([len(part)]) + part
    return encoded + b"\x00"


def build_query(domain_name: str, record_type: int) -> bytes:
    """
    Build a complete DNS query packet for a specified domain name and record type.

    Args:
    ----
    domain_name (str): The domain name to query.
    record_type (int): The type of DNS record being queried.

    Returns:
    -------
    bytes: The complete DNS query packet in byte format.
    """
    id_ = random.randint(0, 65535)
    header = DNSHeader(id=id_, num_questions=1, flags=0)

    name = encode_dns_name(domain_name)
    question = DNSQuestion(name=name, type_=record_type, class_=CLASS_IN)

    return header_to_bytes(header) + question_to_bytes(question)


def parse_header(reader: BytesIO) -> DNSHeader:
    """
    Parse the header of a DNS packet.

    Args:
    ----
    reader (BytesIO): A BytesIO stream containing the DNS packet.

    Returns:
    -------
    DNSHeader: The parsed DNS header.
    """
    # 4.1.1. Header section format
    # https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
    items = struct.unpack("!HHHHHH", reader.read(12))
    return DNSHeader(*items)


def parse_question(reader: BytesIO) -> DNSQuestion:
    """
    Parse a DNS question section from a DNS packet.

    Args:
    ----
    reader (BytesIO): A BytesIO stream containing the DNS packet.

    Returns:
    -------
    DNSQuestion: The parsed DNS question.
    """
    # 4.1.2. Question section format
    # https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
    name = decode_name(reader)
    data = reader.read(4)
    type_, class_ = struct.unpack("!HH", data)
    return DNSQuestion(name, type_, class_)


def parse_record(reader: BytesIO) -> DNSRecord:
    """
    Parse a DNS record from a DNS packet.

    Args:
    ----
    reader (BytesIO): A BytesIO stream containing the DNS packet.

    Returns:
    -------
    DNSRecord: The parsed DNS record.
    """
    # 4.1.3. Resource record format
    # https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3

    name = decode_name(reader)
    data = reader.read(10)
    type_, class_, ttl, data_len = struct.unpack("!HHIH", data)
    if type_ == TYPE_NS:
        data = decode_name(reader)
    elif type_ == TYPE_A:
        data = ip_to_string(reader.read(data_len))
    else:
        data = reader.read(data_len)

    return DNSRecord(name, type_, class_, ttl, data)


def decode_name(reader: BytesIO) -> bytes:
    """
    Decode a domain name from a DNS packet.

    Args:
    ----
    reader (BytesIO): A BytesIO stream containing the DNS packet.

    Returns:
    -------
    bytes: The decoded domain name.
    """
    parts = []
    while (length := reader.read(1)[0]) != 0:
        if length & 0b1100_0000:
            parts.append(decode_compressed_name(length, reader))
            break

        parts.append(reader.read(length))

    return b".".join(parts)


def decode_compressed_name(length: int, reader: BytesIO) -> bytes:
    """
    Decode a compressed domain name from a DNS packet.

    Args:
    ----
    length (int): The length of the compressed name.
    reader (BytesIO): A BytesIO stream containing the DNS packet.

    Returns:
    -------
    bytes: The decoded domain name.
    """
    pointer_bytes = bytes([length & 0b0011_1111]) + reader.read(1)
    pointer = struct.unpack("!H", pointer_bytes)[0]
    current_pos = reader.tell()
    reader.seek(pointer)
    result = decode_name(reader)
    reader.seek(current_pos)
    return result


@dataclass
class DNSPacket:
    """
    Represents a full DNS packet.

    Attributes
    ----------
    header (DNSHeader): The header section of the DNS packet.
    questions (list[DNSQuestion]): A list of questions in the DNS packet.
    answers (list[DNSRecord]): A list of answer records in the DNS packet.
    authorities (list[DNSRecord]): A list of authority records in the DNS packet.
    additionals (list[DNSRecord]): A list of additional records in the DNS packet.
    """

    header: DNSHeader
    questions: list[DNSQuestion]
    answers: list[DNSRecord]
    authorities: list[DNSRecord]
    additionals: list[DNSRecord]


def parse_dns_packet(data: bytes) -> DNSPacket:
    """
    Parse a complete DNS packet.

    Args:
    ----
    data (bytes): The DNS packet in byte format.

    Returns:
    -------
    DNSPacket: The parsed DNS packet.
    """
    reader = BytesIO(data)
    header = parse_header(reader)
    questions = [parse_question(reader) for _ in range(header.num_questions)]
    answers = [parse_record(reader) for _ in range(header.num_answers)]
    authorities = [parse_record(reader) for _ in range(header.num_authorities)]
    additionals = [parse_record(reader) for _ in range(header.num_additionals)]

    return DNSPacket(header, questions, answers, authorities, additionals)


def ip_to_string(ip: bytes) -> str:
    """
    Convert an IP address in bytes to a string format.

    Args:
    ----
    ip (bytes): The IP address in byte format.

    Returns:
    -------
    str: The IP address in string format.
    """
    return ".".join([str(x) for x in ip])


def lookup_domain(domain_name: str) -> str:
    """
    Look up the IP address for a given domain name using a DNS query.

    Args:
    ----
    domain_name (str): The domain name to look up.

    Returns:
    -------
    str: The IP address of the domain.
    """
    query = build_query(domain_name, TYPE_A)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, ("8.8.8.8", 53))

    data, _ = sock.recvfrom(1024)
    response = parse_dns_packet(data)
    return ip_to_string(response.answers[0].data)


def send_query(ip_address: str, domain_name: str, record_type: int) -> DNSPacket:
    """
    Send a DNS query to the specified DNS server and return the response.

    Args:
    ----
    ip_address (str): The IP address of the DNS server to which the query is sent.
    domain_name (str): The domain name for which the DNS query is being made.
    record_type (int): The type of DNS record being queried (e.g., TYPE_A, TYPE_NS).

    Returns:
    -------
    DNSPacket: The DNS packet received in response to the query.
    """
    query = build_query(domain_name, record_type)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, (ip_address, 53))

    data, _ = sock.recvfrom(1024)
    return parse_dns_packet(data)


def get_answer(packet: DNSPacket) -> bytes | None:
    """
    Extract the answer from a DNS response packet.

    Args:
    ----
    packet (DNSPacket): The DNSPacket object containing the DNS response.

    Returns:
    -------
    bytes | None: The answer section of the DNS response, or None if no answer is found.
    """
    for x in packet.answers:
        if x.type_ == TYPE_A:
            return x.data
    return None


def get_nameserver_ip(packet: DNSPacket) -> bytes | None:
    """
    Extract the IP address of the nameserver from the additional records of a DNS packet.

    Args:
    ----
    packet (DNSPacket): The DNSPacket object containing the DNS response.

    Returns:
    -------
    bytes | None: The IP address of the nameserver, or None if not found in the additional records.
    """
    for x in packet.additionals:
        if x.type_ == TYPE_A:
            return x.data
    return None


def get_nameserver(packet: DNSPacket) -> bytes | None:
    """
    Extract the domain name of the nameserver from the authority records of a DNS packet.

    Args:
    ----
    packet (DNSPacket): The DNSPacket object containing the DNS response.

    Returns:
    -------
    bytes | None: The domain name of the nameserver, or None if not found in the authority records.
    """
    for x in packet.authorities:
        if x.type_ == TYPE_NS:
            return x.data.decode("utf-8")
    return None


def resolve(domain_name: str, record_type: int) -> bytes:
    """
    Resolve a domain name by querying DNS servers, following referrals as necessary.

    Args:
    ----
    domain_name (str): The domain name to resolve.
    record_type (int): The type of DNS record to resolve (e.g., TYPE_A, TYPE_NS).

    Returns:
    -------
    bytes: The resolved data for the domain name, typically an IP address.

    Raises:
    ------
    ValueError: If the resolution process fails or cannot find the requested data.
    """
    # List of Root Servers
    # https://www.iana.org/domains/root/servers
    nameserver = "202.12.27.33"
    while True:
        print(f"Querying {nameserver} for {domain_name}")
        response = send_query(nameserver, domain_name, record_type)
        if ip := get_answer(response):
            return ip
        if ns_ip := get_nameserver_ip(response):
            nameserver = ns_ip
        elif ns_domain := get_nameserver(response):
            nameserver = resolve(ns_domain, TYPE_A)
        else:
            msg = "something went wrong"
            raise ValueError(msg)
