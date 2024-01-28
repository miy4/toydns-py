import random
import struct
from dataclasses import astuple, dataclass

TYPE_A = 1
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
    recursion_desired = 0b100000000
    header = DNSHeader(id=id_, num_questions=1, flags=recursion_desired)

    name = encode_dns_name(domain_name)
    question = DNSQuestion(name=name, type_=record_type, class_=CLASS_IN)

    return header_to_bytes(header) + question_to_bytes(question)
