from io import BytesIO

from .dns import (
    TYPE_A,
    DNSHeader,
    DNSPacket,
    DNSQuestion,
    DNSRecord,
    build_query,
    encode_dns_name,
    ip_to_string,
    parse_dns_packet,
    parse_header,
    parse_question,
    parse_record,
)


def test_encode_dns_name():
    expected = b"\x06google\x03com\x00"
    assert expected == encode_dns_name("google.com")


def test_build_query():
    expected = b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    actual = build_query("example.com", TYPE_A)

    # The first 2 bytes contain a randomly generated ID, so they were truncated in this test
    assert expected == actual[2:]


def test_parse_header():
    response = b'`V\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00R\x9b\x00\x04]\xb8\xd8"'
    reader = BytesIO(response)
    expected = DNSHeader(
        id=24662,
        flags=33152,
        num_questions=1,
        num_answers=1,
        num_authorities=0,
        num_additionals=0,
    )
    assert expected == parse_header(reader)


def test_parse_question():
    response = b'`V\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00R\x9b\x00\x04]\xb8\xd8"'
    reader = BytesIO(response)

    parse_header(reader)

    expected = DNSQuestion(name=b"www.example.com", type_=1, class_=1)
    assert expected == parse_question(reader)


def test_parse_record():
    response = b'`V\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00R\x9b\x00\x04]\xb8\xd8"'
    reader = BytesIO(response)

    parse_header(reader)
    parse_question(reader)

    expected = DNSRecord(
        name=b"www.example.com",
        type_=1,
        class_=1,
        ttl=21147,
        data=b']\xb8\xd8"',
    )
    assert expected == parse_record(reader)


def test_parse_dns_packet():
    response = b'`V\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00R\x9b\x00\x04]\xb8\xd8"'

    expected = DNSPacket(
        header=DNSHeader(
            id=24662,
            flags=33152,
            num_questions=1,
            num_answers=1,
            num_authorities=0,
            num_additionals=0,
        ),
        questions=[DNSQuestion(name=b"www.example.com", type_=1, class_=1)],
        answers=[
            DNSRecord(
                name=b"www.example.com",
                type_=1,
                class_=1,
                ttl=21147,
                data=b']\xb8\xd8"',
            ),
        ],
        authorities=[],
        additionals=[],
    )
    assert expected == parse_dns_packet(response)


def test_ip_to_string():
    assert "93.184.216.34" == ip_to_string(b']\xb8\xd8"')
