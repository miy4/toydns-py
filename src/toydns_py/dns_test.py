from .dns import (
    TYPE_A,
    build_query,
    encode_dns_name,
)


def test_encode_dns_name():
    expected = b"\x06google\x03com\x00"
    assert expected == encode_dns_name("google.com")


def test_build_query():
    expected = b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    actual = build_query("example.com", TYPE_A)

    # The first 2 bytes contain a randomly generated ID, so they were truncated in this test
    assert expected == actual[2:]
