import socket

from .dns import build_query


def main():
    query = build_query("www.example.com", 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, ("8.8.8.8", 53))
    response, _ = sock.recvfrom(1024)
    return response
