import socket
import sys
import struct
import random
from dataclasses import dataclass

DNS_DEFAULT_IP = "8.8.8.8" # Google's public DNS server
DNS_PORT = 53 # DNS port number
DNS_HEADER_SIZE = 12
DNS_REQUEST_FLAGS = 0x0100 # Standard query with recursion desired

DNS_RECORD_TYPES = {
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    6: 'SOA',
    12: 'PTR',
    15: 'MX',
    16: 'TXT',
    28: 'AAAA',
    33: 'SRV',
    41: 'OPT',
    43: 'DS',
    46: 'RRSIG',
    47: 'NSEC',
    48: 'DNSKEY',
    255: 'ANY'
}

DNS_CLASSES = {
    1: 'IN',
    2: 'CS',
    3: 'CH',
    4: 'HS',
    255: 'ANY'
}

# List to store the start and end indices of any non A records
# This is used to handle compressed domain names in the RDATA field
# The indices are used to determine the maximum length of the domain name
RDATA_INDEX_LIST = []

# Function to parse a domain name from a DNS packet
# The domain name is stored as a sequence of labels, each of which is a length-prefixed string
# The labels are separated by a period
# The domain name is terminated by a zero-length label
# The function returns the domain name and the offset of the next byte in the packet
def parse_qname(data, offset) -> str:
    qname = ''
    i = offset

    # Determine the maximum length of the domain name
    max_i = len(data)
    for start, end in RDATA_INDEX_LIST:
        if start <= i < end:
            max_i = end
            break

    while i < max_i:
        if (data[i] & 0xC0) == 0xC0:
            # Name is compressed
            compression_offset = struct.unpack('!H', data[i:i+2])[0] & 0x3FFF
            qname_compressed, _ = parse_qname(data, compression_offset)
            if i != offset:
                qname += '.'
            qname += qname_compressed
            i += 2
            continue
        label_len = data[i]
        if label_len == 0:
            break
        if i != offset:
            qname += '.'
        qname += data[i+1:i+1+label_len].decode()
        i += label_len + 1
    i += 1
    return qname, i


@dataclass
class DNSHeader:
    # DNS header fields
    id: int
    flags: int
    qdcount: int # Num Questions
    ancount: int # Num Answers
    nscount: int # Num Nameserver records
    arcount: int # Num Additional records

    # Function to pack the DNS header into a byte string
    def pack(self) -> bytes:
        return struct.pack('!HHHHHH', self.id, self.flags, self.qdcount, self.ancount, self.nscount, self.arcount)
    
    def is_authoritative(self) -> bool:
        return (self.flags & 0x0400) == 0x0400
    
    # Function to unpack a byte string into a DNS header object
    @classmethod
    def unpack(cls, data: bytes) -> 'DNSHeader':
        fields = struct.unpack('!HHHHHH', data[:DNS_HEADER_SIZE])
        return cls(*fields)
    
@dataclass
class DNSQuestion:
    # DNS question fields
    qname: str
    qtype: int
    qclass: int

    # Function to pack the DNS question into a byte string
    def pack(self) -> bytes:
        qname_encoded = b''
        # Encode the domain name by splitting it into labels and encoding each label
        # The labels are length-prefixed and separated by a period
        for label in self.qname.split('.'):
            qname_encoded += struct.pack('!B', len(label))
            qname_encoded += label.encode()
        qname_encoded += b'\x00'
        # Pack the qtype and qclass fields and return the packed data
        return qname_encoded + struct.pack('!HH', self.qtype, self.qclass)
    
    # Function to unpack a byte string into a DNS question object
    @classmethod
    def unpack(cls, data: bytes, offset=DNS_HEADER_SIZE) -> tuple['DNSQuestion', int]:
        i = offset
        # Dynamically parse the domain name
        qname, i = parse_qname(data, i)
        qtype, qclass = struct.unpack('!HH', data[i:i+4])
        return cls(qname, qtype, qclass), i+4
    
@dataclass
class DNSResource:
    # DNS resource fields
    name: str
    rr_type: int
    rr_class: int
    ttl: int
    rdata: bytes
    
    # Function unpack the DNS resource record from a byte string
    @classmethod
    def unpack(cls, data: bytes, offset: int) -> tuple['DNSResource', int]:
        i = offset
        # Parse the name
        if (data[i] & 0xC0) == 0xC0:
            # Name is compressed
            compression_offset = struct.unpack('!H', data[i:i+2])[0] & 0x3FFF
            qname, _ = parse_qname(data, compression_offset)
            i += 2
        else:
            # Name is not compressed
            qname, i = parse_qname(data, i)

        # Unpack the type, class, TTL, and data length
        qtype, qclass, ttl, data_length = struct.unpack('!HHIH', data[i:i+10])
        i += 10

        # Extract the data
        answer_data = data[i:i+data_length]

        # If it's an A record, decode the IP address
        if qtype == 1 and qclass == 1 and data_length == 4:
            answer_data = socket.inet_ntoa(answer_data)
        # If it's a CNAME record keep track of the start and index
        # to assist in locating the end when used in message compression
        else:
            RDATA_INDEX_LIST.append((i, i+data_length))

        i += data_length

        return cls(qname, qtype, qclass, ttl, answer_data), i

# Function to build a DNS query for a domain name
def build_dns_query(domain_name) -> tuple[DNSHeader, DNSQuestion]:
    # Generate a random ID for the DNS query
    id = random.randint(0, 65535)
    dns_header = DNSHeader(id, DNS_REQUEST_FLAGS, 1, 0, 0, 0)
    dns_question = DNSQuestion(domain_name, 1, 1)
    return dns_header, dns_question

def parse_dns_response(data) -> tuple[DNSHeader, list[DNSQuestion], list[DNSResource], list[DNSResource], list[DNSResource], bytes]:
    # Unpack the DNS header
    dns_header = DNSHeader.unpack(data)
    offset = DNS_HEADER_SIZE
    # Unpack the DNS questions
    dns_questions = []
    for _ in range(dns_header.qdcount):
        # Parse the question and update the offset
        dns_question, offset = DNSQuestion.unpack(data, offset)
        dns_questions.append(dns_question)
    # Unpack the DNS answers
    dns_answers = []
    for _ in range(dns_header.ancount):
        # Parse the answer and update the offset
        dns_answer, offset = DNSResource.unpack(data, offset)
        dns_answers.append(dns_answer)
    dns_nameservers = []
    for _ in range (dns_header.nscount):
        dns_ns, offset = DNSResource.unpack(data, offset)
        dns_nameservers.append(dns_ns)
    dns_additional = []
    for _ in range(dns_header.arcount):
        dns_add, offset = DNSResource.unpack(data, offset)
        dns_additional.append(dns_add)
    # Return the DNS header, questions, answers, and any remaining data that might exist
    return dns_header, dns_questions, dns_answers, dns_nameservers, dns_additional, data[offset:]

def perform_query(domain_name, dns_server) -> tuple[DNSHeader, list[DNSQuestion], list[DNSResource], list[DNSResource], list[DNSResource], bytes]:
    # Create the UDP socket and send the query to the DNS server
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Build the DNS query
    query_header, query_question = build_dns_query(domain_name)
    # Pack the query and send it to the DNS server
    query = query_header.pack() + query_question.pack()
    sock.sendto(query, (dns_server, DNS_PORT))
    # Receive the response and parse it
    data, _ = sock.recvfrom(512)
    sock.close()
    # Parse the response and then verify the response
    response_header, response_questions, response_answers, response_nameserver, response_additional, remaining_data = parse_dns_response(data)
    # Check header flags for any errors based on RFC 1035
    if query_header.id != response_header.id:
        print("Error: ID mismatch")
        exit(1)
    if response_header.flags & 0xF == 1:
        print("Error: Format error")
        exit(1)
    if response_header.flags & 0xF == 2:
        print("Error: Server failure")
        exit(1)
    if response_header.flags & 0xF == 3:
        print("Error: Domain name not found")
        exit(1)
    if response_header.flags & 0xF == 4:
        print("Error: Query type not supported")
        exit(1)
    if response_header.flags & 0xF == 5:
        print("Error: Server refused")
        exit(1)
    return response_header, response_questions, response_answers, response_nameserver, response_additional, remaining_data

def convert_dns_type(dns_type) -> str:
    return DNS_RECORD_TYPES.get(dns_type, dns_type)

def convert_dns_class(dns_class) -> str:
    return DNS_CLASSES.get(dns_class, dns_class)

def main():
    if len(sys.argv) < 2:
        print("Usage: python dns_client.py <domain_name> [dns_server_ip]")
        exit(1)
    dns_server = DNS_DEFAULT_IP
    if len(sys.argv) >= 3:
        # Use the specified DNS server
        dns_server = sys.argv[2]
    domain_name = sys.argv[1]
    response_header, response_questions, response_answers, response_nameserver, response_additional, remaining_data = perform_query(domain_name, dns_server)
    print("DNS server:", dns_server)
    print(f"DNS Address: {dns_server}#{DNS_PORT}")
    print()
    print("Num Questions:", response_header.qdcount)
    print("Num Answers", response_header.ancount)
    print("Num Nameserver records:", response_header.nscount)
    print("Num Additional records:", response_header.arcount)
    print()
    if len(response_answers) > 0:
        if response_header.is_authoritative():
            print("Authoritative answer(s):")
        else:
            print("Non-authoritative answer(s):")
        for answer in response_answers:
            # Print the answer details
            print("Name:", answer.name)
            print("Type:", convert_dns_type(answer.rr_type))
            print("Class:", convert_dns_class(answer.rr_class))
            print("TTL:", answer.ttl)
            if answer.rr_type == 1 and answer.rr_class == 1:
                # Print the IP address for A records
                print("Address:", answer.rdata)
            else:
                # Print the raw data for other record types
                print("Data:", answer.rdata)
            print()
    if len(response_nameserver) > 0:
        print("Nameserver record(s):")
        for nameserver in response_nameserver:
            # Print the answer details
            print("Name:", nameserver.name)
            print("Type:", convert_dns_type(nameserver.rr_type))
            print("Class:", convert_dns_class(nameserver.rr_class))
            print("TTL:", nameserver.ttl)
            if nameserver.rr_type == 1 and nameserver.rr_class == 1:
                # Print the IP address for A records
                print("Address:", nameserver.rdata)
            else:
                # Print the raw data for other record types
                print("Data:", nameserver.rdata)
            print()
    if len(response_additional) > 0:
        print("Additional record(s):")
        for additional in response_additional:
            # Print the answer details
            print("Name:", additional.name)
            print("Type:", convert_dns_type(additional.rr_type))
            print("Class:", convert_dns_class(additional.rr_class))
            print("TTL:", additional.ttl)
            if additional.rr_type == 1 and additional.rr_class == 1:
                # Print the IP address for A records
                print("Address:", additional.rdata)
            else:
                # Print the raw data for other record types
                print("Data:", additional.rdata)
            print()
    if len(remaining_data) > 0:
        # Print any remaining data that was not parsed
        print("Remaining data (unparsed):", remaining_data)

if __name__ == '__main__':
    main()