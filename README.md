To run the script use the following command:
python dns_client.py <domain_name> [dns_sever_ip]
On some systems python3 may be required instead of python
Where domain_name is required and is the QNAME to lookup.
dns_server_ip is optional and can be used to indicate an IPv4 DNS server to query.
If a dns_server_ip is not provided 8.8.8.8 will be utilized which is the Google default DNS server.