# DNS Client

## Usage

To run the script use the following command:

```bash
python dns_client.py <domain_name> [dns_sever_ip]
```

Where domain_name is required and is the QNAME to lookup.
dns_server_ip is optional and can be used to indicate an IPv4 DNS server to query.
If a dns_server_ip is not provided 8.8.8.8 will be utilized which is the Google default DNS server.

Note: On some systems python3 may be required instead of python

## Instalation

The script can be installed by using the following command when in the root of the repository:

```bash
pip install .
```

This allows the script to be used globally anywhere on the system or when the virtual environment is activated.
