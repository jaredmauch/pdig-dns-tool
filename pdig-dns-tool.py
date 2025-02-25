#!/usr/bin/python3

"""
# ask each NS in the query for the domainname
# for answers and record response times for
# each address family, IP address, transport and authority

"""

import argparse
import socket
import statistics
import sys
import time
import tempfile

# 3rd party imports
try:
    import dns
    import dns.message
    import dns.query
    import dns.rdatatype
    import dns.resolver
    import dns.zone
except:
    print("apt install python3-dnspython or pip3 install dnspython")
    sys.exit(0)

# apt install python3-netifaces
#try:
#    import netifaces
#except:
#    print("apt install python3-netifaces or pip3 install netifaces")
#    sys.exit(0)

all_ips = {}
socket_af_types = [socket.AF_INET, socket.AF_INET6]

# full_qname: domain name to query for
# prev_cache: list of nameservers to query
# qtype_list: is array of possible query types
#     eg: [dns.rdatatype.A, dns.rdatatype.AAAA]
# tcp: when true, send query over tcp
#
def query_all(full_qname, prev_cache, qtype_list, tcp):
    cname_reply = None
    new_cache = []
    times = []
    query_ip = {}
    domain_exists = True

    for qtype in qtype_list:
        try:
            q = dns.message.make_query(full_qname, qtype)
        except Exception as e:
            print(e, full_qname, qtype)
        for x in prev_cache:
            qip = x['addrinfo']
            # avoid possible odd link-local issues
            if qip.startswith('fe80::'):
                continue
            # check if we have talked to this IP + QTYPE this round
            if query_ip.get(qip + str(qtype), None) is None:
                query_ip[qip + str(qtype)] = 1

                # store list of all IPs
                all_ips[qip] = 1

                # timer
                start_time = time.time()
                try:
                    if tcp:
                        resp = dns.query.tcp(q, x['addrinfo'], timeout=10)
                    else:
                        resp =  dns.query.udp(q, x['addrinfo'], timeout=10)
                    stop_time = time.time()

                    latency = stop_time - start_time
                    latency_ms = latency * 1000
                    times.append(latency_ms)

                    print(f"ns={x['qname']} addr={x['addrinfo']}, latency={latency_ms:.3f} ms")
                    if resp.rcode() == dns.rcode.NXDOMAIN:
                        domain_exists = False
                        continue
                    if resp.rcode() != dns.rcode.NOERROR:
                        print(f"{dns.rcode.to_text(resp.rcode())} for {full_qname} at {x['addrinfo']}")
                        continue
                    if len(resp.answer) > 0:
                        # 5 = CNAME rfc1035
                        if resp.answer[0].rdtype == 5:
                            for i in resp.answer[0].items:
                                cname_reply = str(i)

                    # parse the authority portion of response packet
                    # if we are not yet to an authoritative server
                    if not resp.flags & dns.flags.AA:
                        for var in resp.authority:
                            for i in var.items:
                                # check NS responses
                                if type(i) == dns.rdtypes.ANY.NS.NS:
                                    # both address families
                                    for fam in socket_af_types:
                                        try:
                                            add_info = socket.getaddrinfo(host=i.to_text(), port=None, family=fam, proto=socket.SOCK_RAW)
                                        except socket.gaierror:
    #                                        print(e)
                                            continue
                                        str_name = str(i.to_text())
                                        for a in add_info:
                                            addr_list = a[4]
                                            new_cache.append({'qname': str_name, 'af_type': a[0], 'addrinfo': addr_list[0]})
                except dns.query.BadResponse as e:
                    print(f"error {e} querying {x['addrinfo']} for {full_qname}")
                except dns.exception.Timeout as e:
                    print(f"timeout querying: {x['addrinfo']}")
                except OSError as e:
                    # This is the new block to catch network unreachable errors
#                    print(f"Network error: {e} when trying to reach {x['addrinfo']}")
                    continue  # Skip this address and try the next one

    # output some statistics at the end
    min_value = 0 if len(times) == 0 else min(times)
    max_value = 0 if len(times) == 0 else max(times)
    avg_value = 0 if len(times) == 0 else sum(times)/len(times)
    min_max_range = max_value - min_value
    stddev = 0 if len(times) < 2 else statistics.stdev(times)
    min_max_ratio = 0 if min_value == 0 else max_value / min_value
    print(f"latency: min={min_value:.3f} ms max={max_value:.3f} ms avg={avg_value:.3f} ms")
    print(f"stdev={stddev:.3f} ms max-min={min_max_range:.3f} max/min={min_max_ratio:.2f} x latency variance")
    if not domain_exists:
        print(f"NXDOMAIN for {full_qname}, stopping...")
        return ([], None)
    # See bug #5. This is to prevent some endless loops if we do not
    # progress in the domain name tree.
    if sorted(new_cache, key=lambda ns: ns["qname"]) == \
       sorted(prev_cache, key=lambda ns: ns["qname"]):
        new_cache = []
    return (new_cache, cname_reply)

root_hints = []

# main()

parser = argparse.ArgumentParser(prog=sys.argv[0])
parser.add_argument('domain', help="domain name to query") # positional argument
parser.add_argument('-6', '--ipv6', action='store_true', help="query ipv6-only") # ipv6-only
parser.add_argument('-4', '--ipv4', action='store_true', help="query ipv4-only") # ipv4-only
parser.add_argument('-t', '--tcp', action='store_true', help="send queries over TCP") # use TCP

args = parser.parse_args()
if args.ipv4:
    socket_af_types = [socket.AF_INET]
if args.ipv6:
    socket_af_types = [socket.AF_INET6]
if args.tcp:
    use_tcp = True
else:
    use_tcp = False

#parse args
domain = args.domain

temp_name = '/tmp/' + next(tempfile._get_candidate_names())
print(temp_name)
fh = open(temp_name, "w", encoding='ascii')

print(f"querying for {domain}")

# preseed the data
response = dns.resolver.resolve(".", "NS", lifetime=10, tcp=use_tcp)
for var in response.response.answer:
    for i in var.items:
        for fam in socket_af_types:
            try:
                add_info = socket.getaddrinfo(host=i.to_text(), port=None, family=fam, proto=socket.SOCK_RAW)
            except socket.gaierror:
                continue
            str_name = str(i.to_text())
            for a in add_info:
                addr_list = a[4]
                root_hints.append({'qname': str_name, 'af_type': a[0], 'addrinfo': addr_list[0]})
#                print(f"getaddrinfo: {str_name}: af_type: {a[0]}, addrinfo: {addr_list[0]}")
old_cache = root_hints

# run through the domain tree until done
while len(old_cache) > 0:
    (reply_hints, new_domain) = query_all(domain, old_cache, [dns.rdatatype.TXT], use_tcp)
    old_cache = reply_hints
    if new_domain is not None:
        print(f"(re)querying for {domain} due to CNAME")
        domain = new_domain
        old_cache = root_hints
    print("===================")
#

for ip in all_ips:
    fh.write(f"# {ip}\n")
    fh.write(f"dig +noall +answer +stats @{ip} identity.nameserver.id ch txt\n")
    fh.write(f"mtr -bw {ip}\n")

ts = time.ctime()
print(f"end={ts}")
print(temp_name)

fh.close()
#
