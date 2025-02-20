#!/usr/bin/python3

"""
# ask each NS in the query for the domainname
# for answers and record response times for
# each AF, transport and authority

"""

import socket
import statistics
import sys
import time
import tempfile

# 3rd party imports
import dns
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone
# apt install python3-netifaces
try:
    import netifaces
except:
    print("apt install python3-netifaces")

all_ips = {}
socket_af_types = [socket.AF_INET, socket.AF_INET6]

# qtype_list is array of possible query types
# eg: [dns.rdatatype.A, dns.rdatatype.AAAA]
#
def query_all(full_qname, prev_cache, qtype_list):
    cname_reply = None
    new_cache = []
    times = []
    query_ip = {}

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
                    resp =  dns.query.udp(q, x['addrinfo'], timeout=10)
                    stop_time = time.time()

                    latency = stop_time - start_time
                    latency_ms = latency * 1000
                    times.append(latency_ms)

                    print(f"ns={x['qname']} addr={x['addrinfo']}, latency={latency_ms:.3f} ms")
                    if len(resp.answer) > 0:
                        # 5 = CNAME rfc1035
                        if resp.answer[0].rdtype == 5:
                            for i in resp.answer[0].items:
                                cname_reply = str(i)

                    # parse the authority portion of response packet
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

    # output some statistics at the end
    min_value = min(times)
    max_value = max(times)
    avg_value = 0 if len(times) == 0 else sum(times)/len(times)
    min_max_range = max_value-min_value
    stddev = statistics.stdev(times)
    min_max_ratio = max_value / min_value
    print(f"latency: min={min_value:.3f} ms max={max_value:.3f} ms avg={avg_value:.3f} ms")
    print(f"stdev={stddev:.3f} ms max-min={min_max_range:.3f} max/min={min_max_ratio:.2f} x latency variance")
    return (new_cache, cname_reply)

root_hints = []

# main()

#parse args
if len(sys.argv) > 1:
    domain = sys.argv[1]
else:
    prog_name = sys.argv[0]
    print(f"Usage: {prog_name} example.com")
    sys.exit(1)

temp_name = '/tmp/' + next(tempfile._get_candidate_names())
print(temp_name)
fh = open(temp_name, "w", encoding='ascii')

print(f"querying for {domain}")

# axfr = dns.query.xfr(masterip, domainname, lifetime=dns_timeout)

# preseed the data
response = dns.resolver.resolve(".", "NS")
for var in response.response.answer:
    for i in var.items:
        for fam in socket_af_types:
            add_info = socket.getaddrinfo(host=i.to_text(), port=None, family=fam, proto=socket.SOCK_RAW)
            str_name = str(i.to_text())
            for a in add_info:
                addr_list = a[4]
                root_hints.append({'qname': str_name, 'af_type': a[0], 'addrinfo': addr_list[0]})
#                print(f"getaddrinfo: {str_name}: af_type: {a[0]}, addrinfo: {addr_list[0]}")
old_cache = root_hints

# run through the domain tree until done
while len(old_cache) > 0:
    (reply_hints, new_domain) = query_all(domain, old_cache, [dns.rdatatype.TXT])
    old_cache = reply_hints
    if new_domain is not None:
        print(f"(re)querying for {domain} due to CNAME")
        domain = new_domain
        old_cache = root_hints
    print("===================")
#

for ip in all_ips:
    fh.write(f"# {ip}\n")
    fh.write(f"mtr -w {ip}\n")

ts = time.ctime()
print(f"end={ts}")
print(temp_name)

fh.close()
#
