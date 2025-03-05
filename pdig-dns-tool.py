#!/usr/bin/python3
# /// script
# dependencies = [
#     "dnspython",
#     "requests",
# ]
# ///

"""
# ask each NS in the query for the domainname
# for answers and record response times for
# each address family, IP address, transport and authority

"""

import argparse
import os
import socket
import statistics
import sys
import time
import tempfile
import json
import requests

# statistics stuff at the end
import random
import numpy.random


# 3rd party imports
try:
    import dns
    import dns.message
    import dns.query
    import dns.rdatatype
    import dns.resolver
    import dns.zone
except:  # Too broad
    print("apt install python3-dnspython or pip3 install dnspython")
    sys.exit(1)

# apt install python3-netifaces
#try:
#    import netifaces
#except:
#    print("apt install python3-netifaces or pip3 install netifaces")
#    sys.exit(0)



# full_qname: domain name to query for
# prev_cache: list of nameservers to query
# qtype_list: is array of possible query types
#     eg: [dns.rdatatype.A, dns.rdatatype.AAAA]
# tcp: when true, send query over tcp
#
def query_all(full_qname, prev_cache, qtype_list, tcp, file_handle, high_latency, ip_list, socket_types):
    # Add new data structure to store TTL and latency info
    query_stats = []
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
            if file_handle is not None:
                os.write(file_handle, str.encode(f"{e}:{full_qname}:{qtype}\n"))
        for x in prev_cache:
            qip = x['addrinfo']
            # Skip problematic IPv6 addresses
            if (qip.startswith('fe80::') or  # Link-local
                qip.startswith('fc') or      # ULA
                qip.startswith('fd') or      # ULA
                qip.startswith('ff') or      # Multicast IPv6
                qip == '::' or               # Unspecified IPv6
                qip.startswith('224.') or    # Multicast IPv4
                qip.startswith('225.') or    # Multicast IPv4
                qip.startswith('226.') or    # Multicast IPv4
                qip.startswith('227.') or    # Multicast IPv4
                qip.startswith('228.') or    # Multicast IPv4
                qip.startswith('229.') or    # Multicast IPv4
                qip.startswith('230.') or    # Multicast IPv4
                qip.startswith('231.') or    # Multicast IPv4
                qip.startswith('232.') or    # Multicast IPv4
                qip.startswith('233.') or    # Multicast IPv4
                qip.startswith('234.') or    # Multicast IPv4
                qip.startswith('235.') or    # Multicast IPv4
                qip.startswith('236.') or    # Multicast IPv4
                qip.startswith('237.') or    # Multicast IPv4
                qip.startswith('238.') or    # Multicast IPv4
                qip.startswith('239.') or    # Multicast IPv4
                qip == '0.0.0.0'):           # Unspecified IPv4
                continue
            # check if we have talked to this IP + QTYPE this round
            if query_ip.get(qip + str(qtype), None) is None:
                query_ip[qip + str(qtype)] = 1

                # store list of all IPs
                ip_list[qip] = 1

                # timer
                start_time = time.time()
                try:
                    if tcp:
                        resp = dns.query.tcp(q, qip, timeout=10)
                    else:
                        resp =  dns.query.udp(q, qip, timeout=10)
                    stop_time = time.time()

                    latency = stop_time - start_time
                    latency_ms = latency * 1000
                    times.append(latency_ms)

                    if latency_ms > 100 or high_latency is False:
                        print(f"ns={x['qname']} addr={qip}, latency={latency_ms:.3f} ms")
                        if file_handle is not None:
                            os.write(file_handle, str.encode(f"ns={x['qname']} addr={qip}, latency={latency_ms:.3f} ms" + '\n'))

                    if resp.rcode() == dns.rcode.NXDOMAIN:
                        domain_exists = False
                        continue
                    if resp.rcode() != dns.rcode.NOERROR:
                        print(f"{dns.rcode.to_text(resp.rcode())} for {full_qname} at {qip}")
                        continue

                    # parse the response packet
                    # if we are not yet to an authoritative server
                    if not resp.flags & dns.flags.AA or len(resp.answer) > 0:
                        ttl = None
                        vname = None
                        for var in resp.answer:
                            ttl = var.ttl
                            vname = str(var.name)
                            for i in var.items:
                                if var.rdtype == dns.rdatatype.CNAME:
                                    cname_reply = str(i)
                            if file_handle is not None:
                                os.write(file_handle, str.encode(f"\"{latency_ms}\";ans=\"{vname}\";qip=\"{qip}\";TTL={ttl}" + '\n'))
                            print(f"\"{latency_ms}\";ans=\"{vname}\";qip=\"{qip}\";TTL={ttl}")
                        # Store TTL and latency information
                        if ttl is not None: 
                            query_stats.append({'latency': latency_ms, 'ttl': ttl, 'nameserver': vname, 'ip': qip})
                        ttl = None
                        vname = None
                        # parse the authority portion of response packet
                        for var in resp.authority:
                            ttl = var.ttl
                            vname = str(var.name)
                            for i in var.items:
                                # check NS responses
                                if type(i) == dns.rdtypes.ANY.NS.NS:
                                    # both address families
                                    for fam in socket_types:
                                        try:
                                            add_info = socket.getaddrinfo(host=i.to_text(), port=None, family=fam, proto=socket.SOCK_RAW)
                                        except socket.gaierror:
#                                            print(e)
                                            continue
                                        str_name = str(i.to_text())
                                        for a in add_info:
                                            addr_list = a[4]
                                            new_cache.append({'qname': str_name, 'af_type': a[0], 'addrinfo': addr_list[0]})
                        # Store TTL and latency information
                        if ttl is not None:
                            query_stats.append({'latency': latency_ms, 'ttl': var.ttl, 'nameserver': vname, 'ip': qip})
                except dns.query.BadResponse as e:
                    print(f"error {e} querying {qip} for {full_qname}")
                    if file_handle is not None:
                        os.write(file_handle, str.encode(f"error {e} querying {qip} for {full_qname}\n"))
                except dns.exception.Timeout as e:
                    print(f"timeout querying: {qip} - {x['qname']}")
                    if file_handle is not None:
                        os.write(file_handle, str.encode(f"timeout querying: {qip} - {x['qname']}\n"))
                except OSError as e:
                    # This is the new block to catch network unreachable errors
                    print(f"Network error: {e} when trying to query {qip} for {x['qname']}")
                    if file_handle is not None:
                        os.write(file_handle, str.encode(f"Network error: {e} when trying to query {qip} for {x['qname']}"))
                    continue  # Skip this address and try the next one

    # output some statistics at the end
    min_value = 0 if len(times) == 0 else min(times)
    max_value = 0 if len(times) == 0 else max(times)
    avg_value = 0 if len(times) == 0 else sum(times)/len(times)
    min_max_range = max_value - min_value
    stddev = 0 if len(times) < 2 else statistics.stdev(times)
    min_max_ratio = 0 if min_value == 0 else max_value / min_value
    print(f"latency: min={min_value:.3f} ms max={max_value:.3f} ms avg={avg_value:.3f} ms")
    print(f"stdev={stddev:.3f} ms max-min={min_max_range:.3f} ms max/min={min_max_ratio:.2f} x latency variance")
    if file_handle is not None:
        os.write(file_handle, str.encode(f"latency: min={min_value:.3f} ms max={max_value:.3f} ms avg={avg_value:.3f} ms" + '\n'))
        os.write(file_handle, str.encode(f"stdev={stddev:.3f} ms max-min={min_max_range:.3f} ms max/min={min_max_ratio:.2f} x latency variance" + '\n'))

    if not domain_exists:
        print(f"NXDOMAIN for {full_qname}, stopping...")
        if file_handle is not None:
            os.write(file_handle, str.encode(f"NXDOMAIN for {full_qname}, stopping..." + '\n'))
        return ([], None, [])
    # See bug #5. This is to prevent some endless loops if we do not
    # progress in the domain name tree.
    if sorted(new_cache, key=lambda ns: ns["qname"]) == \
       sorted(prev_cache, key=lambda ns: ns["qname"]):
        new_cache = []
    return (new_cache, cname_reply, query_stats)


def query_domain(fqdn, cli_args, socket_types):
    root_hints = []

    all_ips = {}
    all_query_stats = []  # Store all query statistics

    print(f"querying for {fqdn}")

    fd = None
    filename = None
    if cli_args.report:
        # create a temporary file
        # XXX
        # Should use `tempfile.NamedTemporaryFile()` instead for better resource management
        (fd, filename) = tempfile.mkstemp(suffix=".txt", text=True)
        os.write(fd, str.encode(f"querying for {fqdn}" + '\n'))

    ts = time.ctime()
    print(f"start={ts}")
    if fd is not None:
        os.write(fd, str.encode(f"start={ts}" + '\n'))

    # preseed the data
    try:
        response = dns.resolver.resolve(".", "NS", lifetime=10, tcp=cli_args.tcp)
    except (dns.resolver.NoNameservers, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout) as e:
        print(f"Failed to resolve root nameservers: {e}")
        if fd is not None:
            os.write(fd, str.encode(f"Failed to resolve root nameservers: {e}\n"))
            os.close(fd)
        return None
    except Exception as e:
        print(f"Unexpected error resolving root nameservers: {e}")
        if fd is not None:
            os.write(fd, str.encode(f"Unexpected error resolving root nameservers: {e}\n"))
            os.close(fd)
        return None

    for var in response.response.answer:
        for i in var.items:
            for fam in socket_types:
                try:
                    add_info = socket.getaddrinfo(host=i.to_text(), port=None, family=fam, proto=socket.SOCK_RAW)
                except socket.gaierror:
                    continue
                str_name = str(i.to_text())
                for a in add_info:
                    addr_list = a[4]
                    root_hints.append({'qname': str_name, 'af_type': a[0], 'addrinfo': addr_list[0]})
#                    print(f"getaddrinfo: {str_name}: af_type: {a[0]}, addrinfo: {addr_list[0]}")
    old_cache = root_hints

    # run through the domain tree until done
    while len(old_cache) > 0:
        (reply_hints, new_domain, query_stats) = query_all(fqdn, old_cache, [dns.rdatatype.AAAA], cli_args.tcp, fd, cli_args.gt, all_ips, socket_types)
        all_query_stats.extend(query_stats)
        old_cache = reply_hints
        if new_domain is not None:
            print(f"(re)querying for {fqdn} due to CNAME to {new_domain}")
            if fd is not None:
                os.write(fd, str.encode(f"(re)querying for {fqdn} due to CNAME to {new_domain}" + '\n'))
            fqdn = new_domain
            old_cache = root_hints
        print("===================")
        if fd is not None:
            os.write(fd, str.encode("===================" + "\n"))

    ts = time.ctime()
    print(f"end={ts}")
    if fd is not None:
        os.write(fd, str.encode(f"end={ts}" + '\n'))

        for ip in all_ips:
            os.write(fd, str.encode(f"# {ip}\n"))
            os.write(fd, str.encode(f"dig +noall +answer +stats @{ip} identity.nameserver.id ch txt\n"))
            identity = dns.message.make_query("identity.nameserver.id", dns.rdatatype.TXT, rdclass=dns.rdataclass.CHAOS)
            try:
                resp =  dns.query.udp(identity, ip, timeout=10)
                for var in resp.answer:
                    for i in var.items:
                        os.write(fd, str.encode(f"\"{ts}\";\"{ip}\";{i}" + '\n'))
                        print(f"\"{ts}\";\"{ip}\";{i}")
            except Exception as e:
                print(f"{e}:{ip}")
                os.write(fd, str.encode(f"{e}:{ip}"))
            os.write(fd, str.encode(f"mtr -bw {ip}\n"))

    # After the main query loop, analyze and output the statistics
    if all_query_stats:
        print("\nQuery Statistics Analysis:")
        print("=" * 50)

        # Group by TTL ranges
        ttl_ranges = {}
        for stat in all_query_stats:
            ttl_key = f"{stat['nameserver']}"
            if ttl_key not in ttl_ranges:
                ttl_ranges[ttl_key] = {
                    'count': 0,
                    'latencies': [],
                    'nameservers': set(),
                    'ttl': None
                }
            ttl_ranges[ttl_key]['count'] += 1
            ttl_ranges[ttl_key]['latencies'].append(stat['latency'])
            ttl_ranges[ttl_key]['nameservers'].add(stat['nameserver'])
            ttl_ranges[ttl_key]['ttl'] = stat['ttl']

        avg_list = []
        min_list = []
        max_list = []
        stddev_list = []
        ttl_list = []
        count_list = []

        # Calculate and display statistics for each TTL range
        for delegation, data in ttl_ranges.items():
            avg_latency = statistics.mean(data['latencies'])
            min_latency = min(data['latencies'])
            max_latency = max(data['latencies'])
            stddev = statistics.stdev(data['latencies']) if len(data['latencies']) > 1 else 0

            print(f"\nDelegation: {delegation}")
            print(f"Number of queries: {data['count']}")
            print(f"TTL: {data['ttl']}")
            print(f"Latency statistics (ms):")
            print(f"  Average: {avg_latency:.2f}")
            print(f"  Min: {min_latency:.2f}")
            print(f"  Max: {max_latency:.2f}")
            print(f"  StdDev: {stddev:.2f}")

            avg_list.append(avg_latency)
            min_list.append(min_latency)
            max_list.append(max_latency)
            stddev_list.append(stddev)
            ttl_list.append(data['ttl'])
            count_list.append(data['count'])

            if fd is not None:
                os.write(fd, str.encode(f"\nDelegation: {ttl}\n"))
                os.write(fd, str.encode(f"Number of queries: {data['count']}\n"))
                os.write(fd, str.encode(f"TTL: {data['ttl']}\n"))
                os.write(fd, str.encode(f"Latency statistics (ms):\n"))
                os.write(fd, str.encode(f"  Average: {avg_latency:.2f}\n"))
                os.write(fd, str.encode(f"  Min: {min_latency:.2f}\n"))
                os.write(fd, str.encode(f"  Max: {max_latency:.2f}\n"))
                os.write(fd, str.encode(f"  StdDev: {stddev:.2f}\n"))
            #

    rtt_val = 0.0
    ttl_pct = 0
    #
    with open('data.json', 'w') as f:
        rtt_vals = []
        for ttl_v in ttl_list:
            ttl_pct = ttl_pct + (1/ttl_v)
#            rtt_vals.append(list(numpy.random.uniform(min_v, max_v, 100000)))
        data_dict = {'rtt_values': rtt_vals, 'ttl_odds': f"{ttl_pct:.8f}",
            'avg_list': avg_list, 'min_list': min_list, 'max_list': max_list, 'stddev_list': stddev_list,
            'ttl_list': ttl_list, 'count_list': count_list }
        json.dump(data_dict, f, indent=2)

    ttl_pct = ttl_pct * 100.0
    # likelyhood that any given ttl might expire at any given second
    print(f"ttl_pct={ttl_pct:.5f}")

        

    if fd is not None:
        os.close(fd)
        print(filename)
    return filename
# end query_domain

# main()

# define a parser
parser = argparse.ArgumentParser(prog=sys.argv[0])
parser.add_argument('domains', nargs='+', help="one or more domain names to query") # allow multiple domains
parser.add_argument('-6', '--ipv6', action='store_true', help="query ipv6-only") # ipv6-only
parser.add_argument('-4', '--ipv4', action='store_true', help="query ipv4-only") # ipv4-only
parser.add_argument('-t', '--tcp', action='store_true', help="send queries over TCP") # use TCP
parser.add_argument('-r', '--report', action='store_true', help="Save results to file")
parser.add_argument('-g', '--gt', action='store_true', help="greater than 100ms only")
parser.add_argument('-u', '--upload', action='store_true', help="requires -r - uploads report to hardcoded url")


socket_af_types = [socket.AF_INET, socket.AF_INET6]

args = parser.parse_args()
if args.ipv4:
    socket_af_types = [socket.AF_INET]
if args.ipv6:
    socket_af_types = [socket.AF_INET6]

# XXX Replace me if you are going to use -u flag
url = "https://www.example.com/upload/upload_file.php"

# Iterate through all specified domains
for domain in args.domains:
    print(f"\nProcessing domain: {domain}")
    print("=" * 50)
    fn = query_domain(domain, args, socket_af_types)
    if fn is not None:
        print(f"fn={fn}")
        if args.upload:
            try:
                with open(fn, "rb") as f:
                    post_response = requests.post(
                        url,
                        data={'file': fn},
                        files={'file': f},
                        timeout=10,
                        verify=True
                    )
                    if post_response.status_code == 200:
                        print("Upload successful:", post_response.text)
                        os.unlink(fn)
                    else:
                        print(f"Upload failed with status code: {post_response.status_code}")
            except (requests.RequestException, IOError) as e:
                print(f"Error during upload: {e}")
    print("=" * 50)

#
