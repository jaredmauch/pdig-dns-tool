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
#import json
import os
import requests
import socket
import statistics
import sys
import tempfile
import time

# statistics stuff at the end
# import random
# try:
#     import numpy.random
# except:
#     print("apt install python3-numpy or pip3 install numpy")
#     sys.exit(1)

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
    sys.exit(1)

# apt install python3-netifaces
#try:
#    import netifaces
#except:
#    print("apt install python3-netifaces or pip3 install netifaces")
#    sys.exit(0)

addrinfo_cache = []

addrinfo_cache_hits = 0

def cached_getaddrinfo(hostname, port, family):
    global addrinfo_cache_hits
    for a in addrinfo_cache:
        if a.get('hostname') == hostname and a.get('family') == family:
            addrinfo_cache_hits = addrinfo_cache_hits + 1
            return a.get('cache')
    try:
        add_info = socket.getaddrinfo(host=hostname, port=port, family=family)
    except socket.gaierror as e:
        if e.errno == -2: # Name or service not known
            add_entry = { "hostname": hostname, "family": family, "cache": None }
            addrinfo_cache.append(add_entry)
#        print(f"DNS resolution error for {hostname}: {e.errno}")
        return None
    except socket.error as e:
        print(f"Socket error for {hostname}: {e}")
        return None

    add_entry = { "hostname": hostname, "family": family, "cache": add_info }
    addrinfo_cache.append(add_entry)
    return add_info

# full_qname: domain name to query for
# prev_cache: list of nameservers to query
# qtype_list: is array of possible query types
#     eg: [dns.rdatatype.A, dns.rdatatype.AAAA]
# tcp: when true, send query over tcp
#
def query_all(full_qname, prev_cache, qtype_list, tcp, file_handle, high_latency, ip_list, socket_types):
    """
        query_all handles making the query for each dns server
    """
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
            print(f"{e}:{full_qname}:{qtype}")
            if file_handle is not None:
                os.write(file_handle, str.encode(f"{e}:{full_qname}:{qtype}\n"))
        for x in prev_cache:
            qip = x['addrinfo']
            # Skip problematic IPv6 addresses
            if (qip.startswith('fc') or      # ULA
                qip.startswith('fd') or      # ULA
                qip.startswith('fe80::') or  # Link-local
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
                        resp = dns.query.tcp(q, qip, timeout=3)
                    else:
                        resp =  dns.query.udp(q, qip, timeout=3)
                    stop_time = time.time()

                    latency = stop_time - start_time
                    latency_ms = latency * 1000
                    times.append(latency_ms)

                    if latency_ms > 100 or high_latency is False:
                        print(f"ns={x['qname']}, qtype={dns.rdatatype.to_text(qtype)}, addr={qip}, latency={latency_ms:.3f} ms")
                        if file_handle is not None:
                            os.write(file_handle, str.encode(f"ns={x['qname']}, qtype={dns.rdatatype.to_text(qtype)}, addr={qip}, latency={latency_ms:.3f} ms" + '\n'))

                    if resp.rcode() == dns.rcode.NXDOMAIN:
                        domain_exists = False
                        continue
                    if resp.rcode() != dns.rcode.NOERROR:
                        print(f"{dns.rcode.to_text(resp.rcode())} for {full_qname} at {qip}")
                        continue

                    # parse the response packet
                    # if we are not yet to an authoritative server
                    if not resp.flags & dns.flags.AA or len(resp.answer) > 0 or len(resp.authority) > 0:
                        ttl = None
                        vname = None
#                        print("parsing resp.answer", time.time())
                        for var in resp.answer:
                            ttl = var.ttl
                            vname = str(var.name)
#                            print("var.name=", vname)
                            for i in var.items:
                                if var.rdtype == dns.rdatatype.CNAME:
                                    cname_reply = str(i)
                            if file_handle is not None:
                                os.write(file_handle, str.encode(f"\"{latency_ms:.3f}\";ans=\"{vname}\";qip=\"{qip}\";TTL={ttl}" + '\n'))
                            print(f"\"{latency_ms:.3f}\";ans=\"{vname}\";qip=\"{qip}\";TTL={ttl}")
                        # Store TTL and latency information
                        if ttl is not None:
                            query_stats.append({'latency': latency_ms, 'ttl': ttl, 'nameserver': vname, 'ip': qip})
                        ttl = None
                        vname = None
#                        print("parsing resp.authority", time.time())
                        # parse the authority portion of response packet
                        for var in resp.authority:
                            ttl = var.ttl
                            vname = str(var.name)
#                            print("var.name=", vname)
                            for i in var.items:
                                # check NS responses
                                if type(i) == dns.rdtypes.ANY.NS.NS:
                                    # both address families
                                    for fam in socket_types:
                                        str_name = str(i.to_text())
#                                        print("time=", time.time(), " getaddrinfo:", str_name)
                                        add_info = cached_getaddrinfo(str_name, None, fam)
                                        if add_info is not None:
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


def query_domain(fqdn, cli_args, socket_types, verbose=False):
    """
        query_domain starts the top of the query chain for each domain
    """
    root_hints = []

    all_ips = {}
    all_query_stats = []  # Store all query statistics

    print(f"querying for {fqdn}")

    fd = None
    filename = None
    if cli_args.report:
        filename = cli_args.report
        try:
            fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
            with os.fdopen(fd, 'wb') as f:
                f.write(str.encode(f"querying for {fqdn}\n"))
                ts = time.ctime()
                print(f"start={ts}")
                f.write(str.encode(f"start={ts}\n"))
        except Exception as e:
            print(f"Error creating report file '{filename}': {e}")
            return None

    # preseed the data
    try:
        response = dns.resolver.resolve(".", "NS", lifetime=10, tcp=cli_args.tcp)
        if verbose:
            print(f"[VERBOSE] Successfully resolved root NS records: {response}")
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
                    add_info = socket.getaddrinfo(host=i.to_text(), port=None, family=fam)
                    if verbose:
                        print(f"[VERBOSE] getaddrinfo for {i.to_text()} (family {fam}): {add_info}")
                except socket.gaierror as e:
                    if verbose:
                        print(f"[VERBOSE] socket.gaierror for {i.to_text()} (family {fam}): {e}")
                    continue
                str_name = str(i.to_text())
                for a in add_info:
                    addr_list = a[4]
                    root_hints.append({'qname': str_name, 'af_type': a[0], 'addrinfo': addr_list[0]})
                    if verbose:
                        print(f"[VERBOSE] Added root hint: qname={str_name}, af_type={a[0]}, addrinfo={addr_list[0]}")
    if len(root_hints) == 0:
        print("No root hints found after processing root NS records!")
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
        try:
            fd = os.open(filename, os.O_WRONLY | os.O_APPEND)
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
        except Exception as e:
            print(f"Warning: Could not write to report file: {e}")
        finally:
            os.close(fd)

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

            # Find IP addresses and nameservers associated with min and max latencies
            min_ip = None
            max_ip = None
            min_ns = None
            max_ns = None
            for stat in all_query_stats:
                if stat['nameserver'] == delegation:
                    if stat['latency'] == min_latency:
                        min_ip = stat['ip']
                        # Find the nameserver that maps to this IP
                        for ns_stat in all_query_stats:
                            if ns_stat['ip'] == min_ip:
                                min_ns = ns_stat['nameserver']
                                break
                    if stat['latency'] == max_latency:
                        max_ip = stat['ip']
                        # Find the nameserver that maps to this IP
                        for ns_stat in all_query_stats:
                            if ns_stat['ip'] == max_ip:
                                max_ns = ns_stat['nameserver']
                                break

            print(f"\nDelegation: {delegation}")
            print(f"Number of queries: {data['count']}")
            print(f"TTL: {data['ttl']}")
            print(f"Latency statistics (ms):")
            print(f"  Average: {avg_latency:.2f}")
            print(f"  Min: {min_latency:.2f} (IP: {min_ip}, NS: {min_ns})")
            print(f"  Max: {max_latency:.2f} (IP: {max_ip}, NS: {max_ns})")
            print(f"  StdDev: {stddev:.2f}")

            avg_list.append(avg_latency)
            min_list.append(min_latency)
            max_list.append(max_latency)
            stddev_list.append(stddev)
            ttl_list.append(data['ttl'])
            count_list.append(data['count'])

            if fd is not None:
                os.write(fd, str.encode(f"\nDelegation: {delegation}\n"))
                os.write(fd, str.encode(f"Number of queries: {data['count']}\n"))
                os.write(fd, str.encode(f"TTL: {data['ttl']}\n"))
                os.write(fd, str.encode(f"Latency statistics (ms):\n"))
                os.write(fd, str.encode(f"  Average: {avg_latency:.2f}\n"))
                os.write(fd, str.encode(f"  Min: {min_latency:.2f} (IP: {min_ip}, NS: {min_ns})\n"))
                os.write(fd, str.encode(f"  Max: {max_latency:.2f} (IP: {max_ip}, NS: {max_ns})\n"))
                os.write(fd, str.encode(f"  StdDev: {stddev:.2f}\n"))

##     rtt_val = 0.0
##     ttl_pct = 0
##     #
##     with open('data.json', 'w') as f:
##         rtt_vals = []
##         for ttl_v in ttl_list:
##             ttl_pct = ttl_pct + (1/ttl_v)
## #            rtt_vals.append(list(numpy.random.uniform(min_v, max_v, 100000)))
##         data_dict = {'rtt_values': rtt_vals, 'ttl_odds': f"{ttl_pct:.8f}",
##             'avg_list': avg_list, 'min_list': min_list, 'max_list': max_list, 'stddev_list': stddev_list,
##             'ttl_list': ttl_list, 'count_list': count_list }
##         json.dump(data_dict, f, indent=2)
##
##     ttl_pct = ttl_pct * 100.0
##     # likelyhood that any given ttl might expire at any given second
##     print(f"ttl_pct={ttl_pct:.5f}")

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
parser.add_argument('-r', '--report', metavar='REPORT_FILE', type=str, help="Save results to specified file")
parser.add_argument('-g', '--gt', action='store_true', help="greater than 100ms only")
parser.add_argument('-u', '--upload', action='store_true', help="requires -r - uploads report to hardcoded url")
parser.add_argument('-v', '--verbose', action='store_true', help="enable verbose debugging output")

args = parser.parse_args()

# Validate mutually exclusive arguments
if args.ipv4 and args.ipv6:
    print("Error: Cannot specify both --ipv4 and --ipv6")
    sys.exit(1)

socket_af_types = [socket.AF_INET, socket.AF_INET6]

# XXX Replace me if you are going to use -u flag
url = "https://www.example.com/upload/upload_file.php"

# Iterate through all specified domains
for domain in args.domains:
    print(f"\nProcessing domain: {domain}")
    print("=" * 50)
    fn = query_domain(domain, args, socket_af_types, verbose=args.verbose)
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
                        try:
                            os.unlink(fn)
                        except OSError as e:
                            print(f"Warning: Could not delete temporary file {fn}: {e}")
                    else:
                        print(f"Upload failed with status code: {post_response.status_code}")
                        try:
                            os.unlink(fn)  # Clean up file even on failed upload
                        except OSError:
                            pass
            except (requests.RequestException, IOError) as e:
                print(f"Error during upload: {e}")
                try:
                    os.unlink(fn)  # Clean up file on exception
                except OSError:
                    pass
    print("=" * 50)

# internal statistics
#print(f"addrinfo_cache_hits={addrinfo_cache_hits} - cache size:", len(addrinfo_cache))
