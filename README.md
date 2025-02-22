# pdig-dns-tool
Python implemention of dig that checks all servers recording latency

Many people use dig +trace to check the authorities and delegations, but when you want to check them all, I wanted a easy way to do this but also know per-server, per-address-family (AF_INET6 vs AF_INET), per IP address to make it easier to identify outliers.  This tool will help you with that and give some basic statistics on a per-delegation level.  It also will follow CNAMEs it encounters in the chain, but does it in a "return to the root" sort of way which while not ideal, helps get metrics on what a cold cache client might experience at each delegation point.

I may make a presentation on this for a community like DNS-OARC in the future.

Bugs are mine, contributions are welcome.  It writes out a file in /tmp/ that includes commands that can be passed to a tool like MTR so if you need to identify why some might be poorly routed you can do that.

Example output:
```
querying for www.amazon.com
ns=a.root-servers.net. addr=198.41.0.4, latency=11.636 ms
ns=a.root-servers.net. addr=2001:503:ba3e::2:30, latency=10.948 ms
ns=d.root-servers.net. addr=199.7.91.13, latency=4.851 ms
ns=d.root-servers.net. addr=2001:500:2d::d, latency=5.399 ms
ns=j.root-servers.net. addr=192.58.128.30, latency=10.272 ms
ns=j.root-servers.net. addr=2001:503:c27::2:30, latency=13.218 ms
ns=b.root-servers.net. addr=170.247.170.2, latency=26.688 ms
ns=b.root-servers.net. addr=2801:1b8:10::b, latency=27.936 ms
ns=m.root-servers.net. addr=202.12.27.33, latency=87.245 ms
ns=m.root-servers.net. addr=2001:dc3::35, latency=61.398 ms
ns=h.root-servers.net. addr=198.97.190.53, latency=52.340 ms
ns=h.root-servers.net. addr=2001:500:1::53, latency=38.074 ms
ns=i.root-servers.net. addr=192.36.148.17, latency=23.442 ms
ns=i.root-servers.net. addr=2001:7fe::53, latency=25.205 ms
ns=c.root-servers.net. addr=192.33.4.12, latency=13.017 ms
ns=c.root-servers.net. addr=2001:500:2::c, latency=12.139 ms
ns=g.root-servers.net. addr=192.112.36.4, latency=29.916 ms
ns=g.root-servers.net. addr=2001:500:12::d0d, latency=32.481 ms
ns=l.root-servers.net. addr=199.7.83.42, latency=23.826 ms
ns=l.root-servers.net. addr=2001:500:9f::42, latency=26.094 ms
ns=e.root-servers.net. addr=192.203.230.10, latency=5.092 ms
ns=e.root-servers.net. addr=2001:500:a8::e, latency=5.209 ms
ns=f.root-servers.net. addr=192.5.5.241, latency=5.673 ms
ns=f.root-servers.net. addr=2001:500:2f::f, latency=5.607 ms
ns=k.root-servers.net. addr=193.0.14.129, latency=38.625 ms
ns=k.root-servers.net. addr=2001:7fd::1, latency=43.675 ms
latency: min=4.851 ms max=87.245 ms avg=24.616 ms
stdev=20.113 ms max-min=82.394 max/min=17.99 x latency variance
===================
ns=l.gtld-servers.net. addr=192.41.162.30, latency=12.696 ms
ns=l.gtld-servers.net. addr=2001:500:d937::30, latency=13.207 ms
ns=j.gtld-servers.net. addr=192.48.79.30, latency=12.803 ms
ns=j.gtld-servers.net. addr=2001:502:7094::30, latency=13.904 ms
ns=h.gtld-servers.net. addr=192.54.112.30, latency=18.323 ms
ns=h.gtld-servers.net. addr=2001:502:8cc::30, latency=17.349 ms
ns=d.gtld-servers.net. addr=192.31.80.30, latency=18.136 ms
ns=d.gtld-servers.net. addr=2001:500:856e::30, latency=30.568 ms
ns=b.gtld-servers.net. addr=192.33.14.30, latency=25.896 ms
ns=b.gtld-servers.net. addr=2001:503:231d::2:30, latency=24.350 ms
ns=f.gtld-servers.net. addr=192.35.51.30, latency=14.867 ms
ns=f.gtld-servers.net. addr=2001:503:d414::30, latency=14.309 ms
ns=k.gtld-servers.net. addr=192.52.178.30, latency=8.335 ms
ns=k.gtld-servers.net. addr=2001:503:d2d::30, latency=9.721 ms
ns=m.gtld-servers.net. addr=192.55.83.30, latency=9.733 ms
ns=m.gtld-servers.net. addr=2001:501:b1f9::30, latency=9.405 ms
ns=i.gtld-servers.net. addr=192.43.172.30, latency=14.722 ms
ns=i.gtld-servers.net. addr=2001:503:39c1::30, latency=14.805 ms
ns=g.gtld-servers.net. addr=192.42.93.30, latency=14.300 ms
ns=g.gtld-servers.net. addr=2001:503:eea3::30, latency=14.211 ms
ns=a.gtld-servers.net. addr=192.5.6.30, latency=14.831 ms
ns=a.gtld-servers.net. addr=2001:503:a83e::2:30, latency=27.777 ms
ns=c.gtld-servers.net. addr=192.26.92.30, latency=14.852 ms
ns=c.gtld-servers.net. addr=2001:503:83eb::30, latency=31.442 ms
ns=e.gtld-servers.net. addr=192.12.94.30, latency=17.966 ms
ns=e.gtld-servers.net. addr=2001:502:1ca1::30, latency=31.693 ms
latency: min=8.335 ms max=31.693 ms avg=17.315 ms
stdev=6.940 ms max-min=23.358 max/min=3.80 x latency variance
===================
ns=ns1.amzndns.org. addr=156.154.66.10, latency=21.098 ms
ns=ns1.amzndns.org. addr=2610:a1:1015::10, latency=20.967 ms
ns=ns2.amzndns.org. addr=156.154.150.1, latency=9.764 ms
ns=ns2.amzndns.org. addr=2610:a1:31d1::53, latency=10.915 ms
ns=ns1.amzndns.co.uk. addr=156.154.67.10, latency=21.748 ms
ns=ns1.amzndns.co.uk. addr=2001:502:4612::10, latency=22.743 ms
ns=ns2.amzndns.co.uk. addr=204.74.120.1, latency=23.394 ms
ns=ns2.amzndns.co.uk. addr=2610:a1:32d1::53, latency=41.645 ms
ns=ns1.amzndns.net. addr=156.154.65.10, latency=18.869 ms
ns=ns1.amzndns.net. addr=2610:a1:1014::10, latency=17.709 ms
ns=ns2.amzndns.net. addr=156.154.69.10, latency=21.971 ms
ns=ns2.amzndns.net. addr=2610:a1:1017::10, latency=22.868 ms
ns=ns1.amzndns.com. addr=156.154.64.10, latency=18.789 ms
ns=ns1.amzndns.com. addr=2001:502:f3ff::10, latency=18.293 ms
ns=ns2.amzndns.com. addr=156.154.68.10, latency=18.893 ms
ns=ns2.amzndns.com. addr=2610:a1:1016::10, latency=18.065 ms
latency: min=9.764 ms max=41.645 ms avg=20.483 ms
stdev=6.852 ms max-min=31.881 max/min=4.27 x latency variance
(re)querying for www.amazon.com due to CNAME
===================
ns=a.root-servers.net. addr=198.41.0.4, latency=11.117 ms
ns=a.root-servers.net. addr=2001:503:ba3e::2:30, latency=11.596 ms
ns=d.root-servers.net. addr=199.7.91.13, latency=4.977 ms
ns=d.root-servers.net. addr=2001:500:2d::d, latency=4.313 ms
ns=j.root-servers.net. addr=192.58.128.30, latency=12.675 ms
ns=j.root-servers.net. addr=2001:503:c27::2:30, latency=12.204 ms
ns=b.root-servers.net. addr=170.247.170.2, latency=31.157 ms
ns=b.root-servers.net. addr=2801:1b8:10::b, latency=48.869 ms
ns=m.root-servers.net. addr=202.12.27.33, latency=87.129 ms
ns=m.root-servers.net. addr=2001:dc3::35, latency=60.628 ms
ns=h.root-servers.net. addr=198.97.190.53, latency=49.663 ms
ns=h.root-servers.net. addr=2001:500:1::53, latency=35.854 ms
ns=i.root-servers.net. addr=192.36.148.17, latency=22.324 ms
ns=i.root-servers.net. addr=2001:7fe::53, latency=22.810 ms
ns=c.root-servers.net. addr=192.33.4.12, latency=12.553 ms
ns=c.root-servers.net. addr=2001:500:2::c, latency=12.312 ms
ns=g.root-servers.net. addr=192.112.36.4, latency=29.730 ms
ns=g.root-servers.net. addr=2001:500:12::d0d, latency=27.702 ms
ns=l.root-servers.net. addr=199.7.83.42, latency=26.222 ms
ns=l.root-servers.net. addr=2001:500:9f::42, latency=27.249 ms
ns=e.root-servers.net. addr=192.203.230.10, latency=10.092 ms
ns=e.root-servers.net. addr=2001:500:a8::e, latency=9.993 ms
ns=f.root-servers.net. addr=192.5.5.241, latency=10.664 ms
ns=f.root-servers.net. addr=2001:500:2f::f, latency=9.984 ms
ns=k.root-servers.net. addr=193.0.14.129, latency=41.624 ms
ns=k.root-servers.net. addr=2001:7fd::1, latency=43.470 ms
latency: min=4.313 ms max=87.129 ms avg=26.035 ms
stdev=19.811 ms max-min=82.817 max/min=20.20 x latency variance
===================
ns=l.gtld-servers.net. addr=192.41.162.30, latency=12.398 ms
ns=l.gtld-servers.net. addr=2001:500:d937::30, latency=12.880 ms
ns=j.gtld-servers.net. addr=192.48.79.30, latency=13.131 ms
ns=j.gtld-servers.net. addr=2001:502:7094::30, latency=12.338 ms
ns=h.gtld-servers.net. addr=192.54.112.30, latency=17.431 ms
ns=h.gtld-servers.net. addr=2001:502:8cc::30, latency=18.232 ms
ns=d.gtld-servers.net. addr=192.31.80.30, latency=18.219 ms
ns=d.gtld-servers.net. addr=2001:500:856e::30, latency=31.321 ms
ns=b.gtld-servers.net. addr=192.33.14.30, latency=27.658 ms
ns=b.gtld-servers.net. addr=2001:503:231d::2:30, latency=26.272 ms
ns=f.gtld-servers.net. addr=192.35.51.30, latency=17.859 ms
ns=f.gtld-servers.net. addr=2001:503:d414::30, latency=17.923 ms
ns=k.gtld-servers.net. addr=192.52.178.30, latency=13.401 ms
ns=k.gtld-servers.net. addr=2001:503:d2d::30, latency=12.772 ms
ns=m.gtld-servers.net. addr=192.55.83.30, latency=12.285 ms
ns=m.gtld-servers.net. addr=2001:501:b1f9::30, latency=13.596 ms
ns=i.gtld-servers.net. addr=192.43.172.30, latency=17.448 ms
ns=i.gtld-servers.net. addr=2001:503:39c1::30, latency=17.321 ms
ns=g.gtld-servers.net. addr=192.42.93.30, latency=17.814 ms
ns=g.gtld-servers.net. addr=2001:503:eea3::30, latency=17.834 ms
ns=a.gtld-servers.net. addr=192.5.6.30, latency=18.408 ms
ns=a.gtld-servers.net. addr=2001:503:a83e::2:30, latency=30.435 ms
ns=c.gtld-servers.net. addr=192.26.92.30, latency=18.234 ms
ns=c.gtld-servers.net. addr=2001:503:83eb::30, latency=30.647 ms
ns=e.gtld-servers.net. addr=192.12.94.30, latency=18.079 ms
ns=e.gtld-servers.net. addr=2001:502:1ca1::30, latency=30.763 ms
latency: min=12.285 ms max=31.321 ms avg=19.027 ms
stdev=6.339 ms max-min=19.036 max/min=2.55 x latency variance
===================
ns=ns1.amzndns.org. addr=156.154.66.10, latency=19.706 ms
ns=ns1.amzndns.org. addr=2610:a1:1015::10, latency=19.736 ms
ns=ns2.amzndns.org. addr=156.154.150.1, latency=10.435 ms
ns=ns2.amzndns.org. addr=2610:a1:31d1::53, latency=12.159 ms
ns=ns1.amzndns.co.uk. addr=156.154.67.10, latency=23.990 ms
ns=ns1.amzndns.co.uk. addr=2001:502:4612::10, latency=23.163 ms
ns=ns2.amzndns.co.uk. addr=204.74.120.1, latency=23.391 ms
ns=ns2.amzndns.co.uk. addr=2610:a1:32d1::53, latency=42.568 ms
ns=ns1.amzndns.net. addr=156.154.65.10, latency=18.899 ms
ns=ns1.amzndns.net. addr=2610:a1:1014::10, latency=19.233 ms
ns=ns2.amzndns.net. addr=156.154.69.10, latency=23.250 ms
ns=ns2.amzndns.net. addr=2610:a1:1017::10, latency=23.209 ms
ns=ns1.amzndns.com. addr=156.154.64.10, latency=19.133 ms
ns=ns1.amzndns.com. addr=2001:502:f3ff::10, latency=19.644 ms
ns=ns2.amzndns.com. addr=156.154.68.10, latency=19.920 ms
ns=ns2.amzndns.com. addr=2610:a1:1016::10, latency=21.415 ms
latency: min=10.435 ms max=42.568 ms avg=21.241 ms
stdev=6.835 ms max-min=32.133 max/min=4.08 x latency variance
===================
ns=ns-477.awsdns-59.com. addr=205.251.193.221, latency=9.702 ms
ns=ns-477.awsdns-59.com. addr=2600:9000:5301:dd00::1, latency=23.677 ms
ns=ns-553.awsdns-05.net. addr=205.251.194.41, latency=20.269 ms
ns=ns-553.awsdns-05.net. addr=2600:9000:5302:2900::1, latency=19.028 ms
ns=ns-1404.awsdns-47.org. addr=205.251.197.124, latency=42.392 ms
ns=ns-1404.awsdns-47.org. addr=2600:9000:5305:7c00::1, latency=70.501 ms
ns=ns-1881.awsdns-43.co.uk. addr=205.251.199.89, latency=8.885 ms
ns=ns-1881.awsdns-43.co.uk. addr=2600:9000:5307:5900::1, latency=23.166 ms
latency: min=8.885 ms max=70.501 ms avg=27.203 ms
stdev=20.322 ms max-min=61.615 max/min=7.93 x latency variance
(re)querying for tp.47cf2c8c9-frontier.amazon.com. due to CNAME
===================
ns=a.root-servers.net. addr=198.41.0.4, latency=13.402 ms
ns=a.root-servers.net. addr=2001:503:ba3e::2:30, latency=12.290 ms
ns=d.root-servers.net. addr=199.7.91.13, latency=5.135 ms
ns=d.root-servers.net. addr=2001:500:2d::d, latency=5.173 ms
ns=j.root-servers.net. addr=192.58.128.30, latency=11.861 ms
ns=j.root-servers.net. addr=2001:503:c27::2:30, latency=11.538 ms
ns=b.root-servers.net. addr=170.247.170.2, latency=26.347 ms
ns=b.root-servers.net. addr=2801:1b8:10::b, latency=27.728 ms
ns=m.root-servers.net. addr=202.12.27.33, latency=86.539 ms
ns=m.root-servers.net. addr=2001:dc3::35, latency=61.395 ms
ns=h.root-servers.net. addr=198.97.190.53, latency=49.134 ms
ns=h.root-servers.net. addr=2001:500:1::53, latency=36.202 ms
ns=i.root-servers.net. addr=192.36.148.17, latency=22.478 ms
ns=i.root-servers.net. addr=2001:7fe::53, latency=23.781 ms
ns=c.root-servers.net. addr=192.33.4.12, latency=11.585 ms
ns=c.root-servers.net. addr=2001:500:2::c, latency=11.384 ms
ns=g.root-servers.net. addr=192.112.36.4, latency=33.253 ms
ns=g.root-servers.net. addr=2001:500:12::d0d, latency=37.576 ms
ns=l.root-servers.net. addr=199.7.83.42, latency=24.260 ms
ns=l.root-servers.net. addr=2001:500:9f::42, latency=23.597 ms
ns=e.root-servers.net. addr=192.203.230.10, latency=5.416 ms
ns=e.root-servers.net. addr=2001:500:a8::e, latency=5.532 ms
ns=f.root-servers.net. addr=192.5.5.241, latency=5.924 ms
ns=f.root-servers.net. addr=2001:500:2f::f, latency=5.672 ms
ns=k.root-servers.net. addr=193.0.14.129, latency=38.480 ms
ns=k.root-servers.net. addr=2001:7fd::1, latency=40.694 ms
latency: min=5.135 ms max=86.539 ms avg=24.476 ms
stdev=19.788 ms max-min=81.403 max/min=16.85 x latency variance
===================
ns=m.gtld-servers.net. addr=192.55.83.30, latency=8.617 ms
ns=m.gtld-servers.net. addr=2001:501:b1f9::30, latency=10.165 ms
ns=k.gtld-servers.net. addr=192.52.178.30, latency=10.951 ms
ns=k.gtld-servers.net. addr=2001:503:d2d::30, latency=11.577 ms
ns=b.gtld-servers.net. addr=192.33.14.30, latency=24.774 ms
ns=b.gtld-servers.net. addr=2001:503:231d::2:30, latency=25.753 ms
ns=f.gtld-servers.net. addr=192.35.51.30, latency=15.137 ms
ns=f.gtld-servers.net. addr=2001:503:d414::30, latency=14.903 ms
ns=d.gtld-servers.net. addr=192.31.80.30, latency=15.369 ms
ns=d.gtld-servers.net. addr=2001:500:856e::30, latency=28.727 ms
ns=h.gtld-servers.net. addr=192.54.112.30, latency=14.614 ms
ns=h.gtld-servers.net. addr=2001:502:8cc::30, latency=14.851 ms
ns=j.gtld-servers.net. addr=192.48.79.30, latency=10.851 ms
ns=j.gtld-servers.net. addr=2001:502:7094::30, latency=10.252 ms
ns=l.gtld-servers.net. addr=192.41.162.30, latency=10.487 ms
ns=l.gtld-servers.net. addr=2001:500:d937::30, latency=9.899 ms
ns=a.gtld-servers.net. addr=192.5.6.30, latency=15.483 ms
ns=a.gtld-servers.net. addr=2001:503:a83e::2:30, latency=29.019 ms
ns=e.gtld-servers.net. addr=192.12.94.30, latency=15.419 ms
ns=e.gtld-servers.net. addr=2001:502:1ca1::30, latency=28.552 ms
ns=c.gtld-servers.net. addr=192.26.92.30, latency=15.233 ms
ns=c.gtld-servers.net. addr=2001:503:83eb::30, latency=28.757 ms
ns=g.gtld-servers.net. addr=192.42.93.30, latency=15.438 ms
ns=g.gtld-servers.net. addr=2001:503:eea3::30, latency=16.054 ms
ns=i.gtld-servers.net. addr=192.43.172.30, latency=15.929 ms
ns=i.gtld-servers.net. addr=2001:503:39c1::30, latency=15.619 ms
latency: min=8.617 ms max=29.019 ms avg=16.632 ms
stdev=6.577 ms max-min=20.401 max/min=3.37 x latency variance
===================
ns=ns-666.awsdns-19.net. addr=205.251.194.154, latency=19.971 ms
ns=ns-666.awsdns-19.net. addr=2600:9000:5302:9a00::1, latency=18.881 ms
ns=ns-418.awsdns-52.com. addr=205.251.193.162, latency=8.752 ms
ns=ns-418.awsdns-52.com. addr=2600:9000:5301:a200::1, latency=23.403 ms
ns=ns-1597.awsdns-07.co.uk. addr=205.251.198.61, latency=10.385 ms
ns=ns-1597.awsdns-07.co.uk. addr=2600:9000:5306:3d00::1, latency=24.503 ms
ns=ns-1306.awsdns-35.org. addr=205.251.197.26, latency=42.054 ms
ns=ns-1306.awsdns-35.org. addr=2600:9000:5305:1a00::1, latency=71.455 ms
latency: min=8.752 ms max=71.455 ms avg=27.426 ms
stdev=20.511 ms max-min=62.703 max/min=8.16 x latency variance
===================
ns=ns-1144.awsdns-15.org. addr=205.251.196.120, latency=41.811 ms
ns=ns-1144.awsdns-15.org. addr=2600:9000:5304:7800::1, latency=69.879 ms
ns=ns-130.awsdns-16.com. addr=205.251.192.130, latency=8.307 ms
ns=ns-130.awsdns-16.com. addr=2600:9000:5300:8200::1, latency=22.166 ms
ns=ns-2021.awsdns-60.co.uk. addr=205.251.199.229, latency=8.917 ms
ns=ns-2021.awsdns-60.co.uk. addr=2600:9000:5307:e500::1, latency=23.303 ms
ns=ns-824.awsdns-39.net. addr=205.251.195.56, latency=18.700 ms
ns=ns-824.awsdns-39.net. addr=2600:9000:5303:3800::1, latency=17.506 ms
latency: min=8.307 ms max=69.879 ms avg=26.324 ms
stdev=20.448 ms max-min=61.572 max/min=8.41 x latency variance
===================
end=Thu Feb 20 17:41:01 2025
```
