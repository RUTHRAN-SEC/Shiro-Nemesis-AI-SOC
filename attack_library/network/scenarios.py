"""
Network security scenarios (5).
Evidence produced: firewall, DNS, and traffic-summary logs.
IMPORTANT: no packet is ever sent. DoS is a set of fake "traffic samples" (numbers), nothing more.
"""
import string

from attack_library.base import scenario

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433, 3306, 3389, 5432, 5900, 8080, 8443]


@scenario(
    id="port_scan", name="Port scan against Shiro's PC", category="network",
    technique=("T1046", "Network Service Discovery"), severity="MEDIUM",
    description="An outside address probes many ports on Shiro's workstation in a few seconds.",
    objective="Test whether Guardian detects one source touching many ports quickly.",
)
def port_scan(ctx):
    ip = ctx.external_ip()
    n = ctx.count(20, 150)
    ports = ctx.rng.sample(range(20, 9000), n) if n > len(COMMON_PORTS) else COMMON_PORTS[:n]
    return [
        ctx.event("network", "net_connection",
                  {"src_ip": ip, "dst_ip": ctx.employee.workstation_ip, "dst_port": p, "protocol": "tcp",
                   "result": "denied"}, ago=ago, host="firewall-01")
        for p, ago in zip(ports, ctx.spread(n, 22, end_ago=5))
    ]


def _random_label(ctx, length):
    return "".join(ctx.rng.choice(string.ascii_lowercase + string.digits) for _ in range(length))


@scenario(
    id="dns_tunneling", name="DNS tunneling", category="network",
    technique=("T1071.004", "Application Layer Protocol: DNS"), severity="HIGH",
    description="Shiro's PC sends dozens of long, random-looking DNS names to one strange domain (hidden data channel).",
    objective="Test whether Guardian detects DNS queries with long random labels.",
)
def dns_tunneling(ctx):
    domain = ctx.rng.choice(["tunnel-c2.example", "dns-exfil.test", "cdn-update.invalid"])
    n = ctx.count(25, 90)
    return [
        ctx.event("dns", "dns_query",
                  {"qname": f"{_random_label(ctx, ctx.rng.randint(32, 50))}.{domain}", "qtype": "TXT",
                   "src_ip": ctx.employee.workstation_ip}, ago=ago, host="dns-resolver-01")
        for ago in ctx.spread(n, 100, end_ago=5)
    ]


@scenario(
    id="c2_beaconing", name="Command-and-control beaconing", category="network",
    technique=("T1071.001", "Application Layer Protocol: Web Protocols"), severity="HIGH",
    description="Shiro's PC calls the same outside server about once a minute, like malware checking in.",
    objective="Test whether Guardian can spot regular 'heartbeat' connections (a known blind spot).",
)
def c2_beaconing(ctx):
    ip = ctx.external_ip()
    n = ctx.count(12, 20)
    interval = ctx.rng.choice([45, 60, 75])
    events = []
    for i in range(n):
        jitter = ctx.rng.uniform(-3, 3)
        events.append(ctx.event("network", "net_connection",
                                {"src_ip": ctx.employee.workstation_ip, "dst_ip": ip, "dst_port": 443,
                                 "protocol": "tcp", "result": "allowed", "bytes_out": ctx.rng.randint(200, 600)},
                                ago=max(1.0, (n - i) * interval + jitter), host="firewall-01"))
    return events


@scenario(
    id="dos_simulation", name="Denial-of-service traffic spike (simulated numbers)", category="network",
    technique=("T1499", "Endpoint Denial of Service"), severity="HIGH",
    description="The company web server's traffic summary suddenly shows thousands of requests per second. Only numbers - no traffic is sent.",
    objective="Test whether Guardian detects abnormal request-rate spikes.",
)
def dos_simulation(ctx):
    n = ctx.count(6, 16)
    server = ctx.employee.servers["web_app"]["host"]
    events = [ctx.event("network", "traffic_sample", {"server": server, "rps": ctx.rng.randint(30, 80),
                                                       "unique_sources": ctx.rng.randint(5, 20)},
                        ago=ago, host=server, user="-") for ago in (140, 130, 120)]
    for ago in ctx.spread(n, 60, end_ago=5):
        events.append(ctx.event("network", "traffic_sample",
                                {"server": server, "rps": ctx.rng.randint(4000, 15000),
                                 "unique_sources": ctx.rng.randint(200, 900)}, ago=ago, host=server, user="-"))
    return events


@scenario(
    id="data_exfiltration", name="Large outbound data transfer", category="network",
    technique=("T1048", "Exfiltration Over Alternative Protocol"), severity="CRITICAL",
    description="Hundreds of MB leave Shiro's PC for an unknown outside address.",
    objective="Test whether Guardian detects unusually large outbound transfers.",
)
def data_exfiltration(ctx):
    ip = ctx.external_ip()
    n = ctx.count(1, 3)
    return [
        ctx.event("network", "net_transfer",
                  {"src_ip": ctx.employee.workstation_ip, "dst_ip": ip, "dst_zone": "external",
                   "direction": "outbound", "protocol": ctx.rng.choice(["https", "ftp", "sftp"]),
                   "bytes_out": ctx.rng.randint(300, 2000) * 1024 * 1024}, ago=ago, host="firewall-01")
        for ago in ctx.spread(n, 60, end_ago=10)
    ]
