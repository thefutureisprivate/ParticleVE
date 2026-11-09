"""Exercise host-input policy and external forwarding rules in disposable network namespaces."""

import configparser
import errno
import hashlib
import json
import os
import select
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, "/usr/lib/particleve")
from particleve.common import require
from particleve.config import validate
from particleve.linux import image_version
from particleve.vms import LinuxVMs

require(os.geteuid() == 0, "run on the disposable ParticleVE host as root")
version = image_version()
prefix = f"pvnet-{os.getpid()}-"
namespaces = []
root_links = set()
servers = []
results = []
unit = f"particleve-firewall-acceptance-{os.getpid()}.service"
service_path = Path("/usr/lib/systemd/system/particleve-firewall.service")
service = configparser.ConfigParser(interpolation=None)
service.optionxform = str
service.read_string(service_path.read_text())
require(service["Service"]["ExecStart"] == "/usr/bin/particleve apply-firewall", "unexpected loader")
config = validate(json.loads(Path("/etc/particleve/host.json").read_text()))
management_name = config["network"]["management"]
config["network"]["allowed_sources"] = ["10.233.0.2/32", "fd23:33:0::2/128"]
validate(config)
require(Path("/dev/kvm").exists(), "positive host-device visibility control is missing")
guest_inventory = LinuxVMs().inventory(inhibited=False)
firewall_before = subprocess.check_output(["nft", "--stateless", "list", "ruleset"], text=True)
authority = None
settings = tempfile.TemporaryDirectory(prefix="particleve-firewall-acceptance-", dir="/run")


def run(command, **kwargs):
    kwargs.setdefault("timeout", 30)
    result = subprocess.run(command, capture_output=True, text=True, **kwargs)
    require(result.returncode == 0 and not result.stderr, f"{command[0]} failed: {result.stderr}")
    return result.stdout


def inside(name, command, **kwargs):
    return run(["ip", "netns", "exec", prefix + name, *command], **kwargs)


def namespace(name):
    run(["ip", "netns", "add", prefix + name])
    namespaces.append(prefix + name)
    run(["ip", "-n", prefix + name, "link", "set", "lo", "up"])


def connect(client, host_interface, subnet, number):
    left, right = f"pvn{os.getpid()}{number}a", f"pvn{os.getpid()}{number}b"
    run(["ip", "link", "add", left, "type", "veth", "peer", "name", right])
    root_links.update((left, right))
    for link, target, final in ((left, "host", host_interface), (right, client, "eth0")):
        run(["ip", "link", "set", link, "netns", prefix + target])
        root_links.remove(link)
        run(["ip", "-n", prefix + target, "link", "set", link, "name", final])
        run(["ip", "-n", prefix + target, "link", "set", final, "up"])
    for target, device, suffix in (("host", host_interface, 1), (client, "eth0", 2)):
        run(["ip", "-n", prefix + target, "addr", "add", f"10.233.{subnet}.{suffix}/30", "dev", device])
        run(
            [
                "ip",
                "-n",
                prefix + target,
                "-6",
                "addr",
                "add",
                f"fd23:33:{subnet}::{suffix}/64",
                "dev",
                device,
                "nodad",
            ]
        )
    run(["ip", "-n", prefix + client, "route", "add", "default", "via", f"10.233.{subnet}.1"])
    run(["ip", "-n", prefix + client, "-6", "route", "add", "default", "via", f"fd23:33:{subnet}::1"])


SERVER = """import select,socket,sys
sockets=[]
for port in map(int,sys.argv[1:]):
 for family,address in ((socket.AF_INET,'0.0.0.0'),(socket.AF_INET6,'::')):
  s=socket.socket(family)
  s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
  if family==socket.AF_INET6:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
  s.bind((address,port));s.listen(8);sockets.append(s)
print('ready',flush=True)
while True:
 for s in select.select(sockets,[],[])[0]:
  c,_=s.accept()
  with c:c.sendall(b'particleve-acceptance-network')
"""
CLIENT = """import errno,json,socket,sys
try:
 with socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=2) as s:
  received=b''
  while chunk:=s.recv(64):
   received+=chunk
   assert len(received)<=64
  assert received==b'particleve-acceptance-network'
 print(json.dumps({'connected':True}))
except TimeoutError:print(json.dumps({'connected':False,'errno':errno.ETIMEDOUT}))
except OSError as exc:print(json.dumps({'connected':False,'errno':exc.errno}))
"""

LOADER = r"""import ctypes,errno,json,os,socket
from pathlib import Path
status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
for name in ('CapPrm','CapEff','CapBnd'):
 assert int(status[name],16)==1<<12,(name,status[name])
for name in ('CapInh','CapAmb'):
 assert int(status[name],16)==0,(name,status[name])
assert status['NoNewPrivs'].strip()=='1' and status['Seccomp'].strip()=='2'
assert not status['Groups'].strip()
assert os.getuid()==os.geteuid()==0
for family in (socket.AF_INET,socket.AF_INET6):
 try:connection=socket.socket(family)
 except OSError as error:assert error.errno==errno.EAFNOSUPPORT,error
 else:connection.close();raise AssertionError('IP socket available to rule loader')
try:fd=os.open('/var/lib/particleve/installation.json',os.O_WRONLY)
except OSError as error:assert error.errno==errno.EROFS,error
else:os.close(fd);raise AssertionError('persistent state writable by rule loader')
assert not Path('/dev/kvm').exists()
with open('/dev/null','wb') as device:device.write(b'public fixture control')
library=ctypes.CDLL(None,use_errno=True)
library.unshare.argtypes=(ctypes.c_int,);library.unshare.restype=ctypes.c_int
assert library.unshare(0x10000000)==-1 and ctypes.get_errno()==errno.EPERM
print(json.dumps({'capabilities':'CAP_NET_ADMIN only','no_new_privileges':True,'seccomp':True,
 'ip_socket_creation':'denied for IPv4 and IPv6','persistent_state_write_open':'denied',
 'host_device_visibility':'denied','user_namespace_creation':'denied',
 'context':Path('/proc/self/attr/current').read_text().strip('\0\n')}),flush=True)
os.execv('/usr/bin/particleve',['/usr/bin/particleve','apply-firewall'])
"""


def serve(name, ports):
    child = subprocess.Popen(
        ["ip", "netns", "exec", prefix + name, "python3", "-u", "-c", SERVER, *map(str, ports)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    servers.append(child)
    require(select.select([child.stdout], [], [], 5)[0], "test listener did not become ready")
    require(child.stdout.readline().strip() == "ready", "test listener failed to bind")


def probe(name, destination, port, allowed, purpose):
    result = json.loads(inside(name, ["python3", "-c", CLIENT, destination, str(port)]))
    require(result["connected"] == allowed, f"unexpected {purpose} result: {result}")
    if not allowed:
        require(
            result["errno"] == errno.ETIMEDOUT, f"probe failed without reaching the drop policy: {result}"
        )
    results.append({"case": purpose, "destination": destination, "port": port, "allowed": allowed})


try:
    config_path = Path(settings.name) / "host.json"
    config_path.write_text(json.dumps(config))
    config_path.chmod(0o600)
    for name in ("host", "management", "guest", "destination"):
        namespace(name)
    connect("management", management_name, 0, 0)
    connect("guest", "guest0", 1, 1)
    connect("destination", "uplink0", 2, 2)
    inside("host", ["sysctl", "-w", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1"])
    # Reuse the installed service's authority. Only its namespace, read-only
    # configuration view, and post-test lifetime differ from the production unit.
    properties = [
        "--property=" + key + "=" + value
        for key, value in service["Service"].items()
        if key not in {"ExecStart", "RemainAfterExit"}
    ]
    loaded = run(
        [
            "systemd-run",
            "--quiet",
            "--collect",
            "--wait",
            "--pipe",
            "--unit=" + unit,
            *properties,
            "--property=RemainAfterExit=no",
            "--property=TimeoutStartSec=30s",
            "--property=NetworkNamespacePath=/run/netns/" + prefix + "host",
            "--property=BindReadOnlyPaths=" + str(config_path) + ":/etc/particleve/host.json",
            "/usr/bin/python3",
            "-I",
            "-c",
            LOADER,
        ],
        timeout=40,
    )
    authority_text, loaded_text = loaded.split("\n", 1)
    authority = json.loads(authority_text)
    require(json.loads(loaded_text) == {"firewall": "active"}, "installed rule loader did not complete")
    # Production forwarding remains externally owned. This isolated policy is
    # supplied by the acceptance fixture, separately from host-input rendering.
    inside(
        "host",
        ["nft", "-f", "-"],
        input="""table inet acceptance_external {
 chain forward {
  type filter hook forward priority 0; policy drop;
  iifname "guest0" ip saddr != 10.233.1.2 drop
  iifname "guest0" ip6 saddr != fd23:33:1::2 drop
  ct state established,related accept
  iifname "guest0" oifname "uplink0" ip daddr 10.233.2.2 tcp dport 443 accept
  iifname "guest0" oifname "uplink0" ip6 daddr fd23:33:2::2 tcp dport 443 accept
 }
}
""",
    )
    serve("host", [22])
    serve("destination", [22, 443])
    for management, host_guest, destination in (
        ("10.233.0.1", "10.233.1.1", "10.233.2.2"),
        ("fd23:33:0::1", "fd23:33:1::1", "fd23:33:2::2"),
    ):
        probe("management", management, 22, True, "authorized management")
        probe("guest", host_guest, 22, False, "guest input denied")
        probe("guest", management, 22, False, "guest management path denied")
        probe("host", destination, 22, True, "denied-port listener positive control")
        probe("guest", destination, 443, True, "external forwarding allowed")
        probe("guest", destination, 22, False, "external forwarding denied")
finally:
    if (
        subprocess.check_output(
            ["systemctl", "show", unit, "--property=LoadState", "--value"], text=True
        ).strip()
        != "not-found"
    ):
        run(["systemctl", "stop", unit])
    for child in servers:
        child.terminate()
        child.wait(timeout=5)
        child.stdout.close()
        child.stderr.close()
    for name in reversed(namespaces):
        run(["ip", "netns", "delete", name])
    # Only a partially constructed pair can remain in the initial namespace.
    for link in root_links:
        present = subprocess.run(["ip", "link", "show", link], capture_output=True).returncode == 0
        if present:
            run(["ip", "link", "delete", link])
    settings.cleanup()
require(LinuxVMs().inventory(inhibited=False) == guest_inventory, "existing guests changed")
require(
    run(["nft", "--stateless", "list", "ruleset"]) == firewall_before,
    "host firewall changed",
)
print(
    json.dumps(
        {
            "image": version,
            "network_acceptance": results,
            "firewall_loader_authority": authority,
            "service_sha256": hashlib.sha256(service_path.read_bytes()).hexdigest(),
            "temporary_topology_removed": True,
            "existing_guests_and_host_firewall_unchanged": True,
        }
    )
)
