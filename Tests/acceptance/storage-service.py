#!/usr/bin/python3
"""Storage-service authority: healthy inspection, witness persistence and owned DM fencing.

Run only on a disposable installed host. This does not replace the independent
boot, failed-member return, replacement and owner-recovery acceptance matrix.
"""

import argparse
import configparser
import hashlib
import json
import os
import subprocess
import time
import uuid
from contextlib import ExitStack
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("service", type=Path)
parser.add_argument(
    "--runtime-driver",
    type=Path,
    required=True,
    help="test-only Rust runtime driver provisioned in the disposable fixture",
)
args = parser.parse_args()
assert os.geteuid() == 0, "run only in a disposable native systemd fixture"
args.runtime_driver = args.runtime_driver.resolve(strict=True)
args.service = args.service.resolve(strict=True)
RUNTIME = Path("/run/particleve-admission")
SESSION = RUNTIME / "session.json"
VARIABLE = Path("/sys/firmware/efi/efivars/ParticleVEStorage-59a481c6-fbbc-4d82-8617-37eae6ebdf21")


def runtime(operation, **fields):
    value = subprocess.run(
        [str(args.runtime_driver)],
        input=json.dumps({"operation": operation, **fields}) + "\n",
        capture_output=True,
        text=True,
        timeout=45,
        check=True,
    )
    assert not value.stderr, value.stderr
    response = json.loads(value.stdout)
    assert "ok" in response, response
    return response["ok"]


def load():
    return runtime("admission-load")


text = args.service.read_text()
device_rules = [line for line in text.splitlines() if line.startswith("DeviceAllow=")]
config = configparser.ConfigParser(interpolation=None)
config.optionxform = str
config.read_string("\n".join(line for line in text.splitlines() if not line.startswith("DeviceAllow=")))
assert config["Service"]["ExecStart"] == "/usr/libexec/particleve-storage-admission watch"
properties = [
    "--property=" + key + "=" + value for key, value in config["Service"].items() if key != "ExecStart"
]
properties.extend("--property=" + rule for rule in device_rules)


def run(command, *, check=True):
    value = subprocess.run(command, capture_output=True, text=True, timeout=45)
    if check:
        assert value.returncode == 0 and not value.stderr, (
            command[0],
            value.returncode,
            value.stdout[-1000:],
            value.stderr[-2000:],
        )
    return value


def stop_unit(unit):
    state = run(["systemctl", "show", unit, "--property=LoadState", "--value"]).stdout.strip()
    if state != "not-found":
        run(["systemctl", "stop", unit])


def remove_mapper(name, identity):
    assert (
        run(["dmsetup", "info", "--noheadings", "--columns", "--options=uuid", name]).stdout.strip()
        == identity
    )
    run(["dmsetup", "remove", name])


INNER = r"""import ctypes,errno,json,os,socket,subprocess,sys
from pathlib import Path
SESSION=Path('/run/particleve-admission/session.json')
def request(operation,**fields):
 value=subprocess.run([sys.argv[2]],input=json.dumps({'operation':operation,**fields})+'\n',
  capture_output=True,text=True,timeout=30,check=True)
 assert not value.stderr,value.stderr
 return json.loads(value.stdout)
def runtime(operation,**fields):
 result=request(operation,**fields);assert 'ok' in result,result
 return result['ok']
def load():return runtime('admission-load')
status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
for name in ('CapEff','CapPrm','CapBnd'):assert int(status[name],16)==0x201200,(name,status[name])
for name in ('CapInh','CapAmb'):assert int(status[name],16)==0
assert status['NoNewPrivs'].strip()=='1' and status['Seccomp'].strip()=='2'
assert not status['Groups'].strip() and os.getuid()==os.geteuid()==0
assert os.readlink('/proc/self/ns/net')!=sys.argv[-2]
assert os.readlink('/proc/self/ns/mnt')!=sys.argv[-1]
def command(*argv,check=True):
 value=subprocess.run(argv,capture_output=True,text=True,timeout=10)
 if check:assert value.returncode==0 and not value.stderr,(argv,value.returncode,value.stderr[-1000:])
 return value
mode=sys.argv[1]
if mode=='watch':
 result=runtime('admission-watch')
 assert result['storage_admission']==load()['allowed']
elif mode=='watch-hidden-submount':
 # Reproduce a homed mount visible in findmnt below an inaccessible parent,
 # without touching an actual home. The unit owns this private mount namespace.
 parent=Path('/run/particleve-admission')/('hidden-mount-'+str(os.getpid()))
 parent.mkdir(mode=0o700);view=parent/'view';view.mkdir(mode=0o700);mounted=False
 try:
  command('mount','--bind','/var',str(view));mounted=True
  parent.chmod(0)
  try:fd=os.open(view,os.O_RDONLY|os.O_DIRECTORY)
  except OSError as error:assert error.errno==errno.EACCES,error
  else:os.close(fd);raise AssertionError('fixture mount was not inaccessible')
  table=json.loads(command('findmnt','--json','--list','--types','btrfs',
                           '--output','SOURCE,OPTIONS,TARGET').stdout)
  assert any(m['target']==str(view) for m in table['filesystems'])
  # Shutdown's complete inventory must still refuse an inaccessible mount.
  denied=request('admission-mounts',record=load())
  assert 'Permission denied' in denied.get('error',''),denied
  result=runtime('admission-watch')
  assert result['storage_admission']==load()['allowed']
 finally:
  parent.chmod(0o700)
  if mounted:command('umount',str(view))
  view.rmdir();parent.rmdir()
elif mode=='witness':
 record=load();runtime('witness-save',record=record);assert load()==record
elif mode=='session':
 runtime('session-refresh')
elif mode=='denials':
 for family in (socket.AF_INET,socket.AF_INET6,socket.AF_PACKET):
  try:connection=socket.socket(family)
  except OSError as error:assert error.errno==errno.EAFNOSUPPORT,error
  else:connection.close();raise AssertionError('unexpected socket family allowed')
 paths=(('/var/lib/particleve/installation.json',os.O_WRONLY),
        ('/dev/kvm',os.O_RDONLY),(sys.argv[3],os.O_RDONLY))
 for path,flags in paths:
  try:fd=os.open(path,flags)
  except OSError as error:
   expected=errno.EROFS if path.startswith('/var/') else errno.EPERM
   assert error.errno==expected,(path,error)
  else:os.close(fd);raise AssertionError('unexpected device/state open allowed: '+path)
 escape=Path('/run')/('particleve-storage-escape-'+str(os.getpid()))
 try:fd=os.open(escape,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 except OSError as error:assert error.errno==errno.EROFS,error
 else:os.close(fd);escape.unlink();raise AssertionError('write outside runtime directory allowed')
 library=ctypes.CDLL(None,use_errno=True)
 library.unshare.argtypes=(ctypes.c_int,);library.unshare.restype=ctypes.c_int
 assert library.unshare(0x10000000)==-1 and ctypes.get_errno() in (errno.EPERM,errno.EACCES)
elif mode in ('fence','failed-reload'):
 name,identity=sys.argv[3:5]
 assert name.startswith('particleve-storage-probe-')
 assert command('dmsetup','info','--noheadings','--columns','--options=uuid',name).stdout.strip()==identity
 path='/dev/mapper/'+name
 assert command('blockdev','--getsz',path).stdout.strip()=='2048'
 fd=os.open(path,os.O_RDONLY)
 try:assert os.pread(fd,512,0)==bytes(512)
 finally:os.close(fd)
 command('dmsetup','suspend','--noflush','--nolockfs',name)
 if mode=='failed-reload':
  value=command('dmsetup','reload',name,'--table','0 0 error',check=False)
  assert value.returncode!=0
  state=command('dmsetup','info',name).stdout
  suspended=next(line.split(':',1)[1].strip()
                 for line in state.splitlines() if line.startswith('State:'))
  assert suspended=='SUSPENDED'
 else:
  command('dmsetup','reload',name,'--table','0 2048 error')
  command('dmsetup','resume',name)
  fd=os.open(path,os.O_RDONLY)
  try:
   try:os.pread(fd,512,0)
   except OSError as error:assert error.errno==errno.EIO,error
   else:raise AssertionError('fenced fixture mapper remained readable')
  finally:os.close(fd)
else:raise AssertionError('unknown fixture operation')
evidence={'case':mode,'result':'pass','capabilities':'SYS_ADMIN, LINUX_IMMUTABLE, NET_ADMIN',
 'no_new_privileges':True,'private_network_namespace':True,
 'context':Path('/proc/self/attr/current').read_text().strip('\0\n')}
if mode=='failed-reload':evidence['expected_reload_failure']={'returncode':value.returncode,
                                                            'detail':value.stderr.strip()[:1024]}
print(json.dumps(evidence),flush=True)
"""

witness = VARIABLE.read_bytes()
record = load()
assert record["active"] and record["allowed"]
session = SESSION.read_bytes()
assert json.loads(session)["witness"] == record
lock_inode = (RUNTIME / "maintenance.lock").stat().st_ino
guests = runtime("vm-inventory")
policy = hashlib.sha256(Path("/sys/fs/selinux/policy").read_bytes()).hexdigest()
host_net_namespace = os.readlink("/proc/self/ns/net")
host_mount_namespace = os.readlink("/proc/self/ns/mnt")
manifest = json.loads(Path("/var/lib/particleve/installation.json").read_text())
raw_disk = str(Path(manifest["devices"][0]["path"]).resolve(strict=True))
for path in ("/dev/kvm", raw_disk):
    descriptor = os.open(path, os.O_RDONLY)
    os.close(descriptor)  # Positive controls establish that the nodes can open.
timer = run(["systemctl", "is-active", "particleve-storage-watch.timer"], check=False).stdout.strip()
assert timer in ("active", "inactive")
results = []
with ExitStack() as cleanup:
    # Register restoration first so every owned unit/device cleanup is attempted
    # before the original timer is restored, including when another cleanup fails.
    if timer == "active":
        cleanup.callback(run, ["systemctl", "start", "particleve-storage-watch.timer"])
    run(["systemctl", "stop", "particleve-storage-watch.timer"])
    deadline = time.monotonic() + 15
    while run(
        ["systemctl", "show", "particleve-storage-watch.service", "--property=ActiveState", "--value"]
    ).stdout.strip() in ("active", "activating", "deactivating"):
        assert time.monotonic() < deadline
        time.sleep(0.1)
    for mode in (
        "watch",
        "watch-hidden-submount",
        "witness",
        "session",
        "denials",
        "fence",
        "failed-reload",
    ):
        extra = []
        if mode == "denials":
            extra = [raw_disk]
        if mode in ("fence", "failed-reload"):
            name = "particleve-storage-probe-" + uuid.uuid4().hex
            identity = "PVE-STORAGE-SERVICE-" + uuid.uuid4().hex
            assert not Path("/dev/mapper", name).exists()
            run(["dmsetup", "create", name, "--uuid", identity, "--table", "0 2048 zero"])
            cleanup.callback(remove_mapper, name, identity)
            extra = [name, identity]
        unit = f"particleve-storage-service-{os.getpid()}-{mode}"
        cleanup.callback(stop_unit, unit + ".service")
        started = time.monotonic()
        value = run(
            [
                "systemd-run",
                "--quiet",
                "--collect",
                "--wait",
                "--pipe",
                "--unit=" + unit,
                *properties,
                "/usr/bin/python3",
                "-I",
                "-c",
                INNER,
                mode,
                str(args.runtime_driver),
                *extra,
                host_net_namespace,
                host_mount_namespace,
            ]
        )
        result = json.loads(value.stdout)
        result["wall_seconds"] = time.monotonic() - started
        results.append(result)
        assert VARIABLE.read_bytes() == witness and SESSION.read_bytes() == session
        assert (RUNTIME / "maintenance.lock").stat().st_ino == lock_inode
        print(json.dumps(result), flush=True)
assert VARIABLE.read_bytes() == witness and SESSION.read_bytes() == session
assert runtime("vm-inventory") == guests
assert hashlib.sha256(Path("/sys/fs/selinux/policy").read_bytes()).hexdigest() == policy
print(
    json.dumps(
        {
            "cases": results,
            "service_sha256": hashlib.sha256(args.service.read_bytes()).hexdigest(),
            "runtime_driver": str(args.runtime_driver),
            "witness_session_lock_and_guest_identities_preserved": True,
            "storage_watch_timer_restored": timer,
            "fixture_mappers_removed": True,
            "scope": "healthy monitor and service-operation boundary; failed-member detection/return "
            "and recovery require the separate signed-image matrix",
        }
    ),
    flush=True,
)
