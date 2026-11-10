#!/usr/bin/python3
"""Exercise native Fedora trust extraction and both first-party HTTPS clients.

Run as uid 0 inside an explicitly disposable, rootless Fedora container, with
only public source and the compiled contract driver mounted read-only. This
probe changes that container's CA inputs/outputs, never the desktop trust store.
It establishes component behavior, not NTS, resolved or signed-image acceptance.
"""

import argparse
import hashlib
import http.server
import json
import os
import secrets
import shutil
import ssl
import subprocess
import tempfile
import threading
import urllib.error
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from particleve.common import require
from Tools.publication import request

BUNDLE = Path("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem")
SOURCE = Path("/etc/pki/ca-trust/source")
PAYLOAD = b"ParticleVE native system trust acceptance\n"


def run(arguments):
    return subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=30)


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require_disposable_container(particleve_layout):
    require(os.geteuid() == 0, "run as uid 0 inside the disposable rootless container")
    require(Path("/run/.containerenv").is_file(), "this probe requires a disposable Podman container")
    mapping = [line.split() for line in Path("/proc/self/uid_map").read_text().splitlines()]
    require(
        mapping and mapping[0][0] == "0" and mapping[0][1] != "0",
        "use a rootless container; host uid 0 must not be mapped",
    )
    require(
        not Path("/var/lib/particleve/installation.json").exists(),
        "do not run this component probe on an installed host",
    )
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        mount = Path(line.split()[4])
        for boundary in (Path("/etc"), Path("/usr/share/pki")):
            require(
                mount == Path("/") or not boundary.is_relative_to(mount),
                "a trust-input ancestor is mounted from outside the container",
            )
        require(
            not mount.is_relative_to("/etc/pki") and not mount.is_relative_to("/usr/share/pki"),
            "do not bind-mount trust inputs or outputs into this container",
        )
    directories = (Path("/etc/pki"), SOURCE, SOURCE / "anchors", SOURCE / "blocklist")
    if particleve_layout:
        require(
            Path("/etc/pki/ca-trust/extracted").readlink() == Path("/run/particleve-ca-trust/extracted")
            and Path("/etc/pki/tls/certs").readlink()
            == Path("/run/particleve-ca-trust/extracted/pem/directory-hash"),
            "use the reviewed ParticleVE shared trust aliases",
        )
    else:
        directories += tuple(BUNDLE.parents[:-2])
    for path in directories:
        require(path.is_dir() and not path.is_symlink(), "use native Fedora's container-local CA layout")
    require(BUNDLE.is_file() and not BUNDLE.is_symlink(), "use the native Fedora extracted bundle")


def certificates(directory):
    for name in ("authority", "other"):
        run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-noenc",
                "-keyout",
                directory / f"{name}.key",
                "-out",
                directory / f"{name}.pem",
                "-subj",
                f"/CN=Disposable ParticleVE {name}",
                "-days",
                "2",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-addext",
                "subjectKeyIdentifier=hash",
            ]
        )
    run(
        [
            "openssl",
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-noenc",
            "-keyout",
            directory / "server.key",
            "-out",
            directory / "server.csr",
            "-subj",
            "/CN=localhost",
        ]
    )
    for name, authority, hostname in (
        ("trusted", "authority", "localhost"),
        ("wrong-name", "authority", "wrong.invalid"),
        ("unknown", "other", "localhost"),
    ):
        extensions = directory / f"{name}.ext"
        extensions.write_text(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
            "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n"
            f"extendedKeyUsage=serverAuth\nsubjectAltName=DNS:{hostname}\n"
        )
        run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                directory / "server.csr",
                "-CA",
                directory / f"{authority}.pem",
                "-CAkey",
                directory / f"{authority}.key",
                "-CAcreateserial",
                "-out",
                directory / f"{name}.pem",
                "-days",
                "2",
                "-sha256",
                "-extfile",
                extensions,
            ]
        )
    (directory / "issued").mkdir()
    (directory / "index").write_text("")
    (directory / "serial").write_text("01\n")
    (directory / "ca.cnf").write_text(
        f"[ca]\ndefault_ca=fixture\n[fixture]\ndatabase={directory}/index\n"
        f"new_certs_dir={directory}/issued\nserial={directory}/serial\n"
        f"private_key={directory}/authority.key\ncertificate={directory}/authority.pem\n"
        "default_md=sha256\npolicy=names\nx509_extensions=leaf\n[names]\ncommonName=supplied\n"
        "[leaf]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n"
        "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n"
    )
    run(
        [
            "openssl",
            "ca",
            "-batch",
            "-notext",
            "-config",
            directory / "ca.cnf",
            "-startdate",
            "20200101000000Z",
            "-enddate",
            "20210101000000Z",
            "-in",
            directory / "server.csr",
            "-out",
            directory / "expired.pem",
        ]
    )
    # Establish that the positive certificate satisfies the strict native
    # verifier before using any TLS failure as evidence about trust inputs.
    run(
        [
            "openssl",
            "verify",
            "-x509_strict",
            "-purpose",
            "sslserver",
            "-verify_hostname",
            "localhost",
            "-CAfile",
            directory / "authority.pem",
            directory / "trusted.pem",
        ]
    )


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append(self.path)
        self.send_response(200)
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.end_headers()
        self.wfile.write(PAYLOAD)

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        require(0 < length <= 65536, "invalid report length")
        require(
            self.headers["Authorization"] == "Bearer ParticleVE-disposable-trust-check00",
            "report did not carry the disposable credential",
        )
        require(json.loads(self.rfile.read(length)) == {"schema": 1, "result": "healthy"}, "report changed")
        self.server.requests.append(self.path)
        self.send_response(202)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, _format, *_arguments):
        pass


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = False

    def __init__(self, directory, certificate):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(directory / f"{certificate}.pem", directory / "server.key")
        self.requests = []
        self.rejections = []
        self.rejection_seen = threading.Event()
        super().__init__(("127.0.0.1", 0), Handler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(5)
        try:
            return self.context.wrap_socket(connection, server_side=True), address
        except ssl.SSLError as error:
            self.rejections.append(str(error))
            self.rejection_seen.set()
            connection.close()
            raise
        except BaseException:
            connection.close()
            raise


@contextmanager
def server(directory, certificate):
    with Server(directory, certificate) as endpoint:
        thread = threading.Thread(target=endpoint.serve_forever, kwargs={"poll_interval": 0.02})
        thread.start()
        try:
            yield endpoint, f"https://localhost:{endpoint.server_port}/acceptance"
        finally:
            endpoint.shutdown()
            thread.join(timeout=10)
            require(not thread.is_alive(), "TLS fixture did not terminate")


def clients(directory, driver, certificate, expected, environment):
    results = {}
    for name in ("rust-release-download", "rust-health-delivery", "python-publication-request"):
        diagnostic = ""
        with server(directory, certificate) as (endpoint, url):
            destination = directory / "download"
            destination.unlink(missing_ok=True)
            if name.startswith("rust-"):
                operation = "system-tls-download" if name == "rust-release-download" else "system-tls-report"
                response = subprocess.run(
                    [driver],
                    input=json.dumps({"operation": operation, "url": url, "destination": str(destination)})
                    + "\n",
                    text=True,
                    capture_output=True,
                    timeout=20,
                    check=True,
                    env=os.environ | environment,
                )
                require(not response.stderr, "unexpected Rust driver diagnostic")
                result = json.loads(response.stdout)
                require(len(result) == 1 and next(iter(result)) in ("ok", "error"), "invalid driver response")
                accepted = "ok" in result
                diagnostic = result.get("error", "")
                if accepted and name == "rust-release-download":
                    require(destination.read_bytes() == PAYLOAD, "Rust download payload changed")
                elif accepted:
                    require(
                        result["ok"] == {"delivered": True, "http_status": 202, "report_result": "healthy"},
                        "native reporter did not acknowledge delivery",
                    )
                else:
                    require(not destination.exists(), "a rejected download published an output")
            else:
                try:
                    with patch.dict(os.environ, environment):
                        payload = request(url, size_limit=65536)
                    require(payload == PAYLOAD, "Python publication payload changed")
                    accepted = True
                except urllib.error.URLError as error:
                    require(
                        isinstance(error.reason, ssl.SSLCertVerificationError),
                        "failure was not TLS verification",
                    )
                    accepted = False
                    diagnostic = str(error.reason)
            require(accepted == expected, f"{name}: unexpected TLS outcome for {certificate}: {diagnostic}")
            if expected:
                require(
                    endpoint.requests == ["/acceptance"], "TLS success did not reach the actual HTTP server"
                )
            else:
                # Observe the server side too, so an absent bundle, parse failure or
                # crashed driver cannot stand in for certificate rejection.
                require(endpoint.rejection_seen.wait(5), "server did not observe TLS rejection")
                require(not endpoint.requests and endpoint.rejections, "rejected peer reached HTTP")
            results[name] = {
                "accepted": accepted,
                "http_requests": len(endpoint.requests),
                "tls_rejections": len(endpoint.rejections),
                "verification_error": diagnostic if not accepted else None,
            }
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-driver", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--system-trust-helper", type=Path, help="compiled helper for the ParticleVE layout")
    parser.add_argument("--confirm-disposable-container", action="store_true", required=True)
    args = parser.parse_args()
    require_disposable_container(args.system_trust_helper is not None)
    require(
        len(args.source_revision) == 40 and all(c in "0123456789abcdef" for c in args.source_revision),
        "record the complete source revision",
    )
    driver = args.runtime_driver.resolve(strict=True)
    with driver.open("rb") as binary:
        require(binary.read(4) == b"\x7fELF", "use the compiled Rust contract driver")
    baseline = sha256(BUNDLE)
    result = {
        "source_revision": args.source_revision,
        "runtime_driver_sha256": sha256(driver),
        "probe_sha256": sha256(Path(__file__)),
        "layout": "particleve" if args.system_trust_helper else "native-fedora",
        "system_trust_helper_sha256": sha256(args.system_trust_helper) if args.system_trust_helper else None,
        "packages": run(["rpm", "-q", "ca-certificates", "p11-kit", "p11-kit-trust"]).stdout.splitlines(),
        "baseline_bundle_sha256": baseline,
        "cases": {},
        "scope": "Native extraction and Rust/Python HTTPS components; no NTS, DoT or image acceptance",
    }
    name = "particleve-acceptance-" + secrets.token_hex(12) + ".pem"
    anchor, blocklist = SOURCE / "anchors" / name, SOURCE / "blocklist" / name
    require(not anchor.exists() and not blocklist.exists(), "fixture trust-input name collision")
    with tempfile.TemporaryDirectory(prefix="particleve-ca-", dir="/run") as temporary:
        directory = Path(temporary)
        certificates(directory)
        environment = {
            "SSL_CERT_FILE": str(directory / "other.pem"),
            "SSL_CERT_DIR": str(directory / "alternate"),
            "REQUESTS_CA_BUNDLE": str(directory / "other.pem"),
            "CURL_CA_BUNDLE": str(directory / "other.pem"),
            "HTTPS_PROXY": "",
            "HTTP_PROXY": "",
            "ALL_PROXY": "",
            "https_proxy": "",
            "http_proxy": "",
            "all_proxy": "",
            "NO_PROXY": "localhost",
        }
        (directory / "alternate").mkdir()
        shutil.copyfile(directory / "other.pem", directory / "alternate/other.pem")
        run(["openssl", "rehash", directory / "alternate"])

        def probe(label, certificate, expected):
            result["cases"][label] = {
                "bundle_sha256": sha256(BUNDLE),
                "clients": clients(directory, driver, certificate, expected, environment),
            }

        def extract():
            run([args.system_trust_helper] if args.system_trust_helper else ["update-ca-trust", "extract"])

        try:
            probe("unknown-despite-alternate-store-overrides", "unknown", False)
            probe("untrusted-before-addition", "trusted", False)
            shutil.copyfile(directory / "authority.pem", anchor)
            extract()
            probe("authorized-anchor-extracted", "trusted", True)
            probe("wrong-endpoint-name", "wrong-name", False)
            probe("expired-leaf", "expired", False)
            probe("other-authority-still-rejected", "unknown", False)
            anchor.unlink()
            # Native generated bundles retain the old root until extraction.
            # This records the refresh boundary, not acceptance of stale outputs.
            probe("removed-anchor-before-refresh-observation", "trusted", True)
            extract()
            probe("removed-anchor-after-refresh", "trusted", False)
            shutil.copyfile(directory / "authority.pem", anchor)
            shutil.copyfile(directory / "authority.pem", blocklist)
            extract()
            probe("explicit-distrust-overrides-anchor", "trusted", False)
            blocklist.unlink()
            extract()
            probe("distrust-removed-after-refresh", "trusted", True)
            BUNDLE.write_bytes(b"stale or corrupt extracted trust output\n")
            # Test repair with the real Fedora extractor. Invalid-bundle refusal
            # is distinct from a peer certificate-verification failure.
            extract()
            probe("stale-output-regenerated", "trusted", True)
        finally:
            anchor.unlink(missing_ok=True)
            blocklist.unlink(missing_ok=True)
            extract()
            require(sha256(BUNDLE) == baseline, "fixture did not restore its original system trust")
    result["restored_bundle_sha256"] = sha256(BUNDLE)
    result["result"] = "pass"
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
