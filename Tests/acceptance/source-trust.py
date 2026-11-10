#!/usr/bin/python3
"""Exercise real pinned Git HTTPS fetches through the native shared CA lifecycle.

Use an explicit disposable rootless Fedora container, like system-trust.py.
Only public ephemeral Git objects and that container's CA inputs are changed.
"""

import argparse
import hashlib
import http.server
import json
import os
import runpy
import secrets
import shutil
import subprocess
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from particleve.common import Error, require
from Tools.sourcegit import environment, fetch, git

fixture = runpy.run_path(Path(__file__).with_name("system-trust.py"), run_name="fixture")


class Handler(http.server.BaseHTTPRequestHandler):
    def handle(self):
        try:
            super().handle()
        except (ConnectionResetError, BrokenPipeError) as error:
            # libcurl can close the stream after certificate verification
            # without sending an alert. Retain that observation explicitly.
            self.server.peer_closures.append(type(error).__name__)

    def serve_git(self):
        self.server.requests.append(self.path)
        if self.server.redirect:
            self.send_response(301)
            self.send_header(
                "Location", f"https://localhost:{self.server.server_port}/repository.git/redirected"
            )
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        path = urlsplit(self.path)
        require(path.path.startswith("/repository.git/"), "unexpected Git fixture path")
        length = int(self.headers.get("Content-Length", "0"))
        require(0 <= length <= 65536, "oversized Git fixture request")
        protocol = self.headers.get("Git-Protocol", "")
        require(len(protocol) <= 256, "oversized Git protocol selection")
        result = subprocess.run(
            [self.server.backend],
            input=self.rfile.read(length),
            capture_output=True,
            check=True,
            timeout=10,
            env=environment()
            | {
                "GIT_PROJECT_ROOT": str(self.server.root),
                "GIT_HTTP_EXPORT_ALL": "1",
                "GIT_PROTOCOL": protocol,
                "REQUEST_METHOD": self.command,
                "PATH_INFO": path.path,
                "QUERY_STRING": path.query,
                "CONTENT_TYPE": self.headers.get("Content-Type", ""),
                "CONTENT_LENGTH": str(length),
                "REMOTE_ADDR": "127.0.0.1",
            },
        )
        require(not result.stderr and len(result.stdout) <= 1024 * 1024, "invalid Git backend response")
        headers, body = result.stdout.split(b"\r\n\r\n", 1)
        parsed = [line.decode("ascii").split(":", 1) for line in headers.split(b"\r\n")]
        status = next((int(value.split()[0]) for key, value in parsed if key.lower() == "status"), 200)
        self.send_response(status)
        for key, value in parsed:
            if key.lower() != "status":
                self.send_header(key, value.strip())
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.serve_git()

    def do_POST(self):
        self.serve_git()

    def log_message(self, _format, *_arguments):
        pass


class Server(fixture["Server"]):
    def __init__(self, directory, certificate, repository):
        super().__init__(directory, certificate)
        self.RequestHandlerClass = Handler
        self.root = repository.parent
        self.connections = 0
        self.peer_closures = []
        self.redirect = False
        self.backend = Path(git(repository, "--exec-path").stdout.strip()) / "git-http-backend"
        require(self.backend.is_file(), "install Fedora git-core with its native HTTP backend")

    def get_request(self):
        self.connections += 1
        return super().get_request()


@contextmanager
def server(directory, certificate, repository):
    with Server(directory, certificate, repository) as endpoint:
        thread = threading.Thread(target=endpoint.serve_forever, kwargs={"poll_interval": 0.02})
        thread.start()
        try:
            yield endpoint, f"https://localhost:{endpoint.server_port}/repository.git"
        finally:
            endpoint.shutdown()
            thread.join(timeout=10)
            require(not thread.is_alive(), "Git TLS server did not terminate")


def repository(root):
    path = root / "repository.git"
    path.mkdir()
    git(path, "init", "--bare", "--quiet", "--initial-branch=source")
    blob = git(path, "hash-object", "-w", "--stdin", input="Public pinned source fixture\n").stdout.strip()
    tree = git(path, "mktree", input=f"100644 blob {blob}\tpayload\n").stdout.strip()
    commit = git(
        path,
        "-c",
        "user.name=Source fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit-tree",
        tree,
        input="Public pinned source fixture\n",
    ).stdout.strip()
    git(path, "update-ref", "refs/heads/source", commit)
    return path, commit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--system-trust-helper", type=Path, required=True)
    parser.add_argument("--confirm-disposable-container", action="store_true", required=True)
    args = parser.parse_args()
    fixture["require_disposable_container"](True)
    baseline = fixture["sha256"](fixture["BUNDLE"])
    name = "particleve-git-" + secrets.token_hex(12) + ".pem"
    anchor = fixture["SOURCE"] / "anchors" / name
    blocklist = fixture["SOURCE"] / "blocklist" / name
    require(not anchor.exists() and not blocklist.exists(), "Git fixture trust-input collision")
    observations = {}
    with tempfile.TemporaryDirectory(prefix="particleve-git-trust-", dir="/run") as temporary:
        directory = Path(temporary)
        fixture["certificates"](directory)
        source, revision = repository(directory)
        alternate = directory / "alternate"
        alternate.mkdir()
        shutil.copyfile(directory / "other.pem", alternate / "root.pem")
        fixture["run"](["openssl", "rehash", alternate])
        injected = directory / "injected.gitconfig"

        def check(label, certificate, expected):
            with tempfile.TemporaryDirectory(dir=directory) as clone:
                destination = Path(clone)
                git(destination, "init", "--quiet", "--initial-branch=source")
                with server(directory, certificate, source) as (endpoint, url):
                    git(destination, "config", f"http.{url}.sslVerify", "false")
                    git(destination, "config", f"http.{url}.sslCAInfo", str(directory / "other.pem"))
                    injected.write_text(f'[http "{url}"]\nsslVerify=false\n')
                    overrides = {
                        "GIT_CONFIG_GLOBAL": str(injected),
                        "GIT_CONFIG_COUNT": "1",
                        "GIT_CONFIG_KEY_0": f"http.{url}.sslVerify",
                        "GIT_CONFIG_VALUE_0": "false",
                        "GIT_SSL_NO_VERIFY": "1",
                        "GIT_SSL_CAINFO": str(directory / "other.pem"),
                        "GIT_SSL_CAPATH": str(alternate),
                        "SSL_CERT_FILE": str(directory / "other.pem"),
                        "SSL_CERT_DIR": str(alternate),
                        "CURL_CA_BUNDLE": str(directory / "other.pem"),
                    }
                    diagnostic = ""
                    try:
                        with patch.dict(os.environ, overrides):
                            fetch(destination, url, revision)
                        accepted = True
                    except Error as error:
                        accepted, diagnostic = False, str(error)
                    require(accepted == expected, f"{label}: unexpected Git TLS result: {diagnostic}")
                    if expected:
                        actual = git(destination, "rev-parse", "FETCH_HEAD^{commit}").stdout.strip()
                        require(
                            actual == revision and endpoint.requests, "Git did not fetch the pinned source"
                        )
                        require(
                            git(destination, "show", "FETCH_HEAD:payload").stdout
                            == "Public pinned source fixture\n",
                            "fetched Git contents differ from the selected revision",
                        )
                    else:
                        failure = diagnostic.lower()
                        require(
                            endpoint.connections > 0
                            and not endpoint.requests
                            and "certificate" in failure
                            and any(
                                word in failure
                                for word in (
                                    "verif",
                                    "issuer",
                                    "self-signed",
                                    "expired",
                                    "subject",
                                    "alternative",
                                )
                            ),
                            "Git failure was not peer certificate verification: " + diagnostic,
                        )
                    observations[label] = {
                        "accepted": accepted,
                        "http_requests": endpoint.requests,
                        "tls_rejections": endpoint.rejections,
                        "tls_connections": endpoint.connections,
                        "peer_closures": endpoint.peer_closures,
                        "diagnostic": diagnostic,
                    }

        def extract():
            fixture["run"]([args.system_trust_helper])

        def check_redirect():
            with tempfile.TemporaryDirectory(dir=directory) as clone:
                destination = Path(clone)
                git(destination, "init", "--quiet", "--initial-branch=source")
                with server(directory, "trusted", source) as (endpoint, url):
                    endpoint.redirect = True
                    try:
                        fetch(destination, url, revision)
                    except Error as error:
                        diagnostic = str(error)
                    else:
                        raise Error("Git accepted a redirected source transfer")
                    require(
                        endpoint.connections == 1
                        and endpoint.requests == ["/repository.git/info/refs?service=git-upload-pack"],
                        "Git followed a source redirect",
                    )
                    observations["redirect-refused"] = {
                        "accepted": False,
                        "http_requests": endpoint.requests,
                        "tls_connections": endpoint.connections,
                        "diagnostic": diagnostic,
                    }

        try:
            check("unknown-despite-all-overrides", "unknown", False)
            check("untrusted-before-addition", "trusted", False)
            shutil.copyfile(directory / "authority.pem", anchor)
            extract()
            check("authorized-system-anchor", "trusted", True)
            check_redirect()
            check("wrong-name", "wrong-name", False)
            check("expired", "expired", False)
            check("other-authority", "unknown", False)
            anchor.unlink()
            check("removed-before-refresh-observation", "trusted", True)
            extract()
            check("removed-after-refresh", "trusted", False)
            shutil.copyfile(directory / "authority.pem", anchor)
            shutil.copyfile(directory / "authority.pem", blocklist)
            extract()
            check("distrust-overrides-anchor", "trusted", False)
            blocklist.unlink()
            extract()
            check("distrust-removed", "trusted", True)
            fixture["BUNDLE"].write_bytes(b"stale CA output\n")
            extract()
            check("stale-output-regenerated", "trusted", True)
        finally:
            anchor.unlink(missing_ok=True)
            blocklist.unlink(missing_ok=True)
            extract()
            require(fixture["sha256"](fixture["BUNDLE"]) == baseline, "system trust was not restored")
    result = {
        "result": "pass",
        "probe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "packages": fixture["run"](
            ["rpm", "-q", "git-core", "ca-certificates", "p11-kit-trust"]
        ).stdout.splitlines(),
        "observations": observations,
        "scope": "native pinned Git HTTPS transport in a private rootless container, not image acceptance",
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
