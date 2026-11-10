"""Native Git source operations with distribution CA trust and explicit input ownership."""

import os
import re
from urllib.parse import urlsplit

from particleve.common import Error, require, run
from Tools.trust import system_tls_environment, system_trust_paths


def environment():
    # Source identities must not be redirected by GIT_DIR, replacement objects,
    # injected config, executable paths or a caller-selected CA/verification mode.
    env = {key: value for key, value in system_tls_environment().items() if not key.startswith("GIT_")}
    paths = system_trust_paths()
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_ALLOW_PROTOCOL": "https",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "/usr/bin/false",
            "GIT_SSL_CAINFO": paths["cafile"],
            "GIT_SSL_CAPATH": paths["capath"],
            "GIT_PROXY_SSL_CAINFO": paths["cafile"],
        }
    )
    return env


def source_url(url):
    require(isinstance(url, str) and len(url) <= 4096, "invalid public HTTPS source URL")
    # The URL also becomes a Git -c subsection. An unescaped '=' or control
    # character must not change the key/value grammar of that argument.
    try:
        parsed = urlsplit(url)
        valid = (
            parsed.scheme == "https"
            and parsed.hostname
            and parsed.username is None
            and parsed.password is None
            and not parsed.query
            and not parsed.fragment
            and "=" not in url
            and not any(
                character.isspace() or ord(character) < 32 or ord(character) == 127 for character in url
            )
            and (parsed.port is None or 1 <= parsed.port <= 65535)
        )
    except ValueError as error:
        raise Error("invalid public HTTPS source URL") from error
    require(valid, "source fetches require a public HTTPS URL without credentials")


def git(root, *arguments, remote=None, **options):
    command = ["/usr/bin/git", "-c", "http.sslVerify=true", "-c", "credential.helper="]
    if remote is not None:
        source_url(remote)
        # URL-specific config can otherwise beat a generic command-line setting.
        # Match the exact transfer URL and replace the native CA environment too.
        for setting, value in (
            ("sslVerify", "true"),
            ("proxySSLVerify", "true"),
            ("followRedirects", "false"),
            ("extraHeader", ""),
        ):
            command.extend(["-c", f"http.{remote}.{setting}={value}"])
    return run([*command, "-C", root, *arguments], env=environment(), **options)


def fetch(root, url, revision):
    require(
        isinstance(revision, str)
        and len(revision) <= 128
        and re.fullmatch(r"[0-9a-f]{40}|refs/tags/v?[0-9]+(?:\.[0-9]+){0,2}", revision),
        "fetch an immutable source commit or the checked release tag",
    )
    source_url(url)
    # Native --get-url resolves aliases/insteadOf without contacting a peer.
    # Otherwise a local rewrite could select another URL's TLS exceptions.
    resolved = git(root, "ls-remote", "--get-url", url).stdout.strip()
    require(resolved == url, "source URL rewrites are unsupported; use the reviewed source lock")
    return git(root, "fetch", "--no-progress", "--depth=1", url, revision, remote=url)
