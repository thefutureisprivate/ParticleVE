"""Use the distribution CA authority for workstation and publication clients."""

import os
import platform
import ssl


def system_trust_paths():
    """Return distribution CA paths, independent of process trust overrides."""
    release = platform.freedesktop_os_release()
    # OBS's native Fedora build root uses ID=generic and ID_LIKE=fedora.
    # Its CA package still owns Fedora's canonical extracted trust paths.
    if "fedora" in {release.get("ID"), *release.get("ID_LIKE", "").split()}:
        return {
            "cafile": "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
            "capath": "/etc/pki/tls/certs",
        }
    paths = ssl.get_default_verify_paths()
    return {"cafile": paths.openssl_cafile, "capath": paths.openssl_capath}


def system_tls_context():
    """Use OpenSSL's distribution trust paths, independent of per-tool CA overrides."""
    return ssl.create_default_context(**system_trust_paths())


def system_tls_environment():
    """Select that same native store for child TLS clients."""
    paths = system_trust_paths()
    return {
        **os.environ,
        "SSL_CERT_FILE": paths["cafile"],
        "SSL_CERT_DIR": paths["capath"],
        "CURL_CA_BUNDLE": paths["cafile"],
        "REQUESTS_CA_BUNDLE": paths["cafile"],
        "CARGO_HTTP_CAINFO": paths["cafile"],
        "CARGO_HTTP_PROXY_CAINFO": paths["cafile"],
        "P11_KIT_NO_USER_CONFIG": "1",
    }
