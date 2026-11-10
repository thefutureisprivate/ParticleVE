"""Native GPT type and label contracts used by image construction."""

from .config import version_key

MIB = 1024**2
GIB = 1024**3
TYPES = {
    "esp": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
    "usr": "8484680c-9521-48c6-9c11-b0720656f69e",
    "verity": "77ff5f63-e7b6-4633-acf4-1565b864c0e6",
    "verity_sig": "e7bb33fb-06cf-4e81-8273-e543b413e2e2",
    "raid": "a19d880f-05fc-4d3b-a006-743f0f84911e",
    "root": "4f68bce3-e8cd-4db1-96e7-fbcaf984b709",
}


def os_label(version):
    version_key(version)
    return "PVE_" + version
