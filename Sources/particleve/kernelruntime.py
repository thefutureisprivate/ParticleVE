"""Validate the stock-kernel interface support in a built image."""

from .common import require


def kernel_support(values):
    require(values.get("SECURITY_YAMA") == "y", "kernel Yama policy support is missing")
    for name, expected in (("ARCH_MMAP_RND_BITS_MAX", 32), ("ARCH_MMAP_RND_COMPAT_BITS_MAX", 16)):
        value = values.get(name, "")
        require(
            value.isdecimal() and int(value) >= expected, "kernel ASLR entropy support is missing: " + name
        )
    if values.get("DEVMEM") == "y":
        require(
            values.get("STRICT_DEVMEM") == values.get("IO_STRICT_DEVMEM") == "y",
            "raw physical memory lacks strict kernel restrictions",
        )
    require(values.get("DEVKMEM") != "y", "legacy kernel memory device is enabled")
    return {
        "yama": True,
        "mmap_rnd_bits_max": int(values["ARCH_MMAP_RND_BITS_MAX"]),
        "mmap_rnd_compat_bits_max": int(values["ARCH_MMAP_RND_COMPAT_BITS_MAX"]),
        "strict_devmem": values.get("DEVMEM") == "y",
        "legacy_kmem": False,
        "proc_kcore": values.get("PROC_KCORE") == "y",
    }
