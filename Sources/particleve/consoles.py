"""Signed early-console choices shared by build, installation and runtime checks."""

from pathlib import Path

from .common import require

BAUD_RATES = (9600, 19200, 38400, 57600, 115200)
SERIAL_CONSOLES = {
    f"serial{port}-{baud}": f"console=ttyS{port},{baud}n8" for port in range(4) for baud in BAUD_RATES
}


def profile(config):
    value = config.get("console", "console=tty0")
    require(type(value) is str, "unsupported signed recovery console")
    if value == "console=tty0":
        return None
    if value in {f"console=ttyS{port}" for port in range(4)}:
        value += ",115200n8"
    matches = [name for name, argument in SERIAL_CONSOLES.items() if argument == value]
    require(len(matches) == 1, "unsupported signed recovery console")
    return matches[0]


def uki_profiles():
    return [
        {
            "Profile": {"ID": name, "TITLE": argument.removeprefix("console=")},
            "Cmdline": [argument],
            "SignExpectedPcr": True,
        }
        for name, argument in SERIAL_CONSOLES.items()
    ]


def baseline(config, *, proc=Path("/proc"), sys=Path("/sys")):
    selected = profile(config)
    expected = ["console=tty0", *([SERIAL_CONSOLES[selected]] if selected else [])]
    actual = [word for word in (proc / "cmdline").read_text().split() if word.startswith("console=")]
    require(actual == expected, "signed early recovery console differs from installation configuration")
    active = (sys / "class/tty/console/active").read_text().split()
    device = expected[-1].removeprefix("console=").split(",")[0]
    require(device in active, "selected early recovery console is unavailable")
    require(set(active) <= {"tty0", device}, "unexpected active recovery console")
    return {"profile": selected or "main", "command_line": actual, "active": active}
