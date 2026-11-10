"""Signed early-console profiles generated and inspected by the image builder."""

BAUD_RATES = (9600, 19200, 38400, 57600, 115200)
SERIAL_CONSOLES = {
    f"serial{port}-{baud}": f"console=ttyS{port},{baud}n8" for port in range(4) for baud in BAUD_RATES
}


def uki_profiles():
    return [
        {
            "Profile": {"ID": name, "TITLE": argument.removeprefix("console=")},
            "Cmdline": [argument],
            "SignExpectedPcr": True,
        }
        for name, argument in SERIAL_CONSOLES.items()
    ]
