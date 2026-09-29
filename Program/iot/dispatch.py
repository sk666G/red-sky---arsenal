# language: Python, file: Program/iot/dispatch.py, target: Red Sky iot router
import sys
from typing import List
from Program.utils import print_info, print_err


def _usage():
    print_info("redsky iot <sub-command> [args...]")
    print_info("")
    print_info("  default_creds  spray --host ip:port --protocol http|https|telnet|ssh")
    print_info("      iterate default creds against IoT targets, log hits")
    print_info("")
    print_info("  mqtt           probe | snarf | publish")
    print_info("      MQTT open-broker probe, firehose subscribe, topic injection")
    print_info("")
    print_info("  coap           discover | get | put | post | fuzz")
    print_info("      CoAP resource discovery + per-resource read/write + path fuzz")
    print_info("")
    print_info("  firmware       analyze --image FILE")
    print_info("      carve, extract, and secret-sweep an IoT firmware image")


def run_cli(args: List[str]) -> int:
    if not args:
        _usage()
        return 2
    sub = args[0].lower()
    if sub in ("-h", "--help"):
        _usage()
        return 0

    if sub in ("default_creds", "creds", "dc"):
        from .default_creds import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("mqtt", "m"):
        from .mqtt import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("coap", "c"):
        from .coap import run_cli as _f
        return int(_f(args[1:]))
    if sub in ("firmware", "fw", "f"):
        from .firmware import run_cli as _f
        return int(_f(args[1:]))

    print_err("unknown iot sub-command: " + sub)
    _usage()
    return 2


if __name__ == "__main__":
    sys.exit(run_cli(sys.argv[1:]))
