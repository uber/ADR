# Common

Source shared by more than one ADR package. Nothing here is installed on its
own.

The Sensor (published to PyPI, Python 3.9+) and Discovery (Python 3.11+) are
installed independently, so neither can import from a shared distribution.
Each ships a checked-in copy of the shared modules instead:

| Source | Copies |
|---|---|
| `adr_common/host_identity.py` | `Sensor/adr_sensor/host_identity.py`, `Discovery/adr_discovery/world/host_identity.py` |

Edit the source here, never a copy, then run:

```sh
python Common/sync.py          # rewrite the copies
python Common/sync.py --check  # CI: fail on drift
```

Shared modules must stay standard-library only and Python 3.9 compatible.
