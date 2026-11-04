"""Protocol tests for mi_auth against the simulated device."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

import pytest

from .fake_mi_device import FakeMiDevice

_spec = importlib.util.spec_from_file_location(
    "mi_auth", Path(__file__).parents[1] / "custom_components/mi_bindkey/mi_auth.py"
)
mi_auth = importlib.util.module_from_spec(_spec)
sys.modules["mi_auth"] = mi_auth
_spec.loader.exec_module(mi_auth)


@pytest.mark.parametrize("activated", [False, True])
@pytest.mark.parametrize("skip_rx_ack", [False, True])
async def test_activation_matches_device(activated: bool, skip_rx_ack: bool) -> None:
    dev = FakeMiDevice(activated=activated, skip_rx_ack=skip_rx_ack)
    previous_id = dev.stored_id
    result = await mi_auth.MiActivator(dev, timeout=2).activate()

    assert result.bind_key == dev.bind_key.hex()
    assert result.token == dev.token.hex()
    assert len(result.bind_key) == 32 and len(result.token) == 24
    assert result.firmware == "2.1.1_0159"
    assert result.was_activated is activated
    assert result.login_verified is True
    if activated:
        assert dev.stored_id == previous_id  # device keeps its known id
    else:
        assert dev.stored_id.startswith(b"\x00blt.3.129v") and dev.stored_id.endswith(b"ATC")


async def test_rejected_registration() -> None:
    dev = FakeMiDevice()
    original = dev._on_parcel

    def corrupt(ptype, payload):
        if ptype == 0x00 and dev.state == "key":
            payload = bytes(len(payload))
        original(ptype, payload)

    dev._on_parcel = corrupt
    with pytest.raises(mi_auth.MiAuthError, match="rejected the registration"):
        await mi_auth.MiActivator(dev, timeout=2).activate()


async def test_silent_device_times_out() -> None:
    dev = FakeMiDevice()
    dev._on_ctrl = lambda data: None
    with pytest.raises(mi_auth.MiAuthError, match="Timed out"):
        await mi_auth.MiActivator(dev, timeout=0.3).activate()


async def test_vectors_match_telinkflasher_sjcl() -> None:
    """Expected values were produced by running TelinkFlasher's deriveTheKey() and
    do_login_generate() code on its bundled SJCL (core.js) with the same inputs."""
    keys = mi_auth.derive_setup_keys(bytes(range(32)))
    assert keys.token.hex() == "83d3ce31ee8ca124d82039c3"
    assert keys.bind_key.hex() == "8f614b5c9e69bab29edee12148002a2b"

    device_id = bytes.fromhex("00626c742e332e31323976" "416243646546" "415443")
    did = mi_auth.encrypt_device_id(keys.bind_a, device_id)
    assert did.hex() == "56ee2437c4d9125e7fa6293fc5a73a21ad4113d28e1ae948"

    expected, ours = mi_auth.login_proofs(keys.token, b"\xaa" * 16, b"\xbb" * 16)
    assert expected.hex() == "63553cb30593555a7c5120f3e5600245dfdc487c51122c8a9132e6e1093b0ce3"
    assert ours.hex() == "e024bbe31d78e371d08773985122a71b11902fd4e8c11fb0ecbb73e6f670c909"
    assert len(mi_auth.random_device_id()) == 20
