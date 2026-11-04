"""Xiaomi "Mi standard auth" activation over BLE.

Python port of the activation / login flow in atc1441's TelinkFlasher
(https://atc1441.github.io/TelinkFlasher.html).

Activating a device registers it to a fresh, locally generated identity and
derives a new Mi token and BLE bind key from an ECDH (P-256) key exchange.
The device must be re-paired in the Mi Home app afterwards if you still want
to use it there.

This module has no Home Assistant dependency: it only needs an object that
behaves like a connected ``bleak.BleakClient``.
"""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass
import hashlib
import hmac
import logging
import secrets
import string
from typing import Any, Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_LOGGER = logging.getLogger(__name__)


def _uuid16(value: int) -> str:
    return f"0000{value:04x}-0000-1000-8000-00805f9b34fb"


MI_SERVICE_UUID = _uuid16(0xFE95)
CHAR_VERSION = _uuid16(0x0004)  # firmware version string
CHAR_CTRL = _uuid16(0x0010)  # control point ("enc_10" in TelinkFlasher)
CHAR_AUTH = _uuid16(0x0019)  # parcel channel ("enc_19" in TelinkFlasher)

# Control point commands / results (written to / notified on CHAR_CTRL)
CMD_REGISTER_START = bytes.fromhex("a2000000")
CMD_REGISTER_KEY = bytes.fromhex("15000000")
CMD_REGISTER_END = bytes.fromhex("13000000")
CMD_LOGIN_START = bytes.fromhex("24000000")
RES_REGISTER_OK = bytes.fromhex("11000000")
RES_REGISTER_FAIL = bytes.fromhex("12000000")
RES_LOGIN_OK = bytes.fromhex("21000000")
RES_LOGIN_FAIL = bytes.fromhex("23000000")

# Parcel channel acknowledgements (both directions)
ACK_READY = bytes.fromhex("00000101")  # "ready to receive your frames"
ACK_RECEIVED = bytes.fromhex("00000100")  # "all frames received"
ACK_TIMEOUT = bytes.fromhex("000001050100")

# Parcel types
PARCEL_DEV_ID = 0x00
PARCEL_PUBKEY = 0x03
PARCEL_LOGIN_DEV_INFO = 0x0A
PARCEL_LOGIN_RANDOM = 0x0B
PARCEL_LOGIN_DEV_CONFIRM = 0x0C
PARCEL_LOGIN_DEV_RANDOM = 0x0D

FRAME_PAYLOAD = 18  # 20 byte ATT payload minus 2 byte frame index
DID_NONCE = bytes.fromhex("101112131415161718191a1b")
DID_AAD = b"devID"


class MiAuthError(Exception):
    """Raised when activation or login fails."""


class _BleakLike(Protocol):
    async def start_notify(self, char: Any, callback: Any) -> None: ...
    async def stop_notify(self, char: Any) -> None: ...
    async def write_gatt_char(self, char: Any, data: bytes, response: bool | None = ...) -> None: ...
    async def read_gatt_char(self, char: Any) -> bytearray: ...


@dataclass(frozen=True)
class MiActivationResult:
    """Keys produced by a successful activation."""

    bind_key: str
    token: str
    firmware: str | None
    was_activated: bool
    device_id: str
    login_verified: bool | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "bind_key": self.bind_key,
            "token": self.token,
            "firmware": self.firmware,
            "was_activated": self.was_activated,
            "device_id": self.device_id,
            "login_verified": self.login_verified,
        }


@dataclass(frozen=True)
class SetupKeys:
    token: bytes
    bind_key: bytes
    bind_a: bytes


def derive_setup_keys(shared_secret: bytes) -> SetupKeys:
    """HKDF-SHA256(shared, salt=None, info="mible-setup-info") -> token, bind key, A."""
    okm = HKDF(
        algorithm=hashes.SHA256(), length=64, salt=None, info=b"mible-setup-info"
    ).derive(shared_secret)
    return SetupKeys(token=okm[0:12], bind_key=okm[12:28], bind_a=okm[28:44])


def encrypt_device_id(bind_a: bytes, device_id: bytes) -> bytes:
    """AES-CCM (4 byte tag) of the device id, as expected by the device."""
    return AESCCM(bind_a, tag_length=4).encrypt(DID_NONCE, device_id, DID_AAD)


def login_proofs(token: bytes, app_random: bytes, dev_random: bytes) -> tuple[bytes, bytes]:
    """Return (expected device confirmation, our device-info proof)."""
    salt = app_random + dev_random
    salt_rev = dev_random + app_random
    okm = HKDF(
        algorithm=hashes.SHA256(), length=64, salt=salt, info=b"mible-login-info"
    ).derive(token)
    expected = hmac.new(okm[0:16], salt_rev, hashlib.sha256).digest()
    ours = hmac.new(okm[16:32], salt, hashlib.sha256).digest()
    return expected, ours


def random_device_id() -> bytes:
    """Same shape TelinkFlasher uses: 0x00 + 'blt.3.129v' + 6 random chars + 'ATC'."""
    alphabet = string.ascii_letters + string.digits
    rand = "".join(secrets.choice(alphabet) for _ in range(6))
    return b"\x00blt.3.129v" + rand.encode() + b"ATC"


class MiActivator:
    """Drive the activation conversation on a connected BLE client."""

    def __init__(self, client: _BleakLike, timeout: float = 10.0) -> None:
        self._client = client
        self._timeout = timeout
        self._ctrl_q: asyncio.Queue[bytes] = asyncio.Queue()
        self._auth_q: asyncio.Queue[bytes] = asyncio.Queue()
        self._auth_pushback: deque[bytes] = deque()
        self._write_response: dict[str, bool] = {}

    # ------------------------------------------------------------------ I/O
    def _on_ctrl(self, _sender: Any, data: bytearray) -> None:
        _LOGGER.debug("ctrl <- %s", bytes(data).hex())
        self._ctrl_q.put_nowait(bytes(data))

    def _on_auth(self, _sender: Any, data: bytearray) -> None:
        _LOGGER.debug("auth <- %s", bytes(data).hex())
        self._auth_q.put_nowait(bytes(data))

    def _response_for(self, char: str) -> bool:
        if char in self._write_response:
            return self._write_response[char]
        response = True
        services = getattr(self._client, "services", None)
        if services is not None:
            try:
                gatt_char = services.get_characteristic(char)
            except Exception:  # noqa: BLE001
                gatt_char = None
            if gatt_char is not None:
                props = set(getattr(gatt_char, "properties", []) or [])
                response = "write" in props or "write-without-response" not in props
        self._write_response[char] = response
        return response

    async def _write(self, char: str, data: bytes) -> None:
        _LOGGER.debug("%s -> %s", "ctrl" if char == CHAR_CTRL else "auth", data.hex())
        await self._client.write_gatt_char(char, data, response=self._response_for(char))

    async def _next_auth(self) -> bytes:
        if self._auth_pushback:
            return self._auth_pushback.popleft()
        try:
            value = await asyncio.wait_for(self._auth_q.get(), self._timeout)
        except asyncio.TimeoutError as err:
            raise MiAuthError("Timed out waiting for the device to answer") from err
        if value == ACK_TIMEOUT:
            raise MiAuthError("Device reported a protocol timeout")
        return value

    async def _expect_auth(self, expected: bytes, step: str) -> None:
        value = await self._next_auth()
        if value != expected:
            raise MiAuthError(f"Unexpected answer during {step}: {value.hex()} (wanted {expected.hex()})")

    async def _wait_ctrl(self, ok: bytes, fail: bytes, step: str) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._timeout
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise MiAuthError(f"Timed out waiting for {step} result")
            try:
                value = await asyncio.wait_for(self._ctrl_q.get(), remaining)
            except asyncio.TimeoutError as err:
                raise MiAuthError(f"Timed out waiting for {step} result") from err
            if value == ok:
                return
            if value == fail:
                raise MiAuthError(f"Device rejected the {step}")
            _LOGGER.debug("Ignoring control notification %s while waiting for %s", value.hex(), step)

    # -------------------------------------------------------------- parcels
    async def _recv_parcel(self, expected_type: int | None, step: str) -> bytes:
        header = await self._next_auth()
        if len(header) != 6 or header[0:3] != b"\x00\x00\x00":
            raise MiAuthError(f"Expected a parcel header during {step}, got {header.hex()}")
        ptype = header[3]
        count = int.from_bytes(header[4:6], "little")
        if expected_type is not None and ptype != expected_type:
            raise MiAuthError(f"Unexpected parcel type {ptype:#04x} during {step}")
        if not 0 < count < 64:
            raise MiAuthError(f"Implausible frame count {count} during {step}")
        await self._write(CHAR_AUTH, ACK_READY)
        frames: dict[int, bytes] = {}
        while len(frames) < count:
            frame = await self._next_auth()
            if len(frame) < 3:
                raise MiAuthError(f"Short frame during {step}: {frame.hex()}")
            index = int.from_bytes(frame[0:2], "little")
            if not 1 <= index <= count:
                raise MiAuthError(f"Unexpected frame {frame.hex()} during {step}")
            frames[index] = frame[2:]
        await self._write(CHAR_AUTH, ACK_RECEIVED)
        return b"".join(frames[i] for i in range(1, count + 1))

    async def _send_parcel(self, ptype: int, payload: bytes, step: str) -> None:
        chunks = [payload[i : i + FRAME_PAYLOAD] for i in range(0, len(payload), FRAME_PAYLOAD)]
        await self._write(CHAR_AUTH, bytes([0, 0, 0, ptype]) + len(chunks).to_bytes(2, "little"))
        await self._expect_auth(ACK_READY, step)
        for index, chunk in enumerate(chunks, start=1):
            await self._write(CHAR_AUTH, index.to_bytes(2, "little") + chunk)
        # The device normally confirms with ACK_RECEIVED. TelinkFlasher ignores
        # that confirmation, so tolerate it being skipped: anything else is kept
        # for the next read.
        try:
            value = await asyncio.wait_for(self._auth_q.get(), min(self._timeout, 2.0))
        except asyncio.TimeoutError:
            _LOGGER.debug("No receive confirmation after %s, continuing", step)
            return
        if value == ACK_TIMEOUT:
            raise MiAuthError(f"Device reported a protocol timeout during {step}")
        if value != ACK_RECEIVED:
            self._auth_pushback.append(value)

    # ------------------------------------------------------------- flows
    async def read_firmware(self) -> str | None:
        try:
            raw = await self._client.read_gatt_char(CHAR_VERSION)
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("Could not read firmware version: %s", err)
            return None
        return bytes(raw).split(b"\x00", 1)[0].decode(errors="replace") or None

    async def activate(self, verify_login: bool = True) -> MiActivationResult:
        firmware = await self.read_firmware()
        await self._client.start_notify(CHAR_CTRL, self._on_ctrl)
        await self._client.start_notify(CHAR_AUTH, self._on_auth)
        try:
            return await self._activate(firmware, verify_login)
        finally:
            for char in (CHAR_AUTH, CHAR_CTRL):
                try:
                    await self._client.stop_notify(char)
                except Exception:  # noqa: BLE001
                    pass

    async def _activate(self, firmware: str | None, verify_login: bool) -> MiActivationResult:
        private_key = ec.generate_private_key(ec.SECP256R1())
        own_pub = private_key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )[1:]  # strip 0x04 -> 64 bytes

        # 1. Start registration; the device tells us whether it is already bound.
        await self._write(CHAR_CTRL, CMD_REGISTER_START)
        header = await self._next_auth()
        self._auth_pushback.appendleft(header)
        was_activated = len(header) == 6 and int.from_bytes(header[4:6], "little") >= 2
        known = await self._recv_parcel(PARCEL_DEV_ID, "registration start")
        if was_activated and len(known) > 4:
            device_id = known[4:]
        else:
            device_id = random_device_id()
        _LOGGER.debug("Device previously activated: %s, using id %s", was_activated, device_id)

        # 2. Exchange public keys.
        await self._write(CHAR_CTRL, CMD_REGISTER_KEY)
        await self._send_parcel(PARCEL_PUBKEY, own_pub, "public key upload")
        dev_pub = await self._recv_parcel(PARCEL_PUBKEY, "public key download")
        if len(dev_pub) != 64:
            raise MiAuthError(f"Device public key has unexpected length {len(dev_pub)}")
        try:
            peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + dev_pub)
        except ValueError as err:
            raise MiAuthError("Device sent an invalid public key") from err
        shared = private_key.exchange(ec.ECDH(), peer)

        # 3. Derive keys and hand the device its (encrypted) identity.
        keys = derive_setup_keys(shared)
        await self._send_parcel(PARCEL_DEV_ID, encrypt_device_id(keys.bind_a, device_id), "device id upload")

        # 4. Finish registration.
        await self._write(CHAR_CTRL, CMD_REGISTER_END)
        await self._wait_ctrl(RES_REGISTER_OK, RES_REGISTER_FAIL, "registration")
        _LOGGER.info("Mi activation succeeded")

        login_ok: bool | None = None
        if verify_login:
            try:
                await self._login(keys.token)
                login_ok = True
            except MiAuthError as err:
                _LOGGER.warning("Activation succeeded but login verification failed: %s", err)
                login_ok = False

        return MiActivationResult(
            bind_key=keys.bind_key.hex(),
            token=keys.token.hex(),
            firmware=firmware,
            was_activated=was_activated,
            device_id=device_id[1:].decode(errors="replace"),
            login_verified=login_ok,
        )

    async def _login(self, token: bytes) -> None:
        self._auth_pushback.clear()
        app_random = secrets.token_bytes(16)
        await self._write(CHAR_CTRL, CMD_LOGIN_START)
        await self._send_parcel(PARCEL_LOGIN_RANDOM, app_random, "login random upload")
        dev_random = await self._recv_parcel(PARCEL_LOGIN_DEV_RANDOM, "login random download")
        expected, ours = login_proofs(token, app_random, dev_random)
        confirm = await self._recv_parcel(PARCEL_LOGIN_DEV_CONFIRM, "login confirmation")
        if not hmac.compare_digest(confirm, expected):
            raise MiAuthError("Device login proof does not match the derived token")
        await self._send_parcel(PARCEL_LOGIN_DEV_INFO, ours, "login proof upload")
        await self._wait_ctrl(RES_LOGIN_OK, RES_LOGIN_FAIL, "login")
