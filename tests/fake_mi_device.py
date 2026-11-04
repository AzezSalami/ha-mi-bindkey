"""A simulated Xiaomi device speaking the device side of Mi standard auth.

Used by the tests to exercise MiActivator without real hardware.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CTRL = "00000010-0000-1000-8000-00805f9b34fb"
AUTH = "00000019-0000-1000-8000-00805f9b34fb"
VERSION = "00000004-0000-1000-8000-00805f9b34fb"


class FakeMiDevice:
    """Behaves like a connected BleakClient for the activator."""

    def __init__(self, activated: bool = False, skip_rx_ack: bool = False, firmware: str = "2.1.1_0159") -> None:
        self.activated = activated
        self.skip_rx_ack = skip_rx_ack  # some firmwares don't confirm our frames
        self.firmware = firmware
        self.stored_id = b"\x00blt.3.12345abcdefXYZ" if activated else None
        self.callbacks: dict[str, object] = {}
        self.state = "idle"
        self._rx: dict | None = None  # parcel being received from the app
        self._tx: list[bytes] | None = None  # frames waiting for app's READY
        self._tx_done = None
        self.priv = ec.generate_private_key(ec.SECP256R1())
        self.app_pub: bytes | None = None
        self.bind_key: bytes | None = None
        self.token: bytes | None = None
        self.decrypted_id: bytes | None = None
        self.services = None

    # --- BleakClient surface -------------------------------------------------
    async def read_gatt_char(self, char):
        assert char == VERSION
        return bytearray(self.firmware.encode())

    async def start_notify(self, char, cb):
        self.callbacks[char] = cb

    async def stop_notify(self, char):
        self.callbacks.pop(char, None)

    async def write_gatt_char(self, char, data, response=None):
        data = bytes(data)
        await asyncio.sleep(0)
        if char == CTRL:
            self._on_ctrl(data)
        elif char == AUTH:
            self._on_auth(data)
        else:
            raise AssertionError(char)

    # --- helpers --------------------------------------------------------------
    def _notify(self, char, data: bytes):
        cb = self.callbacks[char]
        asyncio.get_running_loop().call_soon(cb, char, bytearray(data))

    def _send_parcel(self, ptype: int, payload: bytes, then=None):
        chunks = [payload[i : i + 18] for i in range(0, len(payload), 18)]
        self._tx = [i.to_bytes(2, "little") + c for i, c in enumerate(chunks, 1)]
        self._tx_done = then
        self._notify(AUTH, bytes([0, 0, 0, ptype]) + len(chunks).to_bytes(2, "little"))

    # --- control point --------------------------------------------------------
    def _on_ctrl(self, data: bytes):
        if data == bytes.fromhex("a2000000"):
            self.state = "reg"
            if self.activated:
                # 4 unknown bytes + stored id, sent as two frames
                self._send_parcel(0x00, b"\x01\x02\x03\x04" + self.stored_id)
            else:
                self._send_parcel(0x00, bytes.fromhex("01000000"))
        elif data == bytes.fromhex("15000000"):
            self.state = "key"
        elif data == bytes.fromhex("13000000"):
            ok = self.decrypted_id is not None
            if ok:
                self.activated = True
                self.stored_id = self.decrypted_id
            self._notify(CTRL, bytes.fromhex("11000000" if ok else "12000000"))
        elif data == bytes.fromhex("24000000"):
            self.state = "login"
        else:
            raise AssertionError(f"unknown ctrl {data.hex()}")

    # --- parcel channel -------------------------------------------------------
    def _on_auth(self, data: bytes):
        if data == bytes.fromhex("00000101"):  # app ready for our frames
            for frame in self._tx:
                self._notify(AUTH, frame)
            return
        if data == bytes.fromhex("00000100"):  # app received our frames
            done, self._tx_done, self._tx = self._tx_done, None, None
            if done:
                done()
            return
        if len(data) == 6 and data[:3] == b"\x00\x00\x00":  # app starts a parcel
            self._rx = {"type": data[3], "count": int.from_bytes(data[4:6], "little"), "frames": {}}
            self._notify(AUTH, bytes.fromhex("00000101"))
            return
        # a frame of the parcel being received
        idx = int.from_bytes(data[:2], "little")
        self._rx["frames"][idx] = data[2:]
        if len(self._rx["frames"]) == self._rx["count"]:
            payload = b"".join(self._rx["frames"][i] for i in range(1, self._rx["count"] + 1))
            ptype = self._rx["type"]
            self._rx = None
            if not self.skip_rx_ack:
                self._notify(AUTH, bytes.fromhex("00000100"))
            self._on_parcel(ptype, payload)

    def _on_parcel(self, ptype: int, payload: bytes):
        if self.state == "key" and ptype == 0x03:
            self.app_pub = payload
            peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + payload)
            shared = self.priv.exchange(ec.ECDH(), peer)
            okm = HKDF(hashes.SHA256(), 64, None, b"mible-setup-info").derive(shared)
            self.token, self.bind_key, self._bind_a = okm[:12], okm[12:28], okm[28:44]
            own = self.priv.public_key().public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
            )[1:]
            self._send_parcel(0x03, own)
        elif self.state == "key" and ptype == 0x00:
            try:
                self.decrypted_id = AESCCM(self._bind_a, tag_length=4).decrypt(
                    bytes.fromhex("101112131415161718191a1b"), payload, b"devID"
                )
            except Exception:  # noqa: BLE001
                self.decrypted_id = None
        elif self.state == "login" and ptype == 0x0B:
            self._app_rand = payload
            self._dev_rand = secrets.token_bytes(16)
            salt = self._app_rand + self._dev_rand
            okm = HKDF(hashes.SHA256(), 64, salt, b"mible-login-info").derive(self.token)
            self._login_okm = okm
            confirm = hmac.new(okm[:16], self._dev_rand + self._app_rand, hashlib.sha256).digest()
            self._send_parcel(0x0D, self._dev_rand, then=lambda: self._send_parcel(0x0C, confirm))
        elif self.state == "login" and ptype == 0x0A:
            salt = self._app_rand + self._dev_rand
            want = hmac.new(self._login_okm[16:32], salt, hashlib.sha256).digest()
            self._notify(CTRL, bytes.fromhex("21000000" if payload == want else "23000000"))
