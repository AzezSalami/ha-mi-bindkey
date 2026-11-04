# Mi Bind Key for Home Assistant

Get the BLE **bind key** (and Mi token) for Xiaomi Bluetooth devices directly from Home Assistant, by connecting to the device and running the same local activation that the **"Do Activation"** button in atc1441's [TelinkFlasher](https://atc1441.github.io/TelinkFlasher.html) performs. No Xiaomi cloud account is involved.

The key can be pushed straight into the built-in **Xiaomi BLE** integration so encrypted sensors start reporting.

> ⚠️ **Activation replaces the device's keys.** A device paired in Mi Home stops working there until you pair it again, and pairing it again in Mi Home creates a new key, which makes this one stop working. Pick one.

## How it works

Python port of TelinkFlasher's Mi standard auth flow over the `FE95` service:

1. `a2000000` on the control characteristic (`0x0010`) starts registration; the device reports whether it is already bound and, if so, its existing device ID.
2. ECDH on P-256: our public key and the device's are exchanged as framed parcels on `0x0019`.
3. `HKDF-SHA256(shared, info="mible-setup-info")` → 12-byte **token**, 16-byte **bind key**, 16-byte key *A*.
4. The device ID is AES-CCM encrypted with *A* (nonce `101112…1b`, AAD `devID`, 4-byte tag) and sent back; `13000000` finishes. `11000000` = success.
5. A login with the new token (`mible-login-info` HKDF + HMAC proofs) verifies the keys.

The key derivation, device-ID encryption and login proofs are checked byte-for-byte against TelinkFlasher's own SJCL code in `tests/test_mi_auth.py`.

## Requirements

- Home Assistant **2024.8** or newer.
- A Bluetooth adapter or **ESPHome Bluetooth proxy with active connections** (`bluetooth_proxy: active: true`) in range of the device.
- A device that uses Mi *standard auth* (LYWSD03MMC, MHO-C401, CGG1, many other Telink-based sensors). Devices that use newer "secure auth" chips won't activate this way.

## Install

**HACS:** add this repository as a custom repository (category *Integration*), install **Mi Bind Key**, restart.

**Manual:** copy `custom_components/mi_bindkey` into your `config/custom_components/` folder and restart.

## Use

### From the UI
*Settings → Devices & services → Add integration → Mi Bind Key*

1. Pick the device from the dropdown (nearby devices advertising the Xiaomi `FE95` service), or type a MAC address.
2. Leave **Save the key to the Xiaomi BLE integration** on if you want it applied automatically.
3. Wait 10–30 s. The success screen shows the bind key and token.

A diagnostic **Bind key** sensor (and a disabled-by-default **Mi token** sensor) is attached to the same device as Xiaomi BLE so you can copy it later. Use **Reconfigure** on the entry to activate again.

If it fails (out of range, device asleep), the error is shown and you can retry from the same dialog. Pressing the device's button (if it has one) right before retrying often helps.

### As an action
```yaml
action: mi_bindkey.activate
data:
  address: A4:C1:38:12:34:56
  apply_to_xiaomi_ble: true
response_variable: result
```
Returns `bind_key`, `token`, `firmware`, `was_activated`, `login_verified`, `applied_to_xiaomi_ble`.

## Order of setup with Xiaomi BLE

Either order works:
- **Xiaomi BLE first:** it discovers the device and asks for a key. Run Mi Bind Key with "save to Xiaomi BLE" on; the key is written into that entry and it reloads. (If Xiaomi BLE's flow is still open asking for a key, paste it there.)
- **Mi Bind Key first:** copy the key from the success screen into Xiaomi BLE when it asks.

## Development

```bash
pip install pytest-homeassistant-custom-component bleak bleak-retry-connector habluetooth bluetooth-adapters aiousbwatcher pyserial
pytest
```
`tests/fake_mi_device.py` simulates the device side of the protocol (fresh and already-activated devices, with and without frame confirmations).

## Credits

Protocol and reference implementation: [atc1441](https://github.com/atc1441) (TelinkFlasher / ATC_MiThermometer).
