"""Home Assistant glue: connect to a device and run the Mi activation."""

from __future__ import annotations

import logging

from bleak.exc import BleakError
from bleak_retry_connector import BleakClientWithServiceCache, establish_connection

from homeassistant.components import bluetooth
from homeassistant.core import HomeAssistant

from .const import XIAOMI_BLE_BINDKEY, XIAOMI_BLE_DOMAIN
from .mi_auth import MI_SERVICE_UUID, MiActivationResult, MiActivator, MiAuthError

_LOGGER = logging.getLogger(__name__)


class DeviceNotFound(MiAuthError):
    """No connectable adapter / proxy can currently see the device."""


class NotMiDevice(MiAuthError):
    """The device does not expose the Mi auth service."""


async def async_activate_device(hass: HomeAssistant, address: str) -> MiActivationResult:
    """Connect to ``address`` and activate it, returning the new keys."""
    ble_device = bluetooth.async_ble_device_from_address(hass, address, connectable=True)
    if ble_device is None:
        raise DeviceNotFound(
            f"{address} is not in range of any adapter or proxy that can make connections"
        )

    try:
        client = await establish_connection(
            BleakClientWithServiceCache, ble_device, ble_device.name or address, max_attempts=4
        )
    except (BleakError, TimeoutError) as err:
        raise MiAuthError(f"Could not connect to {address}: {err}") from err

    try:
        if client.services.get_service(MI_SERVICE_UUID) is None:
            raise NotMiDevice(f"{address} does not expose the Xiaomi auth service (FE95)")
        return await MiActivator(client).activate()
    except BleakError as err:
        raise MiAuthError(f"Bluetooth error while activating {address}: {err}") from err
    finally:
        try:
            await client.disconnect()
        except BleakError:
            pass


def async_push_to_xiaomi_ble(hass: HomeAssistant, address: str, bind_key: str) -> bool:
    """Store the key in a matching Xiaomi BLE entry and reload it. Returns True if one was found."""
    for entry in hass.config_entries.async_entries(XIAOMI_BLE_DOMAIN):
        if (entry.unique_id or "").upper() != address.upper():
            continue
        hass.config_entries.async_update_entry(
            entry, data={**entry.data, XIAOMI_BLE_BINDKEY: bind_key}
        )
        hass.config_entries.async_schedule_reload(entry.entry_id)
        _LOGGER.info("Updated Xiaomi BLE entry %s with the new bind key", entry.title)
        return True
    return False
