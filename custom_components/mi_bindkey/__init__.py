"""Mi Bind Key: activate Xiaomi BLE devices locally and capture their bind key."""

from __future__ import annotations

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_ADDRESS, Platform
from homeassistant.core import HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.typing import ConfigType

from .activation import async_activate_device, async_push_to_xiaomi_ble
from .const import CONF_APPLY_TO_XIAOMI_BLE, CONF_BIND_KEY, CONF_FIRMWARE, CONF_TOKEN, DOMAIN, SERVICE_ACTIVATE
from .mi_auth import MiAuthError

PLATFORMS = [Platform.SENSOR]
CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)

ACTIVATE_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_ADDRESS): cv.string,
        vol.Optional(CONF_APPLY_TO_XIAOMI_BLE, default=True): cv.boolean,
    }
)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Register the activate action."""

    async def _activate(call: ServiceCall) -> ServiceResponse:
        address: str = call.data[CONF_ADDRESS].upper()
        try:
            result = await async_activate_device(hass, address)
        except MiAuthError as err:
            raise HomeAssistantError(str(err)) from err

        applied = False
        if call.data[CONF_APPLY_TO_XIAOMI_BLE]:
            applied = async_push_to_xiaomi_ble(hass, address, result.bind_key)

        # Keep an existing Mi Bind Key entry for this device in sync.
        for entry in hass.config_entries.async_entries(DOMAIN):
            if entry.unique_id == address:
                hass.config_entries.async_update_entry(
                    entry,
                    data={
                        **entry.data,
                        CONF_BIND_KEY: result.bind_key,
                        CONF_TOKEN: result.token,
                        CONF_FIRMWARE: result.firmware,
                    },
                )
                hass.config_entries.async_schedule_reload(entry.entry_id)

        return {"address": address, **result.as_dict(), "applied_to_xiaomi_ble": applied}

    hass.services.async_register(
        DOMAIN,
        SERVICE_ACTIVATE,
        _activate,
        schema=ACTIVATE_SCHEMA,
        supports_response=SupportsResponse.ONLY,
    )
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up the key sensors for one activated device."""
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
