"""Diagnostic sensors exposing the captured bind key and token."""

from __future__ import annotations

from homeassistant.components.sensor import SensorEntity, SensorEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_ADDRESS, CONF_NAME, EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import CONNECTION_BLUETOOTH, DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import CONF_BIND_KEY, CONF_FIRMWARE, CONF_TOKEN

DESCRIPTIONS = (
    SensorEntityDescription(
        key=CONF_BIND_KEY,
        translation_key=CONF_BIND_KEY,
        icon="mdi:key-variant",
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    SensorEntityDescription(
        key=CONF_TOKEN,
        translation_key=CONF_TOKEN,
        icon="mdi:key-chain",
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    async_add_entities(MiKeySensor(entry, desc) for desc in DESCRIPTIONS)


class MiKeySensor(SensorEntity):
    """Static value read from the config entry."""

    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(self, entry: ConfigEntry, description: SensorEntityDescription) -> None:
        self.entity_description = description
        address: str = entry.data[CONF_ADDRESS]
        self._attr_unique_id = f"{address}_{description.key}"
        self._attr_native_value = entry.data.get(description.key)
        # Same Bluetooth connection as Xiaomi BLE uses, so these attach to that device.
        self._attr_device_info = DeviceInfo(
            connections={(CONNECTION_BLUETOOTH, address)},
            name=entry.data.get(CONF_NAME) or address,
            sw_version=entry.data.get(CONF_FIRMWARE),
        )
