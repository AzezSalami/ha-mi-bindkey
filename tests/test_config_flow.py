"""Config flow, sensors and action tests using the simulated device."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import entity_registry as er
from homeassistant.setup import async_setup_component

from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.mi_bindkey.const import DOMAIN

from .fake_mi_device import FakeMiDevice

ADDRESS = "A4:C1:38:AA:BB:CC"
MI_UUID = "0000fe95-0000-1000-8000-00805f9b34fb"


def _service_info():
    info = MagicMock()
    info.address = ADDRESS
    info.name = "LYWSD03MMC"
    info.service_data = {MI_UUID: b"\x00"}
    info.service_uuids = []
    return info


@pytest.fixture
def fake_device():
    dev = FakeMiDevice()
    dev.services = MagicMock()
    dev.services.get_service.return_value = object()
    dev.services.get_characteristic.return_value = None
    dev.disconnect = MagicMock(side_effect=lambda: _noop())
    return dev


async def _noop():
    return None


@pytest.fixture
def patched_ble(fake_device):
    async def _connect(*args, **kwargs):
        return fake_device

    ble_device = MagicMock()
    ble_device.name = "LYWSD03MMC"
    with (
        patch(
            "custom_components.mi_bindkey.config_flow.bluetooth.async_discovered_service_info",
            return_value=[_service_info()],
        ),
        patch(
            "custom_components.mi_bindkey.activation.bluetooth.async_ble_device_from_address",
            return_value=ble_device,
        ),
        patch("custom_components.mi_bindkey.activation.establish_connection", side_effect=_connect),
    ):
        yield


async def _run_user_flow(hass: HomeAssistant, apply: bool = True):
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": config_entries.SOURCE_USER})
    assert result["type"] is FlowResultType.FORM
    assert result["description_placeholders"]["count"] == "1"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"address": ADDRESS.lower(), "apply_to_xiaomi_ble": apply}
    )
    assert result["type"] is FlowResultType.SHOW_PROGRESS
    await hass.async_block_till_done()
    return await hass.config_entries.flow.async_configure(result["flow_id"])


async def test_full_flow_creates_entry_and_pushes_key(hass: HomeAssistant, patched_ble, fake_device) -> None:
    xiaomi = MockConfigEntry(domain="xiaomi_ble", unique_id=ADDRESS, data={}, title="Thermo")
    xiaomi.add_to_hass(hass)

    with patch.object(hass.config_entries, "async_schedule_reload") as reload:
        result = await _run_user_flow(hass)
        if result["type"] is FlowResultType.SHOW_PROGRESS_DONE:
            result = await hass.config_entries.flow.async_configure(result["flow_id"])

    assert result["type"] is FlowResultType.CREATE_ENTRY, result
    key = fake_device.bind_key.hex()
    assert result["data"]["bind_key"] == key
    assert result["data"]["token"] == fake_device.token.hex()
    assert result["data"]["address"] == ADDRESS
    assert result["title"] == f"LYWSD03MMC ({ADDRESS})"
    assert "saved to your Xiaomi BLE entry" in result["description_placeholders"]["xiaomi_ble"]
    assert xiaomi.data["bindkey"] == key
    reload.assert_called_once_with(xiaomi.entry_id)

    await hass.async_block_till_done()
    ent_reg = er.async_get(hass)
    entity_id = ent_reg.async_get_entity_id("sensor", DOMAIN, f"{ADDRESS}_bind_key")
    assert entity_id
    assert hass.states.get(entity_id).state == key
    # token sensor exists but disabled by default
    token_id = ent_reg.async_get_entity_id("sensor", DOMAIN, f"{ADDRESS}_token")
    assert ent_reg.async_get(token_id).disabled_by is not None


async def test_flow_failure_then_retry(hass: HomeAssistant, patched_ble, fake_device) -> None:
    calls = {"n": 0}
    real = fake_device._on_ctrl

    def flaky(data):
        if data == bytes.fromhex("a2000000") and calls["n"] == 0:
            calls["n"] += 1
            return  # device silent on first attempt
        real(data)

    fake_device._on_ctrl = flaky
    with patch("custom_components.mi_bindkey.mi_auth.MiActivator.__init__.__defaults__", (0.3,)):
        result = await _run_user_flow(hass)
        if result["type"] is FlowResultType.SHOW_PROGRESS_DONE:
            result = await hass.config_entries.flow.async_configure(result["flow_id"])
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "failed"
    assert "Timed out" in result["description_placeholders"]["error"]

    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] is FlowResultType.SHOW_PROGRESS
    await hass.async_block_till_done()
    result = await hass.config_entries.flow.async_configure(result["flow_id"])
    if result["type"] is FlowResultType.SHOW_PROGRESS_DONE:
        result = await hass.config_entries.flow.async_configure(result["flow_id"])
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert "No Xiaomi BLE entry" in result["description_placeholders"]["xiaomi_ble"]


async def test_invalid_address(hass: HomeAssistant, patched_ble) -> None:
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": config_entries.SOURCE_USER})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"address": "nope", "apply_to_xiaomi_ble": True}
    )
    assert result["errors"] == {"address": "invalid_address"}


async def test_activate_action(hass: HomeAssistant, patched_ble, fake_device) -> None:
    assert await async_setup_component(hass, DOMAIN, {})
    response = await hass.services.async_call(
        DOMAIN, "activate", {"address": ADDRESS}, blocking=True, return_response=True
    )
    assert response["bind_key"] == fake_device.bind_key.hex()
    assert response["login_verified"] is True
    assert response["applied_to_xiaomi_ble"] is False


async def test_activate_action_device_missing(hass: HomeAssistant) -> None:
    assert await async_setup_component(hass, DOMAIN, {})
    with (
        patch(
            "custom_components.mi_bindkey.activation.bluetooth.async_ble_device_from_address",
            return_value=None,
        ),
        pytest.raises(HomeAssistantError, match="not in range"),
    ):
        await hass.services.async_call(
            DOMAIN, "activate", {"address": ADDRESS}, blocking=True, return_response=True
        )
