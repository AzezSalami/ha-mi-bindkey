"""Config flow: pick a Xiaomi BLE device, activate it, store the bind key."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

import voluptuous as vol

from homeassistant.components import bluetooth
from homeassistant.config_entries import SOURCE_RECONFIGURE, ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_ADDRESS, CONF_NAME
from homeassistant.helpers.selector import (
    BooleanSelector,
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
)

from .activation import async_activate_device, async_push_to_xiaomi_ble
from .const import CONF_APPLY_TO_XIAOMI_BLE, CONF_BIND_KEY, CONF_FIRMWARE, CONF_TOKEN, DOMAIN
from .mi_auth import MI_SERVICE_UUID, MiActivationResult, MiAuthError

_LOGGER = logging.getLogger(__name__)
MAC_RE = re.compile(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")


def _normalize(address: str) -> str:
    raw = address.strip().upper().replace("-", ":")
    if re.fullmatch(r"[0-9A-F]{12}", raw):
        raw = ":".join(raw[i : i + 2] for i in range(0, 12, 2))
    return raw


class MiBindKeyConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Mi Bind Key."""

    VERSION = 1

    def __init__(self) -> None:
        self._address: str | None = None
        self._name: str | None = None
        self._apply = True
        self._task: asyncio.Task[MiActivationResult] | None = None
        self._result: MiActivationResult | None = None
        self._error: str | None = None

    # ----------------------------------------------------------------- user
    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        discovered: dict[str, str] = {}
        configured = self._async_current_ids(include_ignore=False)
        for info in bluetooth.async_discovered_service_info(self.hass, connectable=True):
            if info.address in configured:
                continue
            if MI_SERVICE_UUID in info.service_data or MI_SERVICE_UUID in info.service_uuids:
                discovered[info.address] = info.name or info.address

        if user_input is not None:
            address = _normalize(user_input[CONF_ADDRESS])
            if not MAC_RE.match(address):
                errors[CONF_ADDRESS] = "invalid_address"
            else:
                await self.async_set_unique_id(address, raise_on_progress=False)
                self._abort_if_unique_id_configured()
                self._address = address
                self._name = discovered.get(address, address)
                self._apply = user_input[CONF_APPLY_TO_XIAOMI_BLE]
                return await self.async_step_activate()

        options = [
            SelectOptionDict(value=addr, label=f"{name} ({addr})" if name != addr else addr)
            for addr, name in sorted(discovered.items(), key=lambda kv: kv[1])
        ]
        schema = vol.Schema(
            {
                vol.Required(CONF_ADDRESS): SelectSelector(
                    SelectSelectorConfig(
                        options=options, custom_value=True, mode=SelectSelectorMode.DROPDOWN
                    )
                ),
                vol.Required(CONF_APPLY_TO_XIAOMI_BLE, default=True): BooleanSelector(),
            }
        )
        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            errors=errors,
            description_placeholders={"count": str(len(discovered))},
        )

    # ------------------------------------------------------------ reconfigure
    async def async_step_reconfigure(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Re-run the activation for an existing device (new keys)."""
        entry = self._get_reconfigure_entry()
        if user_input is None:
            return self.async_show_form(
                step_id="reconfigure",
                data_schema=vol.Schema(
                    {vol.Required(CONF_APPLY_TO_XIAOMI_BLE, default=True): BooleanSelector()}
                ),
                description_placeholders={"name": entry.title},
            )
        self._address = entry.data[CONF_ADDRESS]
        self._name = entry.data.get(CONF_NAME, self._address)
        self._apply = user_input[CONF_APPLY_TO_XIAOMI_BLE]
        return await self.async_step_activate()

    # -------------------------------------------------------------- activate
    async def async_step_activate(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if self._task is None:
            self._task = self.hass.async_create_task(
                async_activate_device(self.hass, self._address), eager_start=False
            )
        if not self._task.done():
            return self.async_show_progress(
                step_id="activate",
                progress_action="activating",
                progress_task=self._task,
                description_placeholders={"name": self._name or ""},
            )

        task, self._task = self._task, None
        try:
            self._result = task.result()
        except MiAuthError as err:
            self._error = str(err)
            return self.async_show_progress_done(next_step_id="failed")
        except Exception as err:  # noqa: BLE001
            _LOGGER.exception("Unexpected error activating %s", self._address)
            self._error = f"Unexpected error: {err}"
            return self.async_show_progress_done(next_step_id="failed")
        return self.async_show_progress_done(next_step_id="finish")

    async def async_step_failed(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Show the error; submitting retries."""
        if user_input is not None:
            return await self.async_step_activate()
        return self.async_show_form(
            step_id="failed",
            data_schema=vol.Schema({}),
            description_placeholders={"error": self._error or "unknown", "name": self._name or ""},
        )

    # ---------------------------------------------------------------- finish
    async def async_step_finish(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        result = self._result
        assert result is not None and self._address is not None
        applied = self._apply and async_push_to_xiaomi_ble(self.hass, self._address, result.bind_key)
        data = {
            CONF_ADDRESS: self._address,
            CONF_NAME: self._name,
            CONF_BIND_KEY: result.bind_key,
            CONF_TOKEN: result.token,
            CONF_FIRMWARE: result.firmware,
        }

        if self.source == SOURCE_RECONFIGURE:
            return self.async_update_reload_and_abort(
                self._get_reconfigure_entry(),
                data=data,
                reason="reactivated",
                description_placeholders={"bind_key": result.bind_key},
            )

        placeholders = {
            "bind_key": result.bind_key,
            "token": result.token,
            "firmware": result.firmware or "unknown",
            "xiaomi_ble": "The key was saved to your Xiaomi BLE entry for this device and it is reloading."
            if applied
            else "No Xiaomi BLE entry for this device was found; paste the key when Xiaomi BLE asks for it.",
        }
        return self.async_create_entry(
            title=f"{self._name} ({self._address})" if self._name != self._address else self._address,
            data=data,
            description="activated",
            description_placeholders=placeholders,
        )
