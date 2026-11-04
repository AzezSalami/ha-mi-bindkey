"""Fixtures for Mi Bind Key tests."""

import pytest


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    """Allow loading custom_components/mi_bindkey."""
    yield


@pytest.fixture(autouse=True)
def _bluetooth(mock_bluetooth):
    """Run with a mocked Bluetooth stack."""
    yield
