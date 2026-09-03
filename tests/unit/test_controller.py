"""
Copyright (c) 2025 Proton AG

This file is part of Proton VPN.

Proton VPN is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Proton VPN is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
"""
import asyncio
from unittest.mock import AsyncMock, Mock, PropertyMock
import pytest

from click.core import Context as ClickContext

from proton.session.exceptions import ProtonAPIAuthenticationNeeded
from proton.vpn.cli.core.controller import Controller, Params, Feature
from proton.vpn.cli.core.exceptions import \
    Authentication2FAFailedError, \
    AuthenticationFailedError, \
    AuthenticationRequiredError, \
    RequiresHigherTierError, \
    SignoutRequiredError
from proton.vpn.connection import states
from proton.vpn.core.api import ProtonVPNAPI, VPNDataRefresher, Settings
from proton.vpn.core.vpnconnector import VPNConnector
from proton.vpn.session.dataclasses import LoginResult
from proton.vpn.session.exceptions import \
    SecurityKeyError, \
    SecurityKeyNotFoundError
from proton.vpn.session.servers.types import LogicalServer, ServerFeatureEnum


@pytest.mark.asyncio
async def test_connect_fails_if_not_logged_in():
    api_mock = Mock()
    params_mock = Mock()
    click_ctx_mock = Mock()
    server = Mock()

    api_mock.is_user_logged_in.return_value = False
    controller = Controller(params_mock, click_ctx_mock, api_mock)
    with pytest.raises(AuthenticationRequiredError):
        await controller.connect(server)


@pytest.mark.asyncio
async def test_find_logical_server_fails_if_not_logged_in():
    api_mock = Mock()
    params_mock = Mock()
    click_ctx_mock = Mock()

    api_mock.is_user_logged_in.return_value = False
    controller = Controller(params_mock, click_ctx_mock, api_mock)
    with pytest.raises(AuthenticationRequiredError):
        await controller.find_logical_server()


@pytest.mark.asyncio
async def test_find_logical_server_fails_when_specifying_server_name_as_free_user():
    api_mock = Mock()
    params_mock = Mock()
    click_ctx_mock = Mock()

    # mock free user tier
    user_tier_property = PropertyMock(return_value=0)
    type(api_mock).user_tier = user_tier_property

    controller = Controller(params_mock, click_ctx_mock, api_mock)
    with pytest.raises(RequiresHigherTierError):
        await controller.find_logical_server(server_name="name")


@pytest.mark.asyncio
async def test_find_logical_server_fails_when_specifying_country_as_free_user():
    api_mock = Mock()
    params_mock = Mock()
    click_ctx_mock = Mock()

    # mock free user tier
    user_tier_property = PropertyMock(return_value=0)
    type(api_mock).user_tier = user_tier_property

    controller = Controller(params_mock, click_ctx_mock, api_mock)
    with pytest.raises(RequiresHigherTierError):
        await controller.find_logical_server(country="FR")


@pytest.mark.asyncio
async def test_find_logical_server_fails_when_specifying_city_as_free_user():
    api_mock = Mock()
    params_mock = Mock()
    click_ctx_mock = Mock()

    # mock free user tier
    user_tier_property = PropertyMock(return_value=0)
    type(api_mock).user_tier = user_tier_property

    controller = Controller(params_mock, click_ctx_mock, api_mock)
    with pytest.raises(RequiresHigherTierError):
        await controller.find_logical_server(city="Milan")


@pytest.mark.asyncio
async def test_find_logical_server_fails_when_requesting_features_as_free_user():
    api_mock = Mock()
    params_mock = Mock()
    click_ctx_mock = Mock()

    # mock free user tier
    user_tier_property = PropertyMock(return_value=0)
    type(api_mock).user_tier = user_tier_property

    controller = Controller(params_mock, click_ctx_mock, api_mock)
    with pytest.raises(RequiresHigherTierError):
        await controller.find_logical_server(features=ServerFeatureEnum.P2P)


@pytest.mark.asyncio
async def test_find_logical_server_fails_when_requesting_random_server_as_free_user():
    api_mock = Mock()
    params_mock = Mock()
    click_ctx_mock = Mock()

    # mock free user tier
    user_tier_property = PropertyMock(return_value=0)
    type(api_mock).user_tier = user_tier_property

    controller = Controller(params_mock, click_ctx_mock, api_mock)
    with pytest.raises(RequiresHigherTierError):
        await controller.find_logical_server(random_server=True)


@pytest.mark.asyncio
async def test_connect_disconnects_when_connection_fails():
    api_mock = AsyncMock(spec=ProtonVPNAPI)
    api_mock.refresher = AsyncMock(spec=VPNDataRefresher)
    params_mock = Mock(spec=Params)
    click_ctx_mock = Mock(spec=ClickContext)
    vpn_connector_mock = Mock(spec=VPNConnector)
    server = Mock(spec=LogicalServer)

    # mock inactive connection
    vpn_connector_mock.is_connection_active = False
    api_mock.get_vpn_connector.return_value = vpn_connector_mock

    # grab subscribers to connection events and
    # send them an Error event to simulate connection failure
    # followed by a Disconnected event to indicate end of disconnection
    def notify_event(subscriber):
        if not notify_event.error_sent:
            # first we let the controller know the connection failed
            subscriber.status_update(states.Error())
            notify_event.error_sent = True
        else:
            # then we let it know the "disconnection" has completed
            subscriber.status_update(states.Disconnected)
    notify_event.error_sent = False
    vpn_connector_mock.register.side_effect = notify_event

    controller = Controller(params_mock, click_ctx_mock, api_mock)
    await controller.connect(server)
    vpn_connector_mock.disconnect.assert_called_once()


@pytest.mark.asyncio
async def test_get_all_countries_raises_authentication_required_exception_when_user_is_not_logged_in():
    api_mock = AsyncMock(spec=ProtonVPNAPI)
    api_mock.is_user_logged_in.return_value = False
    params_mock = Mock(spec=Params)
    click_ctx_mock = Mock(spec=ClickContext)
    controller = Controller(params_mock, click_ctx_mock, api_mock)

    with pytest.raises(AuthenticationRequiredError):
        await controller.get_all_countries()


@pytest.mark.asyncio
async def test_save_feature_setting_raises_exception_when_not_signed_in():
    api_mock = AsyncMock(spec=ProtonVPNAPI)
    api_mock.is_user_logged_in.return_value = False
    params_mock = Mock(spec=Params)
    click_ctx_mock = Mock(spec=ClickContext)
    controller = Controller(params_mock, click_ctx_mock, api_mock)

    with pytest.raises(AuthenticationRequiredError):
        await controller.save_feature_setting(Mock(), Mock())


@pytest.mark.asyncio
async def test_save_feature_setting_raises_exception_when_feature_requires_higher_tier():
    api_mock = AsyncMock(spec=ProtonVPNAPI)
    api_mock.is_user_logged_in.return_value = True
    api_mock.user_tier = 0  # Free tier
    params_mock = Mock(spec=Params)
    click_ctx_mock = Mock(spec=ClickContext)
    controller = Controller(params_mock, click_ctx_mock, api_mock)
    feature_mock = Mock(spec=Feature)
    feature_mock.available_on_free_tier = False

    with pytest.raises(RequiresHigherTierError):
        await controller.save_feature_setting(feature_mock, Mock())


@pytest.mark.asyncio
async def test_get_feature_setting_raises_exception_when_not_signed_in():
    api_mock = AsyncMock(spec=ProtonVPNAPI)
    api_mock.is_user_logged_in.return_value = False
    params_mock = Mock(spec=Params)
    click_ctx_mock = Mock(spec=ClickContext)
    controller = Controller(params_mock, click_ctx_mock, api_mock)

    with pytest.raises(AuthenticationRequiredError):
        await controller.get_feature_setting(Mock())


@pytest.mark.asyncio
async def test_save_settings_waits_for_confirmation_when_requesting_paying_connection_features():
    api_mock = AsyncMock(spec=ProtonVPNAPI)
    params_mock = Mock(spec=Params)
    click_ctx_mock = Mock(spec=ClickContext)
    vpn_connector_mock = Mock(spec=VPNConnector)
    settings = Settings.default(user_tier=1)

    # mock paying user
    api_mock.user_tier = 1

    # mock active connection
    vpn_connector_mock.is_connected = True
    api_mock.get_vpn_connector.return_value = vpn_connector_mock

    # mock Connection event confirmation after features request
    def notify_event(subscriber):
        subscriber.status_update(states.Connected)
    vpn_connector_mock.register.side_effect = notify_event

    controller = Controller(params_mock, click_ctx_mock, api_mock)
    await controller.save_settings(settings)

    # check that a Connection event listener was registered
    vpn_connector_mock.register.assert_called_once()
    api_mock.save_settings.assert_called_with(settings)


@pytest.mark.asyncio
async def test_save_settings_does_not_wait_for_confirmation_when_requesting_free_connection_features():
    api_mock = AsyncMock(spec=ProtonVPNAPI)
    params_mock = Mock(spec=Params)
    click_ctx_mock = Mock(spec=ClickContext)
    vpn_connector_mock = Mock(spec=VPNConnector)
    settings = Settings.default(user_tier=0)

    # mock free user
    api_mock.user_tier = 0

    # mock active connection
    vpn_connector_mock.is_connected = True
    api_mock.get_vpn_connector.return_value = vpn_connector_mock

    controller = Controller(params_mock, click_ctx_mock, api_mock)
    await controller.save_settings(settings)

    # check that a Connection event listener was not registered
    vpn_connector_mock.register.assert_not_called()
    api_mock.save_settings.assert_called_with(settings)


def _api_mock() -> AsyncMock:
    api_mock = AsyncMock(spec=ProtonVPNAPI)
    api_mock.is_user_logged_in.return_value = False
    return api_mock


def _controller(api_mock: AsyncMock) -> Controller:
    return Controller(Mock(spec=Params), Mock(spec=ClickContext), api_mock)


def _login_result(
    success: bool = True,
    authenticated: bool = True,
    twofa_required: bool = False
) -> LoginResult:
    return LoginResult(
        success=success,
        authenticated=authenticated,
        twofa_required=twofa_required
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("twofa_required", [True, False])
async def test_login_returns_whether_2fa_is_still_required(twofa_required):
    api_mock = _api_mock()
    api_mock.login.return_value = _login_result(
        success=not twofa_required, twofa_required=twofa_required
    )

    assert await _controller(api_mock).login("user", lambda: "pass") is twofa_required


@pytest.mark.asyncio
async def test_login_fails_when_already_signed_in():
    api_mock = _api_mock()
    api_mock.is_user_logged_in.return_value = True

    with pytest.raises(SignoutRequiredError):
        await _controller(api_mock).login("user", lambda: "pass")


@pytest.mark.asyncio
async def test_login_fails_when_the_password_is_rejected():
    api_mock = _api_mock()
    api_mock.login.return_value = _login_result(success=False, authenticated=False)

    with pytest.raises(AuthenticationFailedError):
        await _controller(api_mock).login("user", lambda: "pass")


@pytest.mark.asyncio
@pytest.mark.parametrize("accepted", [True, False])
async def test_submit_2fa_code_returns_whether_the_code_was_accepted(accepted):
    api_mock = _api_mock()
    api_mock.submit_2fa_code.return_value = _login_result(
        success=accepted, twofa_required=not accepted
    )

    assert await _controller(api_mock).submit_2fa_code("123456") is accepted


@pytest.mark.asyncio
async def test_submit_2fa_code_fails_when_the_api_invalidates_the_session():
    api_mock = _api_mock()
    api_mock.submit_2fa_code.side_effect = ProtonAPIAuthenticationNeeded(
        401, {}, {"Code": 8002, "Error": "Incorrect login credentials"}
    )

    with pytest.raises(Authentication2FAFailedError):
        await _controller(api_mock).submit_2fa_code("123456")


@pytest.mark.asyncio
async def test_supports_security_key_follows_the_api():
    api_mock = _api_mock()
    type(api_mock).supports_fido2 = PropertyMock(return_value=True)

    assert _controller(api_mock).supports_security_key is True


@pytest.mark.asyncio
async def test_generate_security_key_assertion_returns_what_the_key_produced():
    api_mock = _api_mock()
    assertion = Mock()
    api_mock.generate_2fa_fido2_assertion.return_value = assertion

    read = await _controller(api_mock).generate_security_key_assertion(Mock())

    assert read is assertion


@pytest.mark.asyncio
async def test_submit_security_key_assertion_submits_it():
    api_mock = _api_mock()
    assertion = Mock()
    api_mock.submit_2fa_fido2.return_value = _login_result()

    await _controller(api_mock).submit_security_key_assertion(assertion)

    api_mock.submit_2fa_fido2.assert_awaited_once_with(assertion)


@pytest.mark.asyncio
async def test_generate_security_key_assertion_lets_security_key_errors_through():
    api_mock = _api_mock()
    api_mock.generate_2fa_fido2_assertion.side_effect = SecurityKeyNotFoundError("nope")

    # The command layer maps these to messages, so they must not be swallowed
    # or renamed on the way out.
    with pytest.raises(SecurityKeyNotFoundError):
        await _controller(api_mock).generate_security_key_assertion(Mock())

    # One failed read ends the attempt, the key is not re-armed here.
    assert api_mock.generate_2fa_fido2_assertion.await_count == 1


@pytest.mark.asyncio
async def test_submit_security_key_assertion_fails_when_it_is_rejected():
    api_mock = _api_mock()
    api_mock.submit_2fa_fido2.return_value = _login_result(
        success=False, twofa_required=True
    )

    with pytest.raises(SecurityKeyError):
        await _controller(api_mock).submit_security_key_assertion(Mock())


@pytest.mark.asyncio
async def test_generate_security_key_assertion_stops_the_key_waiting_when_cancelled():
    api_mock = _api_mock()
    waiting = asyncio.Event()
    cancel_tokens = []

    async def wait_for_a_touch(_user_interaction, cancel_assertion):
        cancel_tokens.append(cancel_assertion)
        waiting.set()
        await asyncio.sleep(3600)

    api_mock.generate_2fa_fido2_assertion.side_effect = wait_for_a_touch

    task = asyncio.create_task(
        _controller(api_mock).generate_security_key_assertion(Mock())
    )
    await waiting.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # The key is told to stop waiting, so the CLI can exit right away.
    assert cancel_tokens[0].is_set()
