"""
Copyright (c) 2026 Proton AG

Provides CLI command testing for account related functionality.

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
from unittest.mock import AsyncMock, PropertyMock
import pytest

import click
from click.testing import CliRunner

from proton.vpn.cli import app as app_cmd
from proton.vpn.cli.commands.account import \
    _authenticate_2fa, SIGNIN_COMMAND, SIGNOUT_COMMAND
from proton.vpn.cli.core.exceptions import \
    Authentication2FAFailedError, \
    AuthenticationFailedError, \
    SignoutRequiredError
from proton.vpn.session.exceptions import \
    SecurityKeyError, \
    SecurityKeyNotFoundError, \
    SecurityKeyPINInvalidError


def _requires_2fa(controller_mock: AsyncMock, security_key: bool):
    controller_mock.login.return_value = True
    type(controller_mock).supports_security_key = \
        PropertyMock(return_value=security_key)


def test_signin_fails_when_already_signed_in(
    runner: CliRunner,
    test_context: click.Context,
    controller_mock: AsyncMock
):
    def login(*_):
        raise SignoutRequiredError

    controller_mock.login.side_effect = login

    result = runner.invoke(
        app_cmd,
        [SIGNIN_COMMAND, "name@email.com"],
        parent=test_context
    )

    assert result.exit_code == 1
    assert "Already signed in, please sign out first before changing accounts."\
        in result.output


def test_signin_fails_when_authentication_fails(
    runner: CliRunner,
    test_context: click.Context,
    controller_mock: AsyncMock
):
    def login(*_):
        raise AuthenticationFailedError

    controller_mock.login.side_effect = login

    result = runner.invoke(
        app_cmd,
        [SIGNIN_COMMAND, "name@email.com"],
        parent=test_context
    )

    assert result.exit_code == 1
    assert "Authentication failed. Please check your username and password and try again."\
        in result.output


def test_signin_fails_when_the_2fa_code_is_rejected(
    runner: CliRunner,
    test_context: click.Context,
    controller_mock: AsyncMock
):
    _requires_2fa(controller_mock, security_key=False)
    controller_mock.submit_2fa_code.side_effect = Authentication2FAFailedError

    result = runner.invoke(
        app_cmd,
        [SIGNIN_COMMAND, "name@email.com"],
        parent=test_context,
        input="123456\n"
    )

    assert result.exit_code == 1
    assert "Invalid two-factor authentication code. Please try again." in result.output


@pytest.mark.parametrize("error, expected_message", [
    (
        SecurityKeyPINInvalidError,
        "Incorrect PIN. Please try again."
    ),
    (
        SecurityKeyError,
        "Security key authentication failed. Please try again."
    ),
])
def test_signin_fails_when_the_security_key_cannot_be_used(
    error,
    expected_message,
    runner: CliRunner,
    test_context: click.Context,
    controller_mock: AsyncMock
):
    # Raised from where they really come from, so that the retry loop is
    # proven to let them through instead of asking for the key again.
    _requires_2fa(controller_mock, security_key=True)
    controller_mock.generate_security_key_assertion.side_effect = error

    result = runner.invoke(
        app_cmd,
        [SIGNIN_COMMAND, "name@email.com"],
        parent=test_context
    )

    assert result.exit_code == 1
    assert expected_message in result.output


def test_signin_echoes_account_name_on_success(
    controller_mock: AsyncMock,
    cli_invoke
):
    type(controller_mock).account_name = \
        PropertyMock(return_value="testuser@proton.me")

    result = cli_invoke([SIGNIN_COMMAND, "testuser@proton.me"])

    assert result.exit_code == 0
    assert "Successfully signed in as 'testuser@proton.me'" in result.output


def test_signin_warns_that_the_totp_flag_is_ignored_without_2fa(
    controller_mock: AsyncMock,
    cli_invoke
):
    # controller_mock.login returns False, so no second factor is required.
    result = cli_invoke([SIGNIN_COMMAND, "name@email.com", "--totp"])

    assert result.exit_code == 0
    assert "Ignoring --totp" in result.output


def test_signin_submits_a_2fa_code_when_the_totp_flag_is_used(
    runner: CliRunner,
    test_context: click.Context,
    controller_mock: AsyncMock
):
    _requires_2fa(controller_mock, security_key=True)

    runner.invoke(
        app_cmd,
        [SIGNIN_COMMAND, "name@email.com", "--totp"],
        parent=test_context,
        input="123456\n"
    )

    controller_mock.submit_2fa_code.assert_awaited_once_with("123456")
    controller_mock.generate_security_key_assertion.assert_not_awaited()


def test_signin_submits_a_2fa_code_when_no_security_key_is_registered(
    runner: CliRunner,
    test_context: click.Context,
    controller_mock: AsyncMock
):
    _requires_2fa(controller_mock, security_key=False)

    runner.invoke(
        app_cmd,
        [SIGNIN_COMMAND, "name@email.com"],
        parent=test_context,
        input="123456\n"
    )

    controller_mock.submit_2fa_code.assert_awaited_once_with("123456")


def test_signin_reprompts_until_the_2fa_code_is_accepted(
    runner: CliRunner,
    test_context: click.Context,
    controller_mock: AsyncMock
):
    _requires_2fa(controller_mock, security_key=False)
    controller_mock.submit_2fa_code.side_effect = [False, True]

    result = runner.invoke(
        app_cmd,
        [SIGNIN_COMMAND, "name@email.com"],
        parent=test_context,
        input="000000\n123456\n"
    )

    assert controller_mock.submit_2fa_code.await_count == 2
    assert "Invalid two-factor authentication code." in result.output


def test_signin_uses_the_security_key_when_one_is_registered(
    controller_mock: AsyncMock,
    cli_invoke
):
    _requires_2fa(controller_mock, security_key=True)

    async def read_key(_prompt):
        click.echo("<key read>")
        return "assertion"

    controller_mock.generate_security_key_assertion.side_effect = read_key

    result = cli_invoke([SIGNIN_COMMAND, "name@email.com"])

    controller_mock.submit_security_key_assertion.assert_awaited_once_with("assertion")
    controller_mock.submit_2fa_code.assert_not_awaited()
    assert "Waiting for security key..." in result.output
    # The confirmation is only worth printing if it lands after the touch.
    assert result.output.index("<key read>") \
        < result.output.index("Security key read. Signing in...")


@pytest.mark.asyncio
async def test_2fa_asks_for_the_security_key_again_when_it_is_not_detected(
    controller_mock: AsyncMock
):
    _requires_2fa(controller_mock, security_key=True)
    controller_mock.generate_security_key_assertion.side_effect = [
        SecurityKeyNotFoundError, None
    ]

    await _authenticate_2fa(
        controller_mock, "name@email.com", use_code=False,
        ask_to_insert_key=lambda: None
    )

    assert controller_mock.generate_security_key_assertion.await_count == 2


@pytest.mark.asyncio
async def test_2fa_gives_up_on_the_security_key_when_nobody_can_be_asked_for_it(
    controller_mock: AsyncMock
):
    _requires_2fa(controller_mock, security_key=True)
    controller_mock.generate_security_key_assertion.side_effect = SecurityKeyNotFoundError

    def nobody_to_ask():
        # What click.prompt does once stdin has run out.
        raise click.Abort

    with pytest.raises(click.Abort):
        await _authenticate_2fa(
            controller_mock, "name@email.com", use_code=False,
            ask_to_insert_key=nobody_to_ask
        )


def test_signin_echoes_empty_name_when_account_info_missing_name(
    controller_mock: AsyncMock,
    cli_invoke
):
    type(controller_mock).account_name = \
        PropertyMock(return_value=None)

    result = cli_invoke([SIGNIN_COMMAND, "testuser@proton.me"])

    assert result.exit_code == 0
    assert "Successfully signed in as 'None'" in result.output


def test_signout_echoes_signed_out_message_when_not_connected(
    controller_mock: AsyncMock,
    cli_invoke
):
    controller_mock.is_connection_active.return_value = False

    result = cli_invoke([SIGNOUT_COMMAND])

    assert result.exit_code == 0
    assert "You have been successfully signed out." in result.output


def test_signout_echoes_connection_terminated_message_when_connected(
    controller_mock: AsyncMock,
    cli_invoke
):
    controller_mock.is_connection_active.return_value = True

    result = cli_invoke([SIGNOUT_COMMAND])

    assert result.exit_code == 0
    assert "VPN connection terminated and you've been successfully signed out." in result.output
