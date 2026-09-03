
"""
Account/Authentication related commands.

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
import getpass
from typing import Callable

import click

from proton.vpn.cli._cli_constants import PROGRAM_NAME
from proton.vpn.cli.core.controller import Controller
from proton.vpn.cli.core.exceptions import \
    Authentication2FAFailedError, \
    AuthenticationFailedError, \
    SignoutRequiredError
from proton.vpn.cli.core.run_async import run_async
from proton.vpn.session.exceptions import \
    SecurityKeyError, \
    SecurityKeyNotFoundError, \
    SecurityKeyPINInvalidError


SIGNIN_COMMAND = "signin"
SIGNOUT_COMMAND = "signout"


@click.command(
    name=SIGNIN_COMMAND,
    epilog=f"""\b
           Examples:
             {PROGRAM_NAME} {SIGNIN_COMMAND} user@proton.me"""
)
@click.argument('username')
@click.option(
    "--totp",
    is_flag=True,
    help="Use an authenticator app or recovery code instead of a security key."
)
@click.pass_context
@run_async
async def signin(ctx, username: str, totp: bool):
    """
    Sign in to Proton VPN with your credentials.

    Arguments:

    USERNAME Proton account username
    """
    controller = await Controller.create(params=ctx.obj, click_ctx=ctx)
    try:
        if await controller.login(username, getpass.getpass):
            await _authenticate_2fa(controller, username, use_code=totp)
        elif totp:
            click.echo("Ignoring --totp: this account has no two-factor authentication enabled.")
        click.echo(f"Successfully signed in as '{controller.account_name}'")
    except SignoutRequiredError as exc:
        raise click.ClickException(
            "Already signed in, please sign out first before changing accounts."
        ) from exc
    except AuthenticationFailedError as exc:
        raise click.ClickException(
            "Authentication failed. Please check your username and password and try again."
        ) from exc
    except Authentication2FAFailedError as exc:
        raise click.ClickException(
            "Invalid two-factor authentication code. Please try again."
        ) from exc
    except SecurityKeyPINInvalidError as exc:
        raise click.ClickException(
            "Incorrect PIN. Please try again."
        ) from exc
    except SecurityKeyError as exc:
        raise click.ClickException(
            "Security key authentication failed. Please try again."
        ) from exc


@click.command(
    name=SIGNOUT_COMMAND,
    epilog=f"""\b
           Examples:
             {PROGRAM_NAME} {SIGNOUT_COMMAND}
           \b
           To sign in again:
             {PROGRAM_NAME} {SIGNIN_COMMAND}"""
)
@click.pass_context
@run_async
async def signout(ctx):
    """Sign out from Proton VPN and clear local credentials."""
    controller = await Controller.create(params=ctx.obj, click_ctx=ctx)
    was_connected = await controller.is_connection_active()
    await controller.logout()
    completion_message = "You have been successfully signed out."
    if was_connected:
        completion_message = "VPN connection terminated and you've been successfully signed out."

    click.echo(completion_message)


@click.command()
@click.pass_context
@run_async
async def info(ctx):
    """Display your Proton VPN account information."""
    controller = await Controller.create(params=ctx.obj, click_ctx=ctx)
    click.echo(f"Account: '{controller.account_name}'")


def _totp_signin_command(username: str) -> str:
    return f"'{PROGRAM_NAME} {SIGNIN_COMMAND} {username} --totp'"


def _ask_to_insert_security_key() -> None:
    """Waits for the user to insert a security key.

    Aborts when there is nobody at the terminal to ask, because click turns
    the end of stdin into a click.Abort.
    """
    # Empty default lets a bare Enter through.
    click.prompt(
        "No security key detected. Insert your security key and press Enter",
        default="",
        show_default=False
    )


async def _authenticate_2fa(
    controller: Controller,
    username: str,
    use_code: bool,
    ask_to_insert_key: Callable[[], None] = _ask_to_insert_security_key
):
    """Completes the second factor the account requires.

    :param ask_to_insert_key: waits for a security key to be inserted.
    """
    if use_code or not controller.supports_security_key:
        while not await controller.submit_2fa_code(
            click.prompt("2FA Token", hide_input=True)
        ):
            click.echo("Invalid two-factor authentication code. Please try again.")
        return

    click.echo(
        "Waiting for security key... "
        f"(or run {_totp_signin_command(username)} to use an authenticator code)"
    )
    while True:
        try:
            assertion = await controller.generate_security_key_assertion(
                SecurityKeyPrompt()
            )
            break
        except SecurityKeyNotFoundError:
            # A key that was never inserted and one that was unplugged while
            # waiting for a touch are both reported this way, so ask again.
            ask_to_insert_key()

    # Signing in takes a few requests, so confirm the touch registered
    # instead of leaving the user pressing the key again.
    click.echo("Security key read. Signing in...")
    await controller.submit_security_key_assertion(assertion)


class SecurityKeyPrompt:
    """Prompts for whatever the security key asks for while it is being read.

    Implements the UserInteraction interface proton-vpn-api-core calls into.
    """

    def prompt_up(self) -> None:
        """Called when the security key is awaiting a user presence check."""
        click.echo("Press the button on your security key.")

    def request_pin(self, *_args, **_kwargs) -> str:
        """Called when the security key requires a PIN."""
        return click.prompt("Security key PIN", hide_input=True)

    def request_uv(self, *_args, **_kwargs) -> bool:
        """Called when the security key is about to request user verification."""
        return True

    def request_key_selection(self) -> None:
        """Called when one of several security keys must be tapped."""
        click.echo("Multiple security keys were found. Tap the one you want to use.")
