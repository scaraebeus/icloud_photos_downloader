"""Handles username/password authentication and two-step authentication"""

import logging
import sys
import click
import pyicloud_ipd


class TwoStepAuthRequiredError(Exception):
    """
    Raised when 2SA is required. base.py catches this exception
    and sends an email notification.
    """


def authenticator(logger: logging.Logger, domain: str, list_devices: bool):
    """Wraping authentication with domain context"""
    def authenticate_(
            username,
            password,
            cookie_directory=None,
            raise_error_on_2sa=False,
            client_id=None,
    ) -> pyicloud_ipd.PyiCloudService:
        """Authenticate with iCloud username and password"""
        logger.debug("Authenticating...")
        while True:
            try:
                # If password not provided on command line variable will be set to None
                # and PyiCloud will attempt to retrieve from its keyring
                icloud = pyicloud_ipd.PyiCloudService(
                    domain,
                    username, password,
                    cookie_directory=cookie_directory,
                    client_id=client_id,
                )
                break
            except pyicloud_ipd.exceptions.PyiCloudNoStoredPasswordAvailableException:
                # Prompt for password if not stored in PyiCloud's keyring
                password = click.prompt("iCloud Password", hide_input=True)


        if (icloud.requires_2fa or icloud.requires_2sa) and list_devices:
            prompt_request_verification(icloud, logger)

        elif icloud.requires_2fa:
            if raise_error_on_2sa:
                raise TwoStepAuthRequiredError(
                    "Two-step/two-factor authentication is required"
                )
            logger.info("Two-step/two-factor authentication is required (2fa)")
            request_2fa(icloud, logger)

        elif icloud.requires_2sa:
            if raise_error_on_2sa:
                raise TwoStepAuthRequiredError(
                    "Two-step/two-factor authentication is required"
                )
            logger.info("Two-step/two-factor authentication is required (2sa)")
            request_2sa(icloud, logger)

        elif (not icloud.requires_2fa and not icloud.requires_2sa) and list_devices:
            logger.info("Two-step/two-factor authentication is not required at this time")

        return icloud
    return authenticate_


def request_2sa(icloud: pyicloud_ipd.PyiCloudService, logger: logging.Logger):
    """Request two-step authentication. Prompts for SMS or device"""
    devices = icloud.trusted_devices
    devices_count = len(devices)
    device_index = 0
    if devices_count > 0:
        for i, device in enumerate(devices):
            # pylint: disable-msg=consider-using-f-string
            print(
                "  %s: %s" %
                (i, device.get(
                    "deviceName", "SMS to %s" %
                    device.get("phoneNumber"))))
            # pylint: enable-msg=consider-using-f-string

        device_index = click.prompt(
            "Please choose an option:",
            default=0,
            type=click.IntRange(
                0,
                devices_count - 1))

    device = devices[device_index]
    if not icloud.send_verification_code(device):
        logger.error("Failed to send two-factor authentication code")
        sys.exit(1)

    code = click.prompt("Please enter two-factor authentication code")
    validate_code(icloud, logger, "2SA", code, device)


def request_2fa(icloud: pyicloud_ipd.PyiCloudService, logger: logging.Logger):
    """Request two-factor authentication."""
    code = click.prompt("Please enter two-factor authentication code")
    validate_code(icloud, logger, "2FA", code)


def prompt_request_verification(icloud: pyicloud_ipd.PyiCloudService, logger: logging.Logger):
    "List trusted devices for alternate 2SA/2FA verification"
    devices = icloud.trusted_devices
    devices_count = len(devices)
    device_index = 0

    if devices_count > 0:
        for i, device in enumerate(devices):
            # pylint: disable-msg=consider-using-f-string
            print(
                "  %s: %s" %
                (i, device.get(
                    "deviceName", "SMS to %s" %
                    device.get("phoneNumber"))))
            # pylint: enable-msg=consider-using-f-string

        # pylint: disable-msg=superfluous-parens
        print(f"  {devices_count}: Enter two-factor authentication code")
        # pylint: enable-msg=superfluous-parens
        device_index = click.prompt(
            "Please choose an option:",
            default = 0,
            type = click.IntRange(
                0,
                devices_count
            )
        )

        if device_index == devices_count:
            # We're using the 2FA code that was auto sent to the user's device
            type = "2FA"
            device = {}
        else:
            type = "2SA"
            device = devices[device_index]
            if not icloud.send_verification_code(device):
                logger.error("Failed to send two-factor authentication code")
                sys.exit(1)

        code = click.prompt("Please enter two-factor authentication code")
        validate_code(icloud, logger, type, code, device)


def validate_code(icloud: pyicloud_ipd.PyiCloudService, logger: logging.Logger, type: str, code: str, device: dict = None):
    if type.upper() == "2SA":
        if not icloud.validate_verification_code(device, code):
            logger.error("Failed to verify two-factor authentication code")
            sys.exit(1)

    elif type.upper() == "2FA":
        if not icloud.validate_2fa_code(code):
            logger.error("Failed to verify two-factor authentication code")
            sys.exit(1)
    else:
        logger.error("Unknown authentication type: {type}")
        sys.exit(1)

    logger.info(
        "Great, you're all set up. The script can now be run without "
        "user interaction until 2SA/2FA expires.\n"
        "You can set up email notifications for when "
        "the two-step authentication expires.\n"
        "(Use --help to view information about SMTP options.)"
    )

