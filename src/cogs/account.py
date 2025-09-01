import logging
import os
import subprocess
import tempfile
from pathlib import Path

import jwt
import ldap
import nextcord
from dotenv import load_dotenv
from jwt import DecodeError, ExpiredSignatureError
from nextcord import slash_command, Interaction, SlashOption, File
from nextcord.ext import commands

from src.tokens import get_student_token
from src.utils.constants import Secrets

load_dotenv()
GUILD_IDS = [int(os.getenv("GUILD_ID"))]
ROLE_ID = int(os.getenv("ROLE_ID"))

USER_DATA_DIR = "userdata"
USED_TOKENS_FILE = "used_tokens.txt"


async def register_user(interaction: Interaction, token: str) -> tuple[bool, str]:
    # User is already registered, maybe with another token.
    # By design, if the user has left the server and rejoins, no automatic
    # or token re-registration is possible!
    user_id = interaction.user.id
    user_datafile = f"{USER_DATA_DIR}/{user_id}.txt"

    if os.path.isfile(user_datafile):
        return False, "You are already registered"

    try:
        data = jwt.decode(token, Secrets.JWT_SECRET, algorithms="HS256")
    except (DecodeError, ExpiredSignatureError) as err:
        print(f"User '{user_id}' submitted invalid token '{token}'")
        return False, str(err)

    with open(USED_TOKENS_FILE, "r") as f:
        used_tokens = f.readlines()

    token_string = f"{token}\n"
    if token_string in used_tokens:
        return False, "Token already used"

    try:
        await interaction.user.add_roles(interaction.guild.get_role(ROLE_ID))
    except nextcord.errors.Forbidden:
        return False, "Bot lacks necessary permissions"

    # Do not expire the token or register the user before
    # the user actually has the role.
    with open(user_datafile, "w") as f:
        f.write(f"{data['name']}\n{data['studentCode']}\n{data['uniID']}\n{data['idCode']}")

    with open(USED_TOKENS_FILE, "a") as f:
        f.write(token_string)

    return True, ""


class Account(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @slash_command(name="account", description="Register as a student.", guild_ids=GUILD_IDS)
    async def account(self, interaction: Interaction):
        pass

    @account.subcommand(description="Register with your token.")
    async def reg(self, interaction: Interaction,
                  token: str = SlashOption("token", "The registration token.")):
        ok, err = await register_user(interaction, token)
        if ok:
            message = "Registered successfully"
        else:
            message = f"Registration error! {err}"
        await interaction.send(message, ephemeral=True)

    @account.subcommand(description="Request a registration token.")
    async def req(self, interaction: Interaction,
                  idc: str = SlashOption("idcode", "Your Estonian ID code.",
                                         min_length=11, max_length=11)):
        if not idc.isdigit():
            await interaction.response.send_message(
                "The ID code must be exactly 11 digits.", ephemeral=True
            )
            return

        l = ldap.initialize("ldaps://esteid.ldap.sk.ee/")
        l.simple_bind_s("", "")
        res = l.search_s("c=EE", ldap.SCOPE_SUBTREE, f"(serialNumber=PNOEE-{idc})")

        if len(res) == 0:
            await interaction.send(f"No certificates found for ID code `{idc}`", ephemeral=True)
            return

        cn = ""
        cert_bytes = b""

        for dn, entry in res:
            if "ou=authentication" not in dn.lower() or "o=mobile-id" in dn.lower():
                continue

            cn = entry.get("cn", [b""])[0].decode()
            cert_bytes = entry.get("userCertificate;binary", [b""])[0]

        l.unbind_s()

        if cn == "" or cert_bytes == b"":
            await interaction.send(f"No authentication certificate found for `{cn}`", ephemeral=True)
            return

        cn_objects = cn.split(",")
        surname = cn_objects[0]
        given_name = cn_objects[1]

        token = get_student_token(given_name, surname, idc)
        if token is None:
            logging.warning(f"Student ({interaction.user.id}) with CN '{cn}' could not be found")
            await interaction.send(
                "Could not validate course registration. Send a message to @taka.kv for a code.",
                ephemeral=True)
            return

        # Create temporary files for the certificate and plaintext
        with tempfile.NamedTemporaryFile("wb", delete=False) as cert_file, \
                tempfile.NamedTemporaryFile(delete=False, mode="w", encoding="utf-8",
                                            prefix="token_", suffix=".txt") as token_file:

            cert_file.write(cert_bytes)
            cert_file_path = Path(cert_file.name)

            token_file.write(token)
            token_file_path = Path(token_file.name)

        cdoc_path = Path(f"{USER_DATA_DIR}/{idc}.cdoc")

        cdoc_cmd = [
            "java",
            "-jar",
            "./vendor/cdoc4j-util-1.5.jar",
            "encrypt",
            "-f", str(token_file_path),
            "-r", str(cert_file_path),
            "-o", str(cdoc_path),
        ]

        result = subprocess.run(cdoc_cmd, capture_output=True, text=True)

        cert_file_path.unlink(missing_ok=True)
        token_file_path.unlink(missing_ok=True)

        if result.returncode != 0 or "CDOC composed successfully!" not in result.stdout:
            await interaction.send(
                "Internal error encrypting the token. Send a message to @taka.kv for a code.",
                ephemeral=True)
            cdoc_path.unlink(missing_ok=True)
            return

        logging.info(f"Issued token '{token}' for user '{interaction.user.id}'")

        await interaction.response.send_message(
            "To decrypt your token, you will need your ID card or equivalent, "
            "and the [DigiDoc](https://www.id.ee/en/article/install-id-software/) Estonian ID software.\n"
            "If you are unable to decrypt the container, send a message to @taka.kv for a code.",
            file=File(cdoc_path, filename="token.cdoc"), ephemeral=True
        )
        cdoc_path.unlink(missing_ok=True)
