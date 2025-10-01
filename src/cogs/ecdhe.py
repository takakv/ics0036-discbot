import os
import time

from Crypto.PublicKey import ECC
from nextcord import slash_command, Interaction, SlashOption
from nextcord.ext import commands

from src.commands.eph_dh import get_ec_keys, fetch_session_key, aes_decrypt
from src.utils.constants import Keys

USER_DATA_DIR = "userdata"
CHALLENGE_DATA_DIR = "userdata/ecdhe"


class ECDH(commands.Cog):
    @slash_command(name="ecdhe", description="Ephemeral ECDH.")
    async def ecdhe(self, interaction: Interaction):
        pass

    @ecdhe.subcommand(description="Get public key.")
    async def pub(self, interaction: Interaction):
        pub = Keys.P384.public_key()
        # Use singe quotes here since the backticks confuse some interpreters.
        pub_pem = f'```{pub.export_key(format="PEM")}```'
        await interaction.send(pub_pem, ephemeral=True)

    @ecdhe.subcommand(description="Get the ephemeral key.")
    async def eph(self, interaction: Interaction):
        user_id = interaction.user.id
        user_ephemeral_file = f"{CHALLENGE_DATA_DIR}/{user_id}.txt"

        if not os.path.isfile(user_ephemeral_file):
            ephemeral = ECC.generate(curve="p384")
            with open(user_ephemeral_file, "w") as f:
                data = ephemeral.export_key(format="PEM")
                f.write(data)
        else:
            file_creation_time = os.path.getctime(user_ephemeral_file)
            current_time = time.time()
            elapsed_minutes = (current_time - file_creation_time) / 60

            if elapsed_minutes > 5:
                ephemeral = ECC.generate(curve="p384")
                with open(user_ephemeral_file, "w") as f:
                    data = ephemeral.export_key(format="PEM")
                    f.write(data)
            else:
                ephemeral = ECC.import_key(open(user_ephemeral_file).read())

        ephemeral_pem = f'Ephemeral key:\n```{ephemeral.public_key().export_key(format="PEM")}```'
        await interaction.send(ephemeral_pem, ephemeral=True)

    @ecdhe.subcommand(description="Establish AES-128 key and decrypt.")
    async def challenge(self, interaction: Interaction,
                        s_key: str = SlashOption(description="Your (long term) public key."),
                        e_key: str = SlashOption(description="Your ephemeral public key."),
                        ct: str = SlashOption(description="The AES-128 encrypted message (hex).", max_length=128),
                        iv: str = SlashOption(description="The AES-128 initialization vector (hex).",
                                              min_length=32, max_length=32)):
        user_id = interaction.user.id
        user_ephemeral_file = f"{CHALLENGE_DATA_DIR}/{user_id}.txt"

        if not os.path.isfile(user_ephemeral_file):
            await interaction.send("No active session: generate a new session key with `/ecdhe eph`!", ephemeral=True)
            return

        try:
            s_pk, e_pk = await get_ec_keys(interaction, s_key, e_key)
        except RuntimeError:
            return

        ephemeral = ECC.import_key(open(user_ephemeral_file).read())
        os.remove(user_ephemeral_file)

        session_key = fetch_session_key(Keys.P384, s_pk, ephemeral, e_pk)

        try:
            message = await aes_decrypt(interaction, ct, iv, session_key)
        except RuntimeError:
            return

        await interaction.send(message, ephemeral=True)
