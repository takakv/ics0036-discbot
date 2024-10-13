from nextcord import slash_command, Interaction, SlashOption
from nextcord.ext import commands
from peewee import DoesNotExist

from algos.elgamal import EGCiphertext
from utils.constants import Keys, Secrets
from utils.database import EGToken


class ElGamalAuthentication(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @slash_command(name="eg_auth",
                   description="Authenticate using ElGamal.",
                   dm_permission=True)
    async def authenticate(self, interaction: Interaction):
        pass

    @authenticate.subcommand(description="Show the previous successful token.")
    async def show_token(self, interaction: Interaction):
        try:
            token = EGToken.select().where(EGToken.accepted).order_by(EGToken.id.desc()).get()
        except DoesNotExist:
            await interaction.send("No successful authentications yet.", ephemeral=True)
            return

        s = token.token.split(" ")
        u = int(s[0], 10)
        v = int(s[1], 10)

        await interaction.send(f'```u=\n{u}\nv=\n{v}```')

    @authenticate.subcommand(description="Connect to the server.")
    async def connect(self, interaction: Interaction,
                      u: str = SlashOption(description="The randomness component."),
                      v: str = SlashOption(description="The message component.")):
        try:
            u = int(u, 10)
            v = int(v, 10)
        except ValueError:
            await interaction.send("The components must be integers!", ephemeral=True)
            return

        serialised = f"{u} {v}"
        uid = interaction.user.id

        token_is_accepted = False

        try:
            EGToken.get(EGToken.token == serialised)
        except DoesNotExist:
            token_is_accepted = True

        ct = EGCiphertext(u, v)
        try:
            res = Keys.EG.decrypt(ct)
        except ValueError as e:
            await interaction.send(str(e), ephemeral=True)
            raise RuntimeError

        message = "Invalid token! Access denied."

        if res == Secrets.SYM_SECRET:
            message = "Access granted."
            token_is_valid = True
            if not token_is_accepted:
                # Do not check usage before verifying decryption to
                # help students detect whether their token would have worked.
                message = "Token has already been used."
        else:
            token_is_valid = False
            token_is_accepted = False

        EGToken.create(token=serialised, accepted=token_is_accepted, valid=token_is_valid, author=uid)
        await interaction.send(message, ephemeral=True)
