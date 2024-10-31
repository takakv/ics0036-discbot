from nextcord import slash_command, Interaction, SlashOption, Attachment
from nextcord.ext import commands


class CSR(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @slash_command(name="csr",
                   description="Request a new certificate.",
                   dm_permission=True)
    async def authenticate(self, interaction: Interaction,
                           csr: Attachment = SlashOption(description="The certificate signing request.")):
        await interaction.send("Not yet implemented")
