import base64

import binascii
import nextcord
from Crypto.Cipher import AES
from Crypto.Hash import SHAKE128
from Crypto.Protocol.DH import key_agreement
from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccKey
from Crypto.Util.Padding import unpad

PUB_PEM_START = "-----BEGIN PUBLIC KEY-----"
PUB_PEM_END = "-----END PUBLIC KEY-----"


def kdf(s: bytes, keylen: int = 16) -> bytes:
    """Derive a secret from the seed.

    :param s: The KDF seed
    :param keylen: The length of the desired secret
    :return: the derived secret
    """
    return SHAKE128.new(s).read(keylen)


async def get_ec_keys(interaction: nextcord.Interaction, s_key: str, e_key: str) -> tuple[EccKey, EccKey]:
    s_key = s_key[len(PUB_PEM_START):-len(PUB_PEM_END)].replace(" ", "")
    e_key = e_key[len(PUB_PEM_START):-len(PUB_PEM_END)].replace(" ", "")

    try:
        s_pk_b = base64.b64decode(s_key, validate=True)
        e_pk_b = base64.b64decode(e_key, validate=True)
    except binascii.Error:
        await interaction.send("Public keys are not valid PEM", ephemeral=True)
        raise RuntimeError()

    try:
        user_s_pk = ECC.import_key(s_pk_b)
        user_e_pk = ECC.import_key(e_pk_b)
    except ValueError:
        await interaction.send("Public keys are not valid ECC keys", ephemeral=True)
        raise RuntimeError()

    if user_s_pk.has_private() or user_e_pk.has_private():
        await interaction.send("!!!Submitted a private key!!!", ephemeral=True)
        raise RuntimeError()

    if user_s_pk.curve != "NIST P-384" or user_e_pk.curve != "NIST P-384":
        await interaction.send("Wrong elliptic curve", ephemeral=True)
        raise RuntimeError()

    return user_s_pk, user_e_pk


def fetch_session_key(ssk: EccKey, spk: EccKey, epk: EccKey) -> bytes:
    return key_agreement(static_priv=ssk, static_pub=spk, eph_pub=epk, kdf=kdf)


async def aes_decrypt(interaction: nextcord.Interaction, ct_hex: str, iv_hex: str, key: bytes) -> str:
    try:
        ct_b = bytes.fromhex(ct_hex)
        iv_b = bytes.fromhex(iv_hex)
    except ValueError:
        await interaction.send("Ciphertext or IV is not valid hex", ephemeral=True)
        raise RuntimeError()

    if len(ct_b) % AES.block_size != 0:
        await interaction.send("Ciphertext is of incorrect length", ephemeral=True)
        raise RuntimeError()

    cipher = AES.new(key, AES.MODE_CBC, iv_b)
    try:
        m = unpad(cipher.decrypt(ct_b), AES.block_size).decode("utf-8")
    except UnicodeDecodeError:
        await interaction.send("Message is not printable, potential decryption failure", ephemeral=True)
        raise RuntimeError()

    return m
