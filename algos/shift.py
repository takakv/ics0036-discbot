import base64

def validate_string(s: str):
    if s.lower() != s:
        raise RuntimeError("input must only contain lowercase characters")

    if not s.isalnum():
        raise RuntimeError("input must only contain alphanumeric characters (a-z)")


class ShiftCipher:
    def __init__(self, key: int):
        self.key = key

    def encrypt(self, pt: str) -> str:
        validate_string(pt)
        ct = ""
        # Let 'pos(c)' be the 0-indexed position in the alphabet of some character 'c'.
        # Then, each letter is encrypted as:
        # (pos(c) + key) % 26 for the English alphabet.

        # The ASCII encodings do not begin at 0, so first we need the position
        # in the ASCII table: ord(c) - ord('a'), then we encrypt, and then we
        # adjust the output to be in the ASCII table with + ord('a') again.
        for c in pt:
            ct += chr(ord('a') + ((ord(c) - ord('a') + self.key) % 26))

        return ct

    def decrypt(self, ct: str) -> str:
        validate_string(ct)
        pt: str = ""
        # For decryption, we first also need the position in the alphabet.
        # Finally, we convert the result back to the ASCII table position.
        for c in ct:
            pt += chr(ord('a') + ((ord(c) - ord('a') - self.key) % 26))

        return pt


class BShiftCipher:
    def __init__(self, key: int):
        self.key = key

    def encrypt(self, pt: bytes) -> bytes:
        # Bytes are just integers 0 <= x < 256, so we can have a list of
        # integers which we later convert to an immutable bytes object.
        # Implementation details really are annoying...
        ct: list[int] = []
        # The largest byte value is 255, so you can think of the alphabet as
        # bytes 0--255. We no longer care about encoding (functions take care of
        # that), so we can just apply the mod operator.
        for b in pt:
            ct.append((b + self.key) % 256)

        return bytes(ct)

    def decrypt(self, ct: bytes) -> bytes:
        pt: list[int] = []
        for b in ct:
            pt.append((b - self.key) % 256)

        return bytes(pt)

    def encrypt_strings(self, pt: str) -> str:
        return base64.b64encode(self.encrypt(pt.encode())).decode()

    def decrypt_strings(self, ct: str) -> str:
        return self.decrypt(base64.b64decode(ct, validate=True)).decode()

