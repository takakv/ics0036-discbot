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
