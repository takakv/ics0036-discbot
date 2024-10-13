if __name__ == "__main__":
    import secrets
    from algos.elgamal import RFC3526_3072_HEX

    p = int.from_bytes(bytes.fromhex(RFC3526_3072_HEX), "big")
    q = (p - 1) // 2
    s = secrets.randbelow(q)
    with open("../egkey.txt", "w") as f:
        f.write(f"{s}")
