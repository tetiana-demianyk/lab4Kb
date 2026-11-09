W = 32
R = 12
B = 16
MASK = 0xFFFFFFFF
P32 = 0xB7E15163
Q32 = 0x9E3779B9


def rotl(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & MASK if n else x


def rotr(x, n):
    n &= 31
    return ((x >> n) | (x << (32 - n))) & MASK if n else x


def expand_key(key):
    u = W // 8
    c = max(1, (B + u - 1) // u)
    t = 2 * (R + 1)

    key = list(key) + [0] * (B - len(key))
    L = [0] * c
    for i in range(B - 1, -1, -1):
        L[i // u] = ((L[i // u] << 8) + key[i]) & MASK

    S = [P32]
    for i in range(1, t):
        S.append((S[i - 1] + Q32) & MASK)

    A = Bw = i = j = 0
    for _ in range(3 * max(t, c)):
        A = S[i] = rotl((S[i] + A + Bw) & MASK, 3)
        Bw = L[j] = rotl((L[j] + A + Bw) & MASK, (A + Bw) & MASK)
        i = (i + 1) % t
        j = (j + 1) % c
    return S


def Task1(source, sourceSize, key, encryptionMode):
    """source, key: списки цілих (0..255), наприклад [0x00, 0x1A, ...]."""
    S = expand_key(key)

    data = list(source[:sourceSize])
    data += [0] * (-len(data) % 8)  # доповнення нулями до кратності 8

    out = []
    for off in range(0, len(data), 8):
        A = int.from_bytes(bytes(data[off:off + 4]), "little")
        Bw = int.from_bytes(bytes(data[off + 4:off + 8]), "little")

        if encryptionMode:
            A = (A + S[0]) & MASK
            Bw = (Bw + S[1]) & MASK
            for r in range(1, R + 1):
                A = (rotl(A ^ Bw, Bw) + S[2 * r]) & MASK
                Bw = (rotl(Bw ^ A, A) + S[2 * r + 1]) & MASK
        else:
            for r in range(R, 0, -1):
                Bw = rotr((Bw - S[2 * r + 1]) & MASK, A) ^ A
                A = rotr((A - S[2 * r]) & MASK, Bw) ^ Bw
            Bw = (Bw - S[1]) & MASK
            A = (A - S[0]) & MASK

        out += list(A.to_bytes(4, "little")) + list(Bw.to_bytes(4, "little"))

    return " ".join(f"{b:02X}" for b in out)


if __name__ == "__main__":
    key = [0] * 16
    pt = [0] * 8
    ct = Task1(pt, 8, key, True)
    print(ct)  # 21 A5 DB EE 15 4B 8F 6D
    print(Task1([int(x, 16) for x in ct.split()], 8, key, False))
