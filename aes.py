from binascii import hexlify, unhexlify
from typing import Tuple, Any, List, TypeVar

Word = Tuple[int, int, int, int]
State = Tuple[Word, Word, Word, Word]
T = TypeVar("T")

sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

rcon = (
    (0x01, 0x00, 0x00, 0x00),
    (0x02, 0x00, 0x00, 0x00),
    (0x04, 0x00, 0x00, 0x00),
    (0x08, 0x00, 0x00, 0x00),
    (0x10, 0x00, 0x00, 0x00),
    (0x20, 0x00, 0x00, 0x00),
    (0x40, 0x00, 0x00, 0x00),
    (0x80, 0x00, 0x00, 0x00),
    (0x1B, 0x00, 0x00, 0x00),
    (0x36, 0x00, 0x00, 0x00),
)

def gmult(x: int, y: int) -> int:
    """gmult performs multiplication in GF(2^8) on `x` and `y`.

    `x` and `y` must be 8-bit unsigned integers.
    """
    assert 0 <= x < 256, "%s not within bounds" % x
    assert 0 <= y < 256, "%s not within bounds" % y
    OVERFLOW_MASK, IRR_POLY = 0x100, 0x11B
    p = 0
    while y:
        if y & 1:
            p ^= x
        x <<= 1
        if x & OVERFLOW_MASK:
            x ^= IRR_POLY
        y >>= 1
    p &= OVERFLOW_MASK - 1
    assert 0 <= p < 256, "%s not within bounds" % p
    return p


def xor_word(lword: Word, rword: Word) -> Word:
    """xor_word performs an xor on two Word tuples as if they were a 32-bit
    integer, returning a new Word tuple.
    """
    assert len(lword) == 4 and len(lword) == len(rword)
    return (
        lword[0] ^ rword[0],
        lword[1] ^ rword[1],
        lword[2] ^ rword[2],
        lword[3] ^ rword[3],
    )


def rot_word(word: Word) -> Word:
    """rot_word takes the Word tuple (a0, a1, a2, a3) and returns the Word tuple (a1, a2, a3, a0).
    """
    assert len(word) == 4
    return word[1:] + word[:1]


def sub_word(word: Word) -> Word:
    """sub_word transform each byte of the word using the AES sbox.
    """
    assert len(word) == 4
    return (
        sbox[word[0]],
        sbox[word[1]],
        sbox[word[2]],
        sbox[word[3]],
    )


def key_expansion(key: bytes) -> List[Word]:
    """key_expansion implements the ExpandKey routine for AES with 128-bit keys.
    """
    assert len(key) == 16

    Nk = 4  # Nk = 4 for AES-128
    Nb = 4  # Nb = 4 for AES
    Nr = 10  # Nr = 10 for AES-128

    # initialize the key schedule words list with the cipher key input
    words: List[Word] = list(
        [
            (key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3])
            for i in range(Nk)
        ]
    )

    # build out the rest of the key schedule
    for i in range(Nk, Nb * (Nr + 1)):
        temp = words[i - 1]
        if i % Nk == 0:
            temp = sub_word(rot_word(temp))
            temp = xor_word(temp, rcon[(i // Nk) - 1])
        words.append(xor_word(words[i - Nk], temp))

    assert len(words) == 44
    return words



def sub_words(words: State) -> State:
    """sub_words applies the AES standard SubBytes operation.
    """
    return (
        sub_word(words[0]),
        sub_word(words[1]),
        sub_word(words[2]),
        sub_word(words[3]),
    )


def bytes_to_state(b: bytes) -> State:
    """bytes_to_state formats `b` bytes as a AES state matrix.
    """
    assert len(b) == 16
    return (
        (b[0], b[4], b[8], b[12]),
        (b[1], b[5], b[9], b[13]),
        (b[2], b[6], b[10], b[14]),
        (b[3], b[7], b[11], b[15]),
    )

def state_to_bytes(s: State) -> bytes:
    """state_to_bytes formats a AES state matrix as bytes.
    """
    return bytes(
        (s[0][0], s[1][0], s[2][0], s[3][0],         
         s[0][1], s[1][1], s[2][1], s[3][1],         
         s[0][2], s[1][2], s[2][2], s[3][2],         
         s[0][3], s[1][3], s[2][3], s[3][3])
    )

def add_round_key(state: State, round_key_words: List[Word]) -> State:
    """add_round_key applies the AES standard AddRoundKey operation.
    """
    assert len(round_key_words) == 4
    w0, w1, w2, w3 = round_key_words
    return (
        (
            state[0][0] ^ w0[0],
            state[0][1] ^ w1[0],
            state[0][2] ^ w2[0],
            state[0][3] ^ w3[0],
        ),
        (
            state[1][0] ^ w0[1],
            state[1][1] ^ w1[1],
            state[1][2] ^ w2[1],
            state[1][3] ^ w3[1],
        ),
        (
            state[2][0] ^ w0[2],
            state[2][1] ^ w1[2],
            state[2][2] ^ w2[2],
            state[2][3] ^ w3[2],
        ),
        (
            state[3][0] ^ w0[3],
            state[3][1] ^ w1[3],
            state[3][2] ^ w2[3],
            state[3][3] ^ w3[3],
        ),
    )


def shift_rows(state: State) -> State:
    """shift_rows applies the AES standard ShiftRows operation.
    """
    return (
        state[0],
        state[1][1:] + state[1][:1],
        state[2][2:] + state[2][:2],
        state[3][3:] + state[3][:3],
    )

def _mix_column(s0c: int, s1c: int, s2c: int, s3c: int) -> Word:
    assert 0 <= s0c < 256
    assert 0 <= s1c < 256
    assert 0 <= s2c < 256
    assert 0 <= s3c < 256
    return (
        (gmult(0x02, s0c) ^ gmult(0x03, s1c) ^ s2c ^ s3c), # s'0c
        (s0c ^ gmult(0x02, s1c) ^ gmult(0x03, s2c) ^ s3c), # s'1c
        (s0c ^ s1c ^ gmult(0x02, s2c) ^ gmult(0x03, s3c)), # s'2c
        (gmult(0x03, s0c) ^ s1c ^ s2c ^ gmult(0x02, s3c)), # s'3c
    )

def mix_columns(state: State) -> State:
    """mix_columns applies the AES standard MixColumns operation.
    """
    # column 0
    sp00, sp10, sp20, sp30 = _mix_column(
        state[0][0], state[1][0], state[2][0], state[3][0]
    )
    # column 1
    sp01, sp11, sp21, sp31 = _mix_column(
        state[0][1], state[1][1], state[2][1], state[3][1]
    )
    # column 2
    sp02, sp12, sp22, sp32 = _mix_column(
        state[0][2], state[1][2], state[2][2], state[3][2]
    )
    # column 3
    sp03, sp13, sp23, sp33 = _mix_column(
        state[0][3], state[1][3], state[2][3], state[3][3]
    )
    return (
        (sp00, sp01, sp02, sp03),
        (sp10, sp11, sp12, sp13),
        (sp20, sp21, sp22, sp23),
        (sp30, sp31, sp32, sp33),
    )


def aes128(key: bytes, block: bytes) -> bytes:
    """aes128 encrypts a 16 byte `block` using AES-128 with `key`.
    """
    assert len(key) == 16 and len(block) == 16

    expanded = key_expansion(key)
    state = bytes_to_state(block)

    # round 0
    state = add_round_key(state, expanded[0:4])

    # round 1 -> round 9
    for i in range(1, 10):
        state = sub_words(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, expanded[4*i:4*(i+1)])

    # round 10
    state = sub_words(state)
    state = shift_rows(state)
    state = add_round_key(state, expanded[40:44])

    ciphertext = state_to_bytes(state)
    assert len(ciphertext) == 16
    return ciphertext


if __name__ == "__main__":
    assert gmult(0xFF, 0x00) == gmult(0x00, 0xFF)
    assert gmult(0x7A, 0x01) == 0x7A
    assert gmult(0x57, 0x83) == 0xC1

    expanded = key_expansion(unhexlify("2b7e151628aed2a6abf7158809cf4f3c"))
    assert expanded[-4] == (0xD0, 0x14, 0xF9, 0xA8)
    assert expanded[-3] == (0xC9, 0xEE, 0x25, 0x89)
    assert expanded[-2] == (0xE1, 0x3F, 0x0C, 0xC8)
    assert expanded[-1] == (0xB6, 0x63, 0x0C, 0xA6)

    key: bytes = unhexlify("000102030405060708090a0b0c0d0e0f")
    plaintext: bytes = unhexlify("00112233445566778899aabbccddeeff")
    ciphertext: bytes = unhexlify("69c4e0d86a7b0430d8cdb78070b4c55a")
    got: bytes = aes128(key, plaintext)
    assert got == ciphertext, "%r != %r" % (hexlify(got), hexlify(ciphertext))
    print("ok")
