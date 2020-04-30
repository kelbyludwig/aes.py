from binascii import hexlify, unhexlify
from typing import Tuple, Any, List
from key_schedule import key_expansion, Word, sub_word, gmult

State = Tuple[Word, Word, Word, Word]

def sub_words(words: State) -> State:
    return (
        sub_word(words[0]),
        sub_word(words[1]),
        sub_word(words[2]),
        sub_word(words[3]),
    )


def bytes_to_state(b: bytes) -> State:
    assert len(b) == 16
    return (
        (b[0], b[4], b[8], b[12]),
        (b[1], b[5], b[9], b[13]),
        (b[2], b[6], b[10], b[14]),
        (b[3], b[7], b[11], b[15]),
    )

def state_to_bytes(s: State) -> bytes:
    return bytes(
        (s[0][0], s[1][0], s[2][0], s[3][0],         
         s[0][1], s[1][1], s[2][1], s[3][1],         
         s[0][2], s[1][2], s[2][2], s[3][2],         
         s[0][3], s[1][3], s[2][3], s[3][3])
    )

def add_round_key(state: State, round_key_words: List[Word]) -> State:
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
    # https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    key: bytes = unhexlify("000102030405060708090a0b0c0d0e0f")
    plaintext: bytes = unhexlify("00112233445566778899aabbccddeeff")
    ciphertext: bytes = unhexlify("69c4e0d86a7b0430d8cdb78070b4c55a")
    got: bytes = aes128(key, plaintext)
    assert got == ciphertext, "%r != %r" % (hexlify(got), hexlify(ciphertext))
    print("passed!")
