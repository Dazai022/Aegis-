'''
AEGIS-X128 -- EXPERIMENTAL SUBSTITUTION-PERMUTATION NETWORK

NOT FOR PRODUCTION USE. This is a research prototype only.
AES-256-GCM remains the production encryption standard for Aegis.

Design summary:
  Block size : 128 bits (16 bytes)
  Key size   : 256 bits (32 bytes)
  Rounds     : 14
  Nonce      : 96-bit (12 bytes, random)
  Auth       : CBC-MAC over ciphertext blocks
  Structure  : Substitution-Permutation Network (SPN)
'''
from __future__ import annotations
import os, struct, hashlib
from typing import Final

# EXPERIMENTAL / NOT FOR PRODUCTION
_MARKER: Final = 'AEGIS-X128-EXPERIMENTAL-NOT-FOR-PRODUCTION'

BLOCK_BYTES: Final = 16
KEY_BYTES: Final   = 32
NONCE_BYTES: Final = 12
NUM_ROUNDS: Final  = 14
TAG_BYTES: Final   = 16

# ── S-box (8-bit, derived from AES S-box for correctness baseline) ─────
_SBOX = bytes([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
])

_INV_SBOX = bytearray(256)
for _i, _v in enumerate(_SBOX): _INV_SBOX[_v] = _i

# ── Permutation (byte shuffle for diffusion) ────────────────────────────
_PERM    = bytes([0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15])
_INV_PERM = bytearray(16)
for _i, _v in enumerate(_PERM): _INV_PERM[_v] = _i


def _sub_bytes(block: bytearray) -> bytearray:
    return bytearray(_SBOX[b] for b in block)

def _inv_sub_bytes(block: bytearray) -> bytearray:
    return bytearray(_INV_SBOX[b] for b in block)

def _permute(block: bytearray) -> bytearray:
    return bytearray(block[_PERM[i]] for i in range(16))

def _inv_permute(block: bytearray) -> bytearray:
    return bytearray(block[_INV_PERM[i]] for i in range(16))

def _xor(a: bytes | bytearray, b: bytes | bytearray) -> bytearray:
    return bytearray(x ^ y for x, y in zip(a, b))


# ── Key schedule (HKDF-SHA256-based) ────────────────────────────────────
def _key_schedule(key: bytes) -> list[bytes]:
    assert len(key) == KEY_BYTES
    round_keys = []
    for i in range(NUM_ROUNDS + 1):
        info = struct.pack('>I', i)
        rk = hashlib.pbkdf2_hmac('sha256', key, info, iterations=1, dklen=BLOCK_BYTES)
        round_keys.append(rk)
    return round_keys


# ── Block cipher (SPN) ──────────────────────────────────────────────────
def _encrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
    state = _xor(block, round_keys[0])
    for r in range(1, NUM_ROUNDS):
        state = _sub_bytes(state)
        state = _permute(state)
        state = _xor(state, round_keys[r])
    state = _sub_bytes(state)
    state = _xor(state, round_keys[NUM_ROUNDS])
    return bytes(state)

def _decrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
    state = _xor(block, round_keys[NUM_ROUNDS])
    state = _inv_sub_bytes(state)
    for r in range(NUM_ROUNDS - 1, 0, -1):
        state = _xor(state, round_keys[r])
        state = _inv_permute(state)
        state = _inv_sub_bytes(state)
    state = _xor(state, round_keys[0])
    return bytes(state)


# ── CTR mode + CBC-MAC authentication (AEAD) ────────────────────────────
def _ctr_keystream(round_keys: list[bytes], nonce: bytes, length: int) -> bytes:
    stream = bytearray()
    counter = 0
    while len(stream) < length:
        block_in = nonce[:12] + struct.pack('>I', counter)
        stream.extend(_encrypt_block(block_in, round_keys))
        counter += 1
    return bytes(stream[:length])

def _cbc_mac(round_keys: list[bytes], data: bytes) -> bytes:
    mac = bytearray(BLOCK_BYTES)
    # pad to block boundary
    padded = data + bytes(-len(data) % BLOCK_BYTES)
    for i in range(0, len(padded), BLOCK_BYTES):
        mac = bytearray(_encrypt_block(bytes(_xor(mac, padded[i:i+BLOCK_BYTES])), round_keys))
    return bytes(mac[:TAG_BYTES])


class AegisX128:
    '''
    AEGIS-X128 AEAD cipher (EXPERIMENTAL - NOT FOR PRODUCTION).
    Interface mirrors the production AesGcm class for comparison purposes only.
    '''
    def __init__(self, key: bytes) -> None:
        assert len(key) == KEY_BYTES, f'AegisX128 requires 32-byte key (got {len(key)})'
        self._rk = _key_schedule(key)

    def encrypt(self, plaintext: bytes | str, associated_data: bytes | None = None) -> tuple[bytes, bytes]:
        if isinstance(plaintext, str): plaintext = plaintext.encode()
        nonce = os.urandom(NONCE_BYTES)
        ks = _ctr_keystream(self._rk, nonce, len(plaintext))
        ciphertext = _xor(plaintext, ks)
        mac_input = (associated_data or b'') + bytes(ciphertext)
        tag = _cbc_mac(self._rk, mac_input)
        return nonce + bytes(ciphertext), tag

    def decrypt(self, ciphertext_with_nonce: bytes, tag: bytes, associated_data: bytes | None = None) -> bytes:
        nonce = ciphertext_with_nonce[:NONCE_BYTES]
        ct = ciphertext_with_nonce[NONCE_BYTES:]
        mac_input = (associated_data or b'') + ct
        expected_tag = _cbc_mac(self._rk, mac_input)
        # Constant-time tag compare
        import hmac as _hmac
        if not _hmac.compare_digest(tag, expected_tag):
            raise ValueError('AegisX128: authentication tag mismatch (possible tampering)')
        ks = _ctr_keystream(self._rk, nonce, len(ct))
        return bytes(_xor(ct, ks))
