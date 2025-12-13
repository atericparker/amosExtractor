#!/usr/bin/env python3
"""
full_decrypt.py

Usage:
    python full_decrypt.py base.bin sub.bin xor.bin [outfile]

The script writes the decrypted bytes to stdout if no outfile is given.
"""

from pathlib import Path
import sys

ALPHABET = "f)C1702GoS5rd&Z%s(T>_FEgJMKOkDNI-#RlYj*p+!?QA6=XnyU3LxvWP@8cietz" #probably changes, you can get this one from the first stage
assert len(ALPHABET) == 64 and len(set(ALPHABET)) == 64, "alphabet must be 64 unique chars"


# ---------------------------------------------------------------------------
# 1.  Rebuild the text fed into the decoder
# ---------------------------------------------------------------------------

def build_encoded_string(base: bytes, sub: bytes, xor: bytes) -> str:
    """
    Mirrors the loop:
        out_byte = ( base_lo - sub_lo ) ^ xor_lo
    where *_lo is the least-significant byte of each 32-bit word.
    """
    if not (len(base) == len(sub) == len(xor)):
        raise ValueError("buffers must be the same length")

    if len(base) % 4:
        raise ValueError("buffer length must be a multiple of 4 (they hold 32-bit words)")

    out = bytearray()
    step = 4                    # advance one 32-bit word at a time
    for i in range(0, len(base), step):
        b = base[i]             # low byte of uint32
        s = sub[i]
        x = xor[i]
        out.append(((b - s) & 0xFF) ^ x)

    # Latin-1 keeps bytes 0-255 exactly the same when converted ⇆ str
    outstr = out.decode('latin1') #this produces a hex string
    outtransformed = bytearray()
    for i in range(0, len(outstr)-1 , 2): #pull pairs of chars
        outtransformed.append(int(outstr[i] + outstr[i+1], 16))

    return outtransformed.decode("latin1")


# ---------------------------------------------------------------------------
# 2.  Decode the 6-bit stream with the custom alphabet
# ---------------------------------------------------------------------------

def decode_custom_64(encoded: str, alphabet: str = ALPHABET) -> bytes:
    """
    Reverse of the bit-packing you saw: 64-symbol text → raw bytes.
    Stops as soon as it meets a character not in the alphabet.
    """
    table = {c: idx for idx, c in enumerate(alphabet)}

    bitbuf = 0
    bits   = 0
    out    = bytearray()

    for ch in encoded:
        val = table.get(ch)
        if val is None:                 # unknown symbol ⇒ terminate (matches the binary)
            break

        bitbuf = (bitbuf << 6) | val
        bits  += 6

        while bits >= 8:
            bits -= 8
            out.append((bitbuf >> bits) & 0xFF)

    return bytes(out)


# ---------------------------------------------------------------------------
# Command-line glue
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> None:
    if len(argv) not in (4, 5):
        print("Usage: python full_decrypt.py base.bin sub.bin xor.bin [outfile]", file=sys.stderr)
        sys.exit(1)

    base_path, sub_path, xor_path = map(Path, argv[1:4])
    out_path = Path(argv[4]) if len(argv) == 5 else None

    base_buf = base_path.read_bytes()
    sub_buf  = sub_path.read_bytes()
    xor_buf  = xor_path.read_bytes()

    encoded_text = build_encoded_string(base_buf, sub_buf, xor_buf)
    plaintext    = decode_custom_64(encoded_text)

    if out_path:
        out_path.write_bytes(plaintext)
        print(f"Decrypted data written to {out_path}")
    else:
        # Write to stdout as raw bytes
        sys.stdout.buffer.write(plaintext)


if __name__ == "__main__":
    main(sys.argv)
