#!/usr/bin/env python3
"""
extractor.py                     –  Binary Ninja script to extract amos stealer bash files for analyzing and mitigation
this script can take the whole binary and output the bash scripts.

Run:
    python grab_arrays.py malware
"""

from pathlib import Path
import itertools
import sys
# Binary Ninja API
#
# Upstream recently replaced the long-standing helper
# ``BinaryViewType.get_view_of_file`` with :pyfunc:`binaryninja.load`.
# Import the full *binaryninja* module in addition to the symbols we
# explicitly use so that we can rely on the stable ``load`` helper for
# opening a file.  This keeps the rest of the script untouched.

# Binary Ninja API ---------------------------------------------------------
#
# Binary Ninja's IL operation enumerations have changed a bit over time. In
# particular, what were once `MLIL_FOR`/`MLIL_WHILE` loop operations now live
# in the HLIL name-space (`HLIL_FOR`/`HLIL_WHILE`) and the legacy helper
# `BinaryViewType.get_view_of_file` has been replaced by `binaryninja.load`.
#
# To keep the script working across both old and new releases we import *both*
# Medium- and High-level IL enumerations and build a couple of small helper
# sets that cover the operation codes we are interested in.  The rest of the
# script then simply checks membership in those sets instead of hard-coding a
# single enum value.

import binaryninja as bn
from binaryninja import (
    BinaryViewType,  # for backwards compatibility fall-back
    MediumLevelILOperation as MLOp,
    HighLevelILOperation as HLOp,
    log_info,
    log_warn,
)

# Backwards-compatibility alias ------------------------------------------------
#
# The original script imported ``MediumLevelILOperation`` as *Op*.  To avoid a
# sweeping refactor we keep that name but point it at the HLIL enum which
# contains the loop constructs we care about in modern Binary Ninja builds.

Op = HLOp

# Friendly aliases covering both IL generations --------------------------------

# Loop headers
LOOP_FOR_OPS = set()
for name in ("MLIL_FOR", "HLIL_FOR"):
    LOOP_FOR_OPS.add(getattr(MLOp, name, None))
    LOOP_FOR_OPS.add(getattr(HLOp, name, None))
LOOP_FOR_OPS.discard(None)

LOOP_WHILE_OPS = set()
for name in ("MLIL_WHILE", "HLIL_WHILE", "MLIL_DO_WHILE", "HLIL_DO_WHILE"):
    LOOP_WHILE_OPS.add(getattr(MLOp, name, None))
    LOOP_WHILE_OPS.add(getattr(HLOp, name, None))
LOOP_WHILE_OPS.discard(None)

# Arithmetic ADD (pointer arithmetic)
ADD_OPS = {
    op
    for op in (
        getattr(MLOp, "MLIL_ADD", None),
        getattr(HLOp, "HLIL_ADD", None),
    )
    if op is not None
}

# Constant pointer literal
CONST_PTR_OPS = {
    op
    for op in (
        getattr(MLOp, "MLIL_CONST_PTR", None),
        getattr(HLOp, "HLIL_CONST_PTR", None),
    )
    if op is not None
}

# Memory load / dereference
LOAD_OPS = {
    op
    for op in (
        getattr(MLOp, "MLIL_LOAD", None),
        getattr(HLOp, "HLIL_DEREF", None),  # HLIL renamed LOAD -> DEREF
    )
    if op is not None
}

# Multiplication / shift-left (index scaling)
MUL_OPS = {
    op
    for op in (
        getattr(MLOp, "MLIL_MUL", None),
        getattr(HLOp, "HLIL_MUL", None),
    )
    if op is not None
}

LSL_OPS = {
    op
    for op in (
        getattr(MLOp, "MLIL_LSL", None),
        getattr(HLOp, "HLIL_LSL", None),
    )
    if op is not None
}

# Arithmetic inside the decode loop
XOR_OPS = {
    op
    for op in (
        getattr(MLOp, "MLIL_XOR", None),
        getattr(HLOp, "HLIL_XOR", None),
    )
    if op is not None
}

SUB_OPS = {
    op
    for op in (
        getattr(MLOp, "MLIL_SUB", None),
        getattr(HLOp, "HLIL_SUB", None),
    )
    if op is not None
}

# Loop guard comparisons (different compiler/BN versions produce different ops)
CMP_OPS = set()
for name in (
    "MLIL_CMP_E",
    "HLIL_CMP_E",
    "MLIL_CMP_NE",
    "HLIL_CMP_NE",
    "MLIL_CMP_SLT",
    "HLIL_CMP_SLT",
    "MLIL_CMP_ULT",
    "HLIL_CMP_ULT",
    "MLIL_CMP_SLE",
    "HLIL_CMP_SLE",
    "MLIL_CMP_ULE",
    "HLIL_CMP_ULE",
    "MLIL_CMP_SGT",
    "HLIL_CMP_SGT",
    "MLIL_CMP_UGT",
    "HLIL_CMP_UGT",
    "MLIL_CMP_SGE",
    "HLIL_CMP_SGE",
    "MLIL_CMP_UGE",
    "HLIL_CMP_UGE",
):
    CMP_OPS.add(getattr(MLOp, name, None))
    CMP_OPS.add(getattr(HLOp, name, None))
CMP_OPS.discard(None)

CONST_OPS = {
    op
    for op in (
        getattr(MLOp, "MLIL_CONST", None),
        getattr(HLOp, "HLIL_CONST", None),
    )
    if op is not None
}


# ---------------------------------------------------------------------------
#  helpers
# ---------------------------------------------------------------------------

def const_ptr(expr):
    """
    Return a constant pointer literal from an IL pointer expression.

    Handles both:
      - CONST_PTR
      - ADD(CONST_PTR, X) / ADD(X, CONST_PTR)
    """
    if expr is None or not hasattr(expr, "operation"):
        return None

    if expr.operation in CONST_PTR_OPS:
        return expr.constant

    if expr.operation not in ADD_OPS:
        return None

    left = getattr(expr, "left", None)
    right = getattr(expr, "right", None)
    for side in (left, right):
        if side is None or not hasattr(side, "operation"):
            continue
        if side.operation in CONST_PTR_OPS:
            return side.constant
    return None


def const_ptr_and_offset(expr):
    """
    If *expr* is a constant pointer literal or constant pointer + offset,
    return ``(base_addr, offset_expr)``.
    """
    if expr is None or not hasattr(expr, "operation"):
        return (None, None)

    if expr.operation in CONST_PTR_OPS:
        return (expr.constant, None)

    if expr.operation not in ADD_OPS:
        return (None, None)

    left = getattr(expr, "left", None)
    right = getattr(expr, "right", None)

    if left is not None and hasattr(left, "operation") and left.operation in CONST_PTR_OPS:
        return (left.constant, right)
    if right is not None and hasattr(right, "operation") and right.operation in CONST_PTR_OPS:
        return (right.constant, left)

    return (None, None)


def base_of_load(expr):
    """
    Recursively look for a memory dereference (``LOAD``/``DEREF``) wrapped in
    casts or bit-extraction helpers and return the constant base address inside
    its pointer arithmetic.
    """
    # Only High/Medium-level IL expressions have an ``operation`` attribute.
    if not hasattr(expr, "operation"):
        return None

    # Direct dereference → examine its source pointer arithmetic.
    if expr.operation in LOAD_OPS:
        return const_ptr(expr.src)

    # Unwrap common single-operand wrappers (LOW_PART, SIGN/ZERO-EXTEND, etc.).
    single_operand_attrs = ("src", "operand", "value")
    for attr in single_operand_attrs:
        inner = getattr(expr, attr, None)
        if inner is not None:
            base = base_of_load(inner)
            if base:
                return base

    # Fall back to brute-force traversing child operands provided by the API.
    for op in getattr(expr, "operands", []):
        base = base_of_load(op)
        if base:
            return base

    # No constant base found
    return None


def extract_arrays(bv):
    """
    Returns  [(base_addr, length), …]  grouped as (base, sub, xor) triplets.

    The original version only inspected the entry-point and assumed the loop
    guard was always ``i != CONST`` and that the XOR/SUB expression was the
    *top-level* statement in the loop body. The `update` sample violates those
    assumptions (different compare op and/or additional wrapper statements),
    so we scan all functions and look for the characteristic SUB+XOR pattern
    anywhere inside the loop body.
    """

    arrays = []

    def unwrap_single(expr):
        """Unwrap common single-operand wrappers (casts, low-part, etc.)."""
        for attr in ("src", "operand", "value"):
            inner = getattr(expr, attr, None)
            if inner is not None:
                return inner
        return None

    def loop_bound(cond):
        """Try to extract a constant upper bound from a loop condition."""
        cur = cond
        while hasattr(cur, "operation"):
            if cur.operation in CMP_OPS:
                left = getattr(cur, "left", None)
                right = getattr(cur, "right", None)
                if hasattr(left, "operation") and left.operation in CONST_OPS:
                    return left.constant
                if hasattr(right, "operation") and right.operation in CONST_OPS:
                    return right.constant
                return None
            inner = unwrap_single(cur)
            if inner is None:
                return None
            cur = inner
        return None

    def first_const_base(expr):
        """Return the first constant base address for any deref inside *expr*."""
        base = base_of_load(expr)
        if base:
            return base
        return None

    def walk_expr(expr):
        """Yield *expr* and all descendant operands depth-first."""
        stack = [expr]
        while stack:
            node = stack.pop()
            yield node
            for opnd in reversed(getattr(node, "operands", [])):
                stack.append(opnd)

    def bases_in_loop(inst):
        """Collect constant deref bases from the loop body, in first-seen order."""
        ordered: list[int] = []
        seen: set[int] = set()
        for stmt in inst.body:
            for node in walk_expr(stmt):
                if not hasattr(node, "operation"):
                    continue
                if node.operation not in LOAD_OPS:
                    continue
                base = const_ptr(getattr(node, "src", None))
                if not base:
                    continue
                if base not in seen:
                    seen.add(base)
                    ordered.append(base)
        return ordered

    def loop_scale(inst) -> int:
        """Best-effort guess of element-to-byte scaling inside the loop."""
        scale = 1
        for stmt in inst.body:
            for node in walk_expr(stmt):
                if not hasattr(node, "operation") or node.operation not in LOAD_OPS:
                    continue
                base, offset = const_ptr_and_offset(getattr(node, "src", None))
                if not base or offset is None:
                    continue

                for off_node in walk_expr(offset):
                    if not hasattr(off_node, "operation"):
                        continue

                    if off_node.operation in MUL_OPS:
                        left = getattr(off_node, "left", None)
                        right = getattr(off_node, "right", None)
                        for side in (left, right):
                            if hasattr(side, "operation") and side.operation in CONST_OPS:
                                scale = max(scale, int(side.constant))

                    if off_node.operation in LSL_OPS:
                        shift = getattr(off_node, "right", None)
                        if hasattr(shift, "operation") and shift.operation in CONST_OPS:
                            scale = max(scale, 1 << int(shift.constant))

        return scale

    def triplet_from_loop(inst):
        """Try to recover ordered (base, sub, xor) from SUB/XOR expressions."""
        sub_pairs: list[tuple[int, int]] = []
        xor_operands: list[int] = []

        for stmt in inst.body:
            for node in walk_expr(stmt):
                if not hasattr(node, "operation"):
                    continue

                if node.operation in SUB_OPS:
                    left = getattr(node, "left", None)
                    right = getattr(node, "right", None)
                    base_left = first_const_base(left) if left is not None else None
                    base_right = first_const_base(right) if right is not None else None
                    if base_left and base_right and base_left != base_right:
                        sub_pairs.append((base_left, base_right))

                if node.operation in XOR_OPS:
                    left = getattr(node, "left", None)
                    right = getattr(node, "right", None)

                    # Prefer the classic nested form: (base - sub) ^ xor
                    for sub_node, other in ((left, right), (right, left)):
                        if not hasattr(sub_node, "operation") or sub_node.operation not in SUB_OPS:
                            continue

                        base_left = first_const_base(getattr(sub_node, "left", None))
                        base_right = first_const_base(getattr(sub_node, "right", None))
                        base_other = first_const_base(other) if other is not None else None

                        if (
                            base_left
                            and base_right
                            and base_other
                            and len({base_left, base_right, base_other}) == 3
                        ):
                            return (base_left, base_right, base_other)

                    # Otherwise, just record any constant base used directly by XOR
                    if left is not None:
                        b = first_const_base(left)
                        if b:
                            xor_operands.append(b)
                    if right is not None:
                        b = first_const_base(right)
                        if b:
                            xor_operands.append(b)

        # Fallback: pair a SUB(L,R) with a different XOR operand
        for left_base, right_base in sub_pairs:
            for xb in xor_operands:
                if xb not in (left_base, right_base):
                    return (left_base, right_base, xb)

        return None

    # Scan all functions (entry-point often just dispatches to the real decoder).
    for fn in sorted(bv.functions, key=lambda f: f.start):
        if not getattr(fn, "hlil", None):
            continue
        for inst in fn.hlil.instructions:
            if inst.operation not in (LOOP_FOR_OPS | LOOP_WHILE_OPS):
                continue

            cond = getattr(inst, "condition", None)
            if cond is None:
                continue
            length = loop_bound(cond)
            if not length:
                continue

            length *= loop_scale(inst)

            triplet = triplet_from_loop(inst)
            if triplet is None:
                bases = bases_in_loop(inst)
                if len(bases) < 3:
                    continue
                triplet = (bases[0], bases[1], bases[2])

            base_addr, sub_addr, xor_addr = triplet
            arrays.append((base_addr, length))
            arrays.append((sub_addr, length))
            arrays.append((xor_addr, length))

    return arrays


# ---------------------------------------------------------------------------
#  main
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> None:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <binary>", file=sys.stderr)
        sys.exit(1)

    # Binary Ninja 4.2 deprecated ``BinaryViewType.get_view_of_file`` in
    # favour of the higher-level ``binaryninja.load`` convenience helper.
    #
    # Use it here so the script works with both new and old releases.  For
    # older versions we fall back to the previous API if it's still
    # available.

    try:
        bv = bn.load(argv[1])
        # Some Binary Ninja builds analyze asynchronously even when opened
        # headless; ensure HLIL is available before walking it.
        bv.update_analysis_and_wait()
    except AttributeError:
        # Very old Binary Ninja builds (<4.2) – keep existing behaviour.
        bv = BinaryViewType.get_view_of_file(argv[1])
        bv.update_analysis_and_wait()

    array_meta = extract_arrays(bv)

    if len(array_meta) < 3:
        log_warn(
            f"Only found {len(array_meta)} constant arrays – continuing without extraction."
        )
        # Continue execution instead of bailing out.  A mismatch here is not a
        # fatal error for the purpose of simply *loading* the binary.
        return

    # ------------------------------------------------------------------
    # Stage-1  –  dump the three raw constant buffers of the *first* group
    #            (handy for debugging/verification).
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Stage-2  –  reconstruct the strings the malware builds at run-time.
    # ------------------------------------------------------------------

    def lowbyte_decode(base_bytes: bytes, sub_bytes: bytes, xor_bytes: bytes) -> bytes:
        """Return the raw bytes produced by the low-byte arithmetic."""
        if not (len(base_bytes) == len(sub_bytes) == len(xor_bytes)):
            raise ValueError("buffers must have equal length")
        if len(base_bytes) % 4:
            raise ValueError("length must be a multiple of 4")
        base_bytes = list(base_bytes)
        sub_bytes = list(sub_bytes)
        xor_bytes = list(xor_bytes)
        out = bytearray()
        for i in range(0, len(base_bytes), 4):
            b = base_bytes[i]
            s = sub_bytes[i]
            x = xor_bytes[i]
            out.append(((b -s) & 0xff)  ^x)
        return bytes(out)

    def triplet_to_hex_string(base_bytes: bytes, sub_bytes: bytes, xor_bytes: bytes) -> str:
        """Return the ASCII *hex* string produced by the low-byte expression.

        Mirrors exactly what the malware loop does: one byte per 32-bit word
        taking only the least-significant byte of each buffer.
        """
        if not (len(base_bytes) == len(sub_bytes) == len(xor_bytes)):
            raise ValueError("buffers must have equal length")
        if len(base_bytes) % 4:
            raise ValueError("length must be a multiple of 4")

        raw = lowbyte_decode(base_bytes, sub_bytes, xor_bytes)
        return raw.decode("latin1", "strict")

    def hex_string_to_bytes(hex_str: str) -> bytes:
        outtransformed = bytearray()
        for i in range(0, len(hex_str)-1 , 2): #pull pairs of chars
            outtransformed.append(int(hex_str[i] + hex_str[i+1], 16))

        return bytes(outtransformed)

    # ------------------------------------------------------------------
    # Find the alphabet triplet and the correct (base, sub, xor) ordering.
    # The extractor can locate the right arrays but ordering differs between
    # IL patterns/versions; we recover the order by checking which permutation
    # yields a 64-byte alphabet with 64 distinct characters.
    # ------------------------------------------------------------------

    triplets = [array_meta[i : i + 3] for i in range(0, len(array_meta) - 2, 3)]

    if triplets:
        for n, (addr, length) in enumerate(triplets[0]):
            outname = Path(f"triplet_0_{n}.bin")
            outname.write_bytes(bv.read(addr, length))
            log_info(f"Wrote {length:#x} bytes from 0x{addr:x} -> {outname}")

    alphabet_triplet_index: int | None = None
    order: tuple[int, int, int] | None = None
    alphabet: bytes | None = None
    length_scale = 1

    for idx, grp in enumerate(triplets):
        (a0, ln0), (a1, ln1), (a2, ln2) = grp
        if ln0 != ln1 or ln0 != ln2:
            continue

        # Some IL versions represent the loop bound as an element-count (uint32
        # words) rather than a byte-count. Try a few common scale factors and
        # accept the one that yields a valid 64-unique-character alphabet.
        for scale in (1, 2, 4, 8, 16):
            byte_len = ln0 * scale
            if byte_len % 4:
                continue

            bufs = [bv.read(a0, byte_len), bv.read(a1, byte_len), bv.read(a2, byte_len)]
            if any(len(b) != byte_len for b in bufs):
                continue

            for perm in itertools.permutations((0, 1, 2)):
                try:
                    hex_str = triplet_to_hex_string(
                        bufs[perm[0]],
                        bufs[perm[1]],
                        bufs[perm[2]],
                    )
                    candidate = hex_string_to_bytes(hex_str)
                except Exception:
                    continue

                if len(candidate) == 64 and len(set(candidate)) == 64:
                    alphabet_triplet_index = idx
                    order = perm
                    alphabet = candidate
                    length_scale = scale
                    break

            if alphabet is not None:
                break

        if alphabet is not None:
            break

    if alphabet is None or order is None or alphabet_triplet_index is None:
        log_warn("Could not recover the custom alphabet from extracted arrays – skipping decoding")
        return

    log_info(
        f"Alphabet recovered from triplet #{alphabet_triplet_index} (order={order}, scale={length_scale})"
    )
    print(f"Custom alphabet: {alphabet!r}")

    # ------------------------------------------------------------------
    # Stage-1  – dump the three raw constant buffers of the *alphabet* group
    #            (handy for debugging/verification).
    # ------------------------------------------------------------------

    filenames = ["base.bin", "sub.bin", "xor.bin"]
    base_entry, sub_entry, xor_entry = (triplets[alphabet_triplet_index][i] for i in order)
    alphabet_len = base_entry[1] * length_scale
    for (addr, length), outname in zip((base_entry, sub_entry, xor_entry), filenames):
        Path(outname).write_bytes(bv.read(addr, alphabet_len))
        log_info(f"Wrote {alphabet_len:#x} bytes from 0x{addr:x} -> {outname}")

    # Mapping char -> 6-bit value
    b64_map = {ch: idx for idx, ch in enumerate(alphabet.decode('latin1'))}

    def custom_b64_decode(data: str) -> bytes:
        bits = 0
        nbits = 0
        out = bytearray()
        for ch in data:
            val = b64_map.get(ch)
            if val is None:
                continue  # ignore padding / unexpected chars
            bits = (bits << 6) | val
            nbits += 6
            while nbits >= 8:
                nbits -= 8
                out.append((bits >> nbits) & 0xFF)
        return bytes(out)

    # Process every remaining triplet and drop the decoded payload to disk.
    file_index = 0
    for idx, grp in enumerate(triplets):
        if idx == alphabet_triplet_index:
            continue

        (a0, ln0), (a1, ln1), (a2, ln2) = grp
        if ln0 != ln1 or ln0 != ln2:
            log_warn(f"Skipping triplet #{idx}: mismatched lengths ({ln0:#x}, {ln1:#x}, {ln2:#x})")
            continue

        byte_len = ln0 * length_scale
        if byte_len % 4:
            log_warn(f"Skipping triplet #{idx}: scaled length not 4-byte aligned ({byte_len:#x})")
            continue

        bufs = [bv.read(a0, byte_len), bv.read(a1, byte_len), bv.read(a2, byte_len)]
        base_buf, sub_buf, xor_buf = (bufs[i] for i in order)

        try:
            hex_string = triplet_to_hex_string(base_buf, sub_buf, xor_buf)
            encoded_bytes = hex_string_to_bytes(hex_string)
        except Exception as exc:
            log_warn(f"Skipping triplet #{idx}: hex decode failed ({exc})")
            continue

        encoded_str = encoded_bytes.decode("latin1", "ignore")
        plaintext = custom_b64_decode(encoded_str)

        outpath = Path(f"out_{file_index}.txt")
        outpath.write_bytes(plaintext)
        log_info(f"Decoded payload #{file_index} – {len(plaintext)} bytes -> {outpath}")

        file_index += 1


if __name__ == "__main__":
    main(sys.argv)
