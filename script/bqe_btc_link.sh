#!/usr/bin/env bash
set -euo pipefail

# Build a coinbase-like raw transaction embedding SHA256(message) in scriptSig,
# then derive its TXID, assemble a minimal spend transaction that spends vout=0,
# and finally print a copy-pastable bitcoin-cli command:
#
#   bitcoin-cli -rpcwallet=offline signrawtransactionwithwallet "$RAW" \
#     "[{\"txid\":\"$TO_SPEND_TXID\",\"vout\":0,\"scriptPubKey\":\"$SPK\",\"amount\":0}]"
#
# Requirements:
# - All hex is normalized to lowercase.
# - scriptPubKey length MUST fit in 1-byte CompactSize (<= 252). Otherwise error.
# - Errors are printed in English to stderr and the script exits non-zero.
#
# Notes:
# - The spend transaction uses the user-provided fixed template:
#   RAW_SPEND = "0000000001" + txidLE + "000000000000000000010000000000000000016a00000000"
# - This spend tx has an empty scriptSig, sequence=0, one output with value=0 and script=OP_RETURN.

die() {
  echo "Error: $*" >&2
  exit 1
}

trim() {
  # Trim leading/trailing whitespace from a string.
  local s="$1"
  s="${s#"${s%%[!$' \t\r\n']*}"}"
  s="${s%"${s##*[!$' \t\r\n']}"}"
  printf '%s' "$s"
}

read_input() {
  # Read a single line prompt safely (no backslash escapes).
  local prompt="$1"
  local out
  read -r -p "$prompt" out || die "Failed to read input."
  printf '%s' "$out"
}

normalize_hex() {
  # Normalize a hex string:
  # - trim
  # - remove all whitespace
  # - strip optional 0x prefix
  # - validate hex-only and even length
  # - lowercase
  local s="$1"
  s="$(trim "$s")"
  s="$(printf '%s' "$s" | tr -d ' \t\r\n')"
  if [[ "${s:0:2}" == "0x" || "${s:0:2}" == "0X" ]]; then
    s="${s:2}"
  fi
  [[ -n "$s" ]] || die "scriptPubKey is empty."
  if ! [[ "$s" =~ ^[0-9A-Fa-f]+$ ]]; then
    die "scriptPubKey contains non-hex characters."
  fi
  if (( ${#s} % 2 != 0 )); then
    die "scriptPubKey has an odd number of hex characters."
  fi
  s="$(printf '%s' "$s" | tr 'A-F' 'a-f')"
  printf '%s' "$s"
}

sha256_hex_string() {
  # Compute SHA256 of an ASCII string (no newline), return lowercase hex.
  local msg="$1"
  command -v sha256sum >/dev/null 2>&1 || die "sha256sum is not available on this system."
  local d
  d="$(printf '%s' "$msg" | sha256sum | awk '{print $1}' | tr 'A-F' 'a-f')" || die "Failed to compute SHA256."
  [[ "$d" =~ ^[0-9a-f]{64}$ ]] || die "Failed to compute a valid SHA256 digest."
  printf '%s' "$d"
}

sha256d_txid_from_rawhex() {
  # Compute TXID from raw transaction hex:
  # txid = reverse_bytes(SHA256(SHA256(tx_bytes))) rendered as lowercase hex.
  #
  # Uses python3 if available (preferred). Falls back to xxd+openssl if available.
  local rawhex="$1"
  rawhex="$(printf '%s' "$rawhex" | tr 'A-F' 'a-f')"

  [[ "$rawhex" =~ ^[0-9a-f]+$ ]] || die "Raw transaction contains non-hex characters."
  (( ${#rawhex} % 2 == 0 )) || die "Raw transaction hex length is odd."

  if command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY' "$rawhex"
import sys, hashlib, re
raw = sys.argv[1].strip()
if not re.fullmatch(r"[0-9a-f]+", raw) or len(raw) % 2:
    print("Error: invalid raw transaction hex.", file=sys.stderr)
    sys.exit(1)
b = bytes.fromhex(raw)
h = hashlib.sha256(hashlib.sha256(b).digest()).digest()
print(h[::-1].hex())
PY
    return $?
  fi

  # Fallback: requires xxd and openssl
  command -v xxd >/dev/null 2>&1 || die "python3 is not available and xxd is missing (cannot compute TXID)."
  command -v openssl >/dev/null 2>&1 || die "python3 is not available and openssl is missing (cannot compute TXID)."

  local h
  h="$(
    printf '%s' "$rawhex" \
      | xxd -r -p \
      | openssl dgst -sha256 -binary \
      | openssl dgst -sha256 -binary \
      | xxd -p -c 32 \
      | tr -d '\n' \
      | tr 'A-F' 'a-f'
  )" || die "Failed to compute sha256d."

  # Reverse bytes for display txid
  printf '%s' "$h" | sed 's/../& /g' | awk '{for(i=NF;i>0;i--) printf $i; print ""}'
}

reverse_hex_bytes() {
  # Reverse byte order of a hex string (expects even length).
  local h="$1"
  h="$(printf '%s' "$h" | tr 'A-F' 'a-f')"
  [[ "$h" =~ ^[0-9a-f]+$ ]] || die "Internal error: non-hex in reverse_hex_bytes."
  (( ${#h} % 2 == 0 )) || die "Internal error: odd-length hex in reverse_hex_bytes."
  printf '%s' "$h" | sed 's/../& /g' | awk '{for(i=NF;i>0;i--) printf $i; print ""}'
}

main() {
  local bqe btc spk

  bqe="$(trim "$(read_input 'Enter BQE address: ')")"
  btc="$(trim "$(read_input 'Enter BTC address: ')")"
  spk="$(read_input 'Enter scriptPubKey (hex): ')"

  [[ -n "$bqe" ]] || die "BQE address is empty."
  [[ -n "$btc" ]] || die "BTC address is empty."

  # Normalize scriptPubKey to lowercase hex
  spk="$(normalize_hex "$spk")"

  # 1) message = "<bqe><space><btc>" (exactly one ASCII space)
  local message="${bqe} ${btc}"

  # 2) digest = SHA256(message) lowercase hex
  local digest
  digest="$(sha256_hex_string "$message")"

  # 3) Build the coinbase-like raw hex (as per your fixed template)
  local spk_len_bytes=$(( ${#spk} / 2 ))

  # Enforce 1-byte CompactSize encoding only (<= 252).
  if (( spk_len_bytes > 252 )); then
    die "Invalid script length: ${spk_len_bytes} bytes (must fit in 1 byte CompactSize, i.e., <= 252)."
  fi

  local spk_len_hex
  spk_len_hex="$(printf '%02x' "$spk_len_bytes" | tr 'A-F' 'a-f')"
  [[ "$spk_len_hex" =~ ^[0-9a-f]{2}$ ]] || die "Invalid script length encoding (expected exactly 1 byte)."

  local PREFIX_A="00000000010000000000000000000000000000000000000000000000000000000000000000ffffffff220020"
  local MIDDLE_B="00000000010000000000000000"
  local SUFFIX_C="00000000"

  local coinbase_raw="${PREFIX_A}${digest}${MIDDLE_B}${spk_len_hex}${spk}${SUFFIX_C}"
  [[ "$coinbase_raw" =~ ^[0-9a-f]+$ ]] || die "Internal error: coinbase raw contains non-hex characters."

  # 4) Compute TXID of the coinbase-like transaction (display form, big-endian hex)
  local to_spend_txid
  to_spend_txid="$(sha256d_txid_from_rawhex "$coinbase_raw")" || exit $?
  to_spend_txid="$(printf '%s' "$to_spend_txid" | tr -d '\r\n' | tr 'A-F' 'a-f')"
  [[ "$to_spend_txid" =~ ^[0-9a-f]{64}$ ]] || die "Failed to compute a valid TXID."

  # 5) txidLE to embed into the spend raw (byte-reversed form)
  local txid_le
  txid_le="$(reverse_hex_bytes "$to_spend_txid")"
  txid_le="$(printf '%s' "$txid_le" | tr -d '\r\n' | tr 'A-F' 'a-f')"
  [[ "$txid_le" =~ ^[0-9a-f]{64}$ ]] || die "Internal error: invalid txidLE."

  # 6) Assemble the spend raw using the provided fixed template
  local spend_prefix="0000000001"
  local spend_suffix="000000000000000000010000000000000000016a00000000"
  local raw_spend="${spend_prefix}${txid_le}${spend_suffix}"
  [[ "$raw_spend" =~ ^[0-9a-f]+$ ]] || die "Internal error: spend raw contains non-hex characters."

  # 7) Print a copy-pastable bitcoin-cli command (stdout only)
  #    Keep the user's requested quoting/escaping style.
  printf 'bitcoin-cli signrawtransactionwithwallet "%s" \\\n' "$raw_spend"
  printf '  "[{\\"txid\\":\\"%s\\",\\"vout\\":0,\\"scriptPubKey\\":\\"%s\\",\\"amount\\":0}]"\n' "$to_spend_txid" "$spk"
}

main "$@"
