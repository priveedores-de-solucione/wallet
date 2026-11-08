"""
Botchain -> Dune indexer for FaucetDrops (fast + crash-proof).
Run: python botchain.py
Resumes from the stored cursor; retries transient RPC failures;
checkpoints data every 25 ranges so crashes never lose progress.
"""
import csv
import io
import os
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import requests
from supabase import create_client
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

# ── CONFIG ────────────────────────────────────────────────────────────────
RPC_URL      = os.getenv("BOTCHAIN_RPC", "https://rpc.botchain.ai")
DUNE_API_KEY = os.environ["DUNE_API_KEY"]
SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_SERVICE_KEY"]
DUNE_TABLE   = "botchain_faucetdrops_activity"

RANGE_SIZE       = 10000   # blocks per eth_getLogs call
MIN_RANGE        = 250
WORKERS          = 4       # parallel RPC fetches (8 was tripping the node)
RETRY_MAX        = 6       # retries per range on transient RPC errors
CHECKPOINT_EVERY = 25      # persist + advance cursor every N ranges

FACTORIES = {
    "0xda66c58e6941ac1bec3cf7cf15386ab7858a4a0f",  # droplist
    "0x636685bcfeef6baeb05872f01e69405077eaf633",  # dropcode
    "0xd73170170e002b45ea4aa51e7e93302d61c30173",  # custom
    "0xe7f93a609babfe25912402f57e46aeb94115fbd6",  # quest
    "0x8ec988f892034f7cb7b80576590b1a9ec000ad54",  # quiz
}
DIRECT = {
    "0xbad791f200f1f8fb639d83125fcf732f5f6ecd03",  # DROPS token
    "0x9825670865b896738cf8e6c98d093ad5b40f0a11",  # redeem pool
    "0xe7f217a8447087600c1cbfb63192586edfa619fe",  # quizHub
    "0xfe762b4e60914bc1f745e26b297234c52b98ede8",  # CustomFaucet
}
EXCLUDED_SENDERS = {
    # "0xyourresolverwallet...",
    # "0xyourbackendwallet...",
}

TRANSFER_TOPIC = Web3.keccak(text="Transfer(address,address,uint256)").hex()

w3 = Web3(Web3.HTTPProvider(RPC_URL, request_kwargs={"timeout": 60}))
w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
sb = create_client(SUPABASE_URL, SUPABASE_KEY)

# ── SUPABASE HELPERS ──────────────────────────────────────────────────────
def load_children() -> set:
    rows = sb.table("botchain_children").select("address").execute().data
    return {r["address"].lower() for r in rows}

def save_child(address: str, factory: str, block: int):
    sb.table("botchain_children").upsert(
        {"address": address.lower(), "factory": factory,
         "found_at_block": block}).execute()

def get_cursor() -> int:
    return sb.table("botchain_cursor").select("last_block") \
             .eq("id", 1).execute().data[0]["last_block"]

def set_cursor(block: int):
    sb.table("botchain_cursor").update(
        {"last_block": block}).eq("id", 1).execute()

def seed_agg() -> defaultdict:
    """Load already-persisted totals so merges a
    re always correct."""
    agg = defaultdict(int)
    page = 0
    while True:
        batch = sb.table("botchain_activity").select("*") \
                  .range(page * 1000, page * 1000 + 999).execute().data
        if not batch:
            break
        for r in batch:
            agg[(r["day"], r["from_address"], r["contract"])] = r["tx_count"]
        page += 1
    return agg

def persist(agg):
    rows = [{"day": d, "from_address": u, "contract": c, "tx_count": n}
            for (d, u, c), n in agg.items()]
    for i in range(0, len(rows), 500):
        sb.table("botchain_activity").upsert(rows[i:i + 500]).execute()
    print(f"  checkpoint: {len(rows)} rows persisted")

# ── LOG HELPERS ───────────────────────────────────────────────────────────
def word_to_address(word: bytes):
    if len(word) == 32 and word[:12] == b"\x00" * 12:
        return Web3.to_checksum_address(word[12:]).lower()
    return None

def get_logs(from_block: int, to_block: int, addresses: list):
    return w3.eth.get_logs({
        "fromBlock": from_block,
        "toBlock": to_block,
        "address": [Web3.to_checksum_address(a) for a in addresses],
    })

def discover_children_from_logs(logs, tracked: set):
    for log in logs:
        factory = log["address"].lower()
        words = [bytes(t) for t in log["topics"][1:]]
        data = bytes(log["data"])
        words += [data[i:i + 32] for i in range(0, len(data), 32)]
        for word in words:
            addr = word_to_address(word)
            if addr and addr not in tracked:
                if len(w3.eth.get_code(Web3.to_checksum_address(addr))) > 2:
                    tracked.add(addr)
                    save_child(addr, factory, log["blockNumber"])
                    print(f"  new child faucet: {addr}")

def attribute_via_logs(receipt):
    for log in receipt["logs"]:
        topics = log["topics"]
        if len(topics) == 3 and topics[0].hex() == TRANSFER_TOPIC:
            recipient = word_to_address(bytes(topics[2]))
            if recipient and recipient not in EXCLUDED_SENDERS:
                return recipient
    return None

# ── SCAN ──────────────────────────────────────────────────────────────────
def scan_range(start: int, end: int, tracked: set, agg: dict) -> int:
    factory_logs = get_logs(start, end, list(FACTORIES)) if FACTORIES else []
    discover_children_from_logs(factory_logs, tracked)

    logs = get_logs(start, end, list(tracked))
    if not logs:
        return 0

    tx_hashes = list({log["transactionHash"] for log in logs})
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        receipts = list(pool.map(w3.eth.get_transaction_receipt, tx_hashes))

    block_nums = list({r["blockNumber"] for r in receipts})
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        headers = list(pool.map(lambda n: w3.eth.get_block(n), block_nums))
    day_of = {h["number"]: datetime.fromtimestamp(
        h["timestamp"], tz=timezone.utc).strftime("%Y-%m-%d") for h in headers}

    counted = 0
    for r in receipts:
        if r["status"] != 1:
            continue
        to = (r["to"] or "").lower() if r["to"] else ""
        if to not in tracked:
            continue
        sender = r["from"].lower()
        user = attribute_via_logs(r) if sender in EXCLUDED_SENDERS else sender
        if user:
            agg[(day_of[r["blockNumber"]], user, to)] += 1
            counted += 1
    return counted

TRANSIENT_MARKERS = ("connection", "remote", "reset", "timeout", "timed out",
                     "temporarily", "unavailable", "502", "503", "504")
SIZE_MARKERS = ("limit", "range", "too many", "response size", "query returned")

def scan():
    global RANGE_SIZE
    tracked = FACTORIES | DIRECT | load_children()
    head = w3.eth.block_number - 5
    start = get_cursor() + 1
    if start > head:
        print("nothing to scan — already at chain head")
        return

    print(f"scanning {start:,} -> {head:,}  ({len(tracked)} tracked)")
    agg = seed_agg()
    print(f"  seeded {len(agg)} existing rows from Supabase")

    current = start
    ranges_done = 0
    last_persisted_end = start - 1

    while current <= head:
        end = min(current + RANGE_SIZE - 1, head)
        attempt = 0
        while True:
            try:
                n = scan_range(current, end, tracked, agg)
                print(f"  {current:,}-{end:,}: {n} txs")
                break
            except Exception as e:
                msg = str(e).lower()
                if any(k in msg for k in SIZE_MARKERS) and RANGE_SIZE > MIN_RANGE:
                    RANGE_SIZE = max(MIN_RANGE, RANGE_SIZE // 2)
                    end = min(current + RANGE_SIZE - 1, head)
                    print(f"  range too big, retrying with {RANGE_SIZE}")
                elif any(k in msg for k in TRANSIENT_MARKERS) and attempt < RETRY_MAX:
                    attempt += 1
                    wait = min(60, 5 * attempt)
                    print(f"  RPC hiccup ({type(e).__name__}), "
                          f"retry {attempt}/{RETRY_MAX} in {wait}s")
                    time.sleep(wait)
                else:
                    # Unrecoverable: save what we have before dying.
                    persist(agg)
                    set_cursor(last_persisted_end)
                    raise

        current = end + 1
        ranges_done += 1
        if ranges_done % CHECKPOINT_EVERY == 0:
            persist(agg)
            set_cursor(end)
            last_persisted_end = end

    # Final checkpoint.
    persist(agg)
    set_cursor(head)

# ── UPLOAD ────────────────────────────────────────────────────────────────
def upload_to_dune():
    rows, page = [], 0
    while True:
        batch = sb.table("botchain_activity").select("*") \
                  .range(page * 1000, page * 1000 + 999).execute().data
        if not batch:
            break
        rows += batch
        page += 1
    if not rows:
        print("no rows to upload yet")
        return
    buf = io.StringIO()
    wr = csv.DictWriter(
        buf, fieldnames=["day", "from_address", "contract", "tx_count"])
    wr.writeheader()
    wr.writerows(rows)
    r = requests.post(
        "https://api.dune.com/api/v1/table/upload/csv",
        headers={"X-DUNE-API-KEY": DUNE_API_KEY},
        json={"table_name": DUNE_TABLE,
              "description": "FaucetDrops activity on Botchain (self-indexed)",
              "data": buf.getvalue(),
              "is_private": False},
        timeout=180,
    )
    r.raise_for_status()
    print(f"uploaded {len(rows)} rows to Dune")

if __name__ == "__main__":
    scan()
    upload_to_dune()
    print("done ✓")