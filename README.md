# Seed Phrase Recoverer (`spr`)

A fast, offline recovery tool for **partially remembered BIP39 seed phrases** across
**EVM (Ethereum/BSC/…), Bitcoin, Dogecoin, Ripple XRP, Tron, Solana and Cardano**.

You describe what you *do* remember (`lucky ? ? ? photo you ? myself`) and one or more
addresses you know belong to the wallet. `spr` enumerates the unknown words, filters
candidates with the BIP39 checksum, stretches the survivors with
PBKDF2-HMAC-SHA512 (2048 rounds, exactly as the standard requires), derives the
configured addresses and tells you the phrase that reproduces **your** address.

* Rust core, multi-threaded with Rayon (and shardable across processes/machines).
* Runs head-less on **Google Colab, Kaggle, vast.ai, RunPod, any Linux CPU box**, with
  a built-in web dashboard for people who prefer clicking to typing.
* **No network access at runtime.** No RPC calls, no balance scanning, no telemetry:
  a candidate is only ever reported when it derives an address you supplied.

> ### Scope — please read
> This tool verifies candidates against addresses **you provide**. It does not scan
> the blockchain for funded wallets, and it will not accept "find any wallet with a
> balance" as a target. Recovering your own backup is the entire supported use case;
> guessing other people's seed phrases is infeasible *and* is theft. Keep it that way.

---

## 1. Supported networks and default derivation paths

| Network | Default paths | Encoding |
|---|---|---|
| `evm` | `m/44'/60'/0'/0/{0..n}` | EIP-55 checksummed `0x…` (`keccak256`) |
| `btc` | `m/44'/0'/0'/0/{i}` (P2PKH), `m/49'/0'/0'/0/{i}` (P2SH-P2WPKH), `m/84'/0'/0'/0/{i}` (P2WPKH) | Base58Check + bech32 (`bc1…`) |
| `doge` | `m/44'/3'/0'/0/{i}` | Base58Check version `0x1e` |
| `xrp` | `m/44'/144'/0'/0/{i}` | Ripple base58 alphabet |
| `tron` | `m/44'/195'/0'/0/{i}` | Base58Check version `0x41` |
| `solana` | `m/44'/501'/0'/0'` (SLIP-0010 ed25519) | base58 ed25519 pubkey |
| `cardano` | `m/1852'/1815'/0'/0/{i}` + stake `m/1852'/1815'/0'/2/0` (Icarus / CIP-3) | bech32 `addr1…` |

Any path can be overridden with `--path "m/…"`. BIP39 lists are embedded for English,
Spanish, French, Italian, Portuguese, Czech, Korean, Japanese, simplified and
traditional Chinese.

---

## 2. Build

```bash
cargo build --release          # needs Rust >= 1.80 and a C compiler
./target/release/spr selfcheck # 18 published vectors, all must pass
./target/release/spr bench     # seeds/s on this machine
```

## 3. Use

```bash
# one unknown word, verified against your own ETH address
spr recover --phrase "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?" \
    --target evm:0x9858EfFD232B4033E47d90003D41EC34EcaEda94

# two unknown words, several networks at once
spr recover --phrase "lucky ? ? yourself ..." \
    --target evm:0x1234… --target btc:bc1q… --target solana:HAgk…

# you know the positions but not the words
spr recover --phrase "word1 ... word12" --missing 4,9 --target tron:TUEZ…

# you know a fragment of the address
spr recover --phrase "…" --target btc:1LqBGSk --match prefix

# only two possible words for position 3 (shrinks the space 1024x)
spr recover --phrase "…" --at 3=lucky,lonely --target doge:D…

# see the plan first: space size, checksum effect, derivations
spr recover --dry-run --phrase "…" --target evm:0x…

# backup sheet for a phrase you do have
spr derive --phrase "<full mnemonic>" --network all

# dashboard
spr serve --port 8080
```

Useful flags: `--threads N`, `--breadth N` (how many addresses per path),
`--path "m/…"` (repeatable), `--all` (keep going after the first hit),
`--max-candidates N` (safety cap), `--json out.json` (`-` = stdout),
`--shard I/N` (see §6), `--lang english`, `--passphrase "25th word"`.

Exit codes: `0` = phrase found, `1` = search finished without a match, `2` = bad input.

## 4. Dashboard

`spr serve --port 8080` exposes a dark/gold console (Server-Sent Events for live
progress, sparklines, per-network match donut, activity log, JSON export) plus a small
HTTP API (`/api/start`, `/api/status`, `/api/events`, `/api/control`, `/api/analyze`,
`/api/derive`, `/api/wordlist`).

## 5. Cloud: Colab, Kaggle, vast.ai, RunPod

```bash
bash scripts/setup.sh          # installs Rust if missing, builds, self-checks, benchmarks
```

* **Google Colab / Kaggle** — run the two cells in `notebooks/spr_colab.ipynb`; the last
  cell forwards the dashboard:
  ```python
  from google.colab import output
  output.serve_kernel_port_as_window(8080)
  ```
* **vast.ai / RunPod / Lambda / any VM** — `bash scripts/setup.sh`, then either use the
  CLI, or `spr serve --host 0.0.0.0 --port 8080` and open `http://<instance-ip>:8080`
  (open the port in the provider's firewall).
* Nothing is GPU-only: the engine is CPU parallel and scales with cores, which is what
  cheap cloud CPUs give you. See §7 for the GPU status.

## 6. Performance and scaling

`PBKDF2-HMAC-SHA512` is deliberately slow — that is the security property you are
fighting. Measured on this repository's build (2 vCPU sandbox, `spr bench`):

```
429 seeds/s per core   (~2.3 ms per seed; HMAC pad states are precompressed)
```

| Unknown words | Combinations | Seeds after checksum filter | 1 core | 8 cores | 96 cores |
|---|---|---|---|---|---|
| **12-word phrase** (4 checksum bits) | | | 429/s | 3.4k/s | 41k/s |
| 1 | 2 048 | 128 | < 1 s | < 1 s | < 1 s |
| 2 | 4 194 304 | 262 144 | 10 min | 1.3 min | 6 s |
| 3 | 8 589 934 592 | 536 870 912 | 14.5 days | 1.8 days | 3.6 h |
| **24-word phrase** (8 checksum bits) | | | | | |
| 1 | 2 048 | 8 | < 1 s | < 1 s | < 1 s |
| 2 | 4 194 304 | 16 384 | 38 s | 5 s | < 1 s |
| 3 | 8 589 934 592 | 33 554 432 | 21.7 h | 2.7 h | 13.6 min |

Notes:

* Faster CPUs do ~600 seeds/s/core, slower cloud vCPUs ~300.
* `--at POS=word1,word2` multiplies the space by `list_len/2048` per restricted
  position — a 32-word candidate list is a 64× speed-up.
* Splitting across processes/machines: `spr recover --shard 1/8 …`, `--shard 2/8 …`.
  `scripts/run_shards.sh 8 …` launches them on one box.
* Address derivation (secp256k1/ed25519) adds only a few percent per path next to
  PBKDF2, so multi-network searches are nearly free.

## 7. GPU status — please read

The current release is **CPU-only**. There is no CUDA/Metal/WebGPU backend in this
repository, and nothing here claims GPU numbers.

Why it was left out rather than half-added: the PBKDF2 + ed25519/secp256k1 pipeline
would have to be reimplemented in a device kernel, and this workspace has no GPU to
build or validate it against. Shipping an unverified kernel would be worse than not
shipping one — a subtly wrong kernel silently fails to find a phrase, which is exactly
the failure mode a recovery tool must never have.

What to do instead, today:

* Use a many-core CPU instance (the search is embarrassingly parallel and shardable).
* Use `--at` restricted candidate lists wherever you can narrow a position — it beats
  any single-GPU speed-up you would get from the same effort.
* GPU support is the natural next step (WebGPU compute for the PBKDF2 stage, then
  secp256k1 for EVM/BTC), and the engine is already structured for it: candidates are
  produced on the host, so only `PBKDF2(mnemonic) → seed` has to move.

## 8. Verification

`cargo test` and `spr selfcheck` check every derivation against independent references
(`bip_utils` 2.12) and published vectors:

* BIP39 seed (Trezor vector) · BIP32/BIP44/BIP49/BIP84 (BTC P2PKH/P2SH-P2WPKH/P2WPKH),
  EVM, DOGE, XRP, TRON addresses for the standard test mnemonic
* SLIP-0010 ed25519 master/m/0' private keys, chain code and public key; Solana
  `m/44'/501'/0'/0'`
* CIP-3 Icarus master key vector, CIP-1852 payment/stake keys and Shelley base address
* BIP173 bech32
* an end-to-end search that recovers a phrase from its EVM address

`cargo test -p spr-core` covers the PBKDF2/HMAC primitives (RFC 4231 vectors,
`hashlib`-verified multi-block PBKDF2), bit packing/checksum and the engine.

## 9. Repository layout

```
spr-core/            engine library
  src/hmac_fast.rs   PBKDF2-HMAC-SHA512 with precompressed pad states
  src/mnemonic.rs    BIP39 bit packing, checksum filter, seed stretching
  src/bip32.rs       BIP32 secp256k1 (EVM/BTC/DOGE/XRP/TRX)
  src/slip10.rs      SLIP-0010 ed25519 (Solana)
  src/cardano.rs     Icarus master key + BIP32-Ed25519 v2 (Cardano)
  src/addr.rs        address encoders      src/bech32x.rs  bech32
  src/deriv.rs       networks, paths, prepared derivations
  src/engine.rs      parallel search, progress, target matching
  src/vectors.rs     self-check vectors
src/main.rs          CLI (recover/derive/selfcheck/bench/serve/wordlist)
src/web.rs           dashboard server
src/assets/          dashboard HTML/CSS/JS
scripts/             setup.sh (cloud), run_shards.sh
notebooks/           Colab/Kaggle notebook
```

## 10. License

MIT. Use it on your own wallets.
