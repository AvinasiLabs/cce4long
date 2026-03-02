# API Test Flow (Posting TUI)

## Prerequisites

0. Install [Posting](https://posting.sh) ([GitHub](https://github.com/darrenburns/posting)):
   ```bash
   uv tool install posting
   ```
1. Start cced:
   ```bash
   cd cce4long && cargo run --bin cced
   ```
2. Open Posting TUI in the `api-tests/` directory:
   ```bash
   cd cce4long/api-tests && posting
   ```
3. The `posting.env` file is auto-loaded, providing `$upload_token` (a long-lived dev token bound to dataset `0x4242...4242`).

## Test Sequence

### Phase 1: Auth Rejection

| # | Test Name | Expected |
|---|-----------|----------|
| 1 | Upload no auth | 401 — missing Authorization header |
| 2 | Finalize no auth | 401 — missing Authorization header |

### Phase 2: Single File Upload + Finalize

| # | Test Name | Expected |
|---|-----------|----------|
| 3 | Upload dataset | 200 — uploads `data.csv` |
| 4 | Upload large dataset | 200 — uploads `large_data.csv`, multiple chunks |
| 5 | Upload empty body | 200 — uploads `empty.csv`, 0 chunks |
| 6 | Finalize dataset | 200 — receipt lists 3 files, status `ready` |
| 7 | Finalize already finalized | 409 — dataset already in ready state |
| 8 | Upload dataset (repeat) | 409 — upload rejected after finalize |

### Phase 3: Batch Upload with Deep Directories

> Restart cced to reset state, then run:

| # | Test Name | Upload Path | Expected |
|---|-----------|-------------|----------|
| 9 | Upload deep dir sensor data | `raw/2024/01/sensors/temperature.csv` | 200 |
| 10 | Upload deep dir humidity data | `raw/2024/01/sensors/humidity.csv` | 200 |
| 11 | Upload processed summary | `processed/2024/q1/summary.json` | 200 |
| 12 | Upload model weights | `models/v1/weights.bin` | 200 |
| 13 | Upload pipeline config | `config/pipeline.toml` | 200 |
| 14 | Finalize after batch upload | — | 200 — receipt lists 5 files |

### Phase 4: Upload Token Issuance

> Tests the `/v1/upload-token` endpoint using a test wallet (private key in Notes below).

| # | Test Name | Expected |
|---|-----------|----------|
| 15 | Issue upload token | 200 — returns `{ token, expires_in }` |
| 16 | Issue upload token - bad signature | 401 — signature must be 65 bytes |

## Notes

- **Token**: All upload/finalize tests use the dev token from `posting.env`, valid until 2036.
- **State**: Finalize locks a dataset permanently. Restart cced between Phase 2 and Phase 3 to reset.
- **Storage**: Uploaded files go to the configured storage backend (local or S3). Each dataset directory contains a `.meta.json` tracking lifecycle state (`uploading` → `ready`).
- **Test Wallet** (no funds, safe to publish):
  - Address: `0x10c77Eb3C94D0129AF6626733CABf5d1a5811899`
  - Private Key: `0x33d4c7001aad4acf3ababc101d44cfcbc0637e42db75ff24d2f1789035795093`
  - Used by Phase 4 tests. Signature was generated with `cast wallet sign`.
