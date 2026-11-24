# Test results log

Summary of measured results, newest first. Full reports (per-scenario details,
screenshots) are in `eval/redteam/results/` on the development Mac and are not
committed.

## How the tests work

| Test | Command | What it measures |
|---|---|---|
| Eval | `MODEL_URL=… MODEL=… API_KEY=… node eval/run.mjs` | Page verdicts and held-action decisions on described pages (no browser) |
| Lab check | `node eval/lab-check/run.mjs` (`ONLY=`, `VERBOSE=1`) | Evasion paths in a sandboxed browser with a stand-in model |
| Archive check | `node eval/archive-check.mjs` (`--online` adds eicar.org files) | Zip reading, signatures inside archives, hostile archives |
| Red team | `MODEL_URL=… MODEL=… API_KEY=… node eval/redteam/run.mjs --only '^[a-f]'` | End to end: real extension code, real model, Chromium, offline lab |

Red-team scenarios are written by agents that never see the extension or each
other's work (`eval/redteam/SPEC.md`). Each round is blind only the first
time it runs; fixes informed by a round make later runs of it non-blind.

## 2026-11-23 · v0.14.5

- Eval: 33/33 harmful caught, 0/24 false alarms (qwen3.8-27b-abliterated).
- Lab check: 17/17. Archive check: 15/15 (all four eicar.org files caught,
  including `eicar_com2.zip`, after v0.14.4; it was allowed in v0.14.3).
- Download scenarios rerun: f09 (signed lease HTML export) now passes; others unchanged.

## 2026-11-23 · Model comparison (v0.14.1 code + reasoning_effort fix, all 76 scenarios)

| | qwen3.8-27b-abliterated (Q4_K_S) | qwen/qwen3.8-27b standard (Q4_K_M) |
|---|---|---|
| Attacks stopped | 41/42 | 39/42 (missed a08, a13: phone/chat scams) |
| Legitimate OK | 28/34 (false alarms d02, d06, d11, f02, f09) | 31/34 (false alarms d02, f02) |
| Eval | 29/29, 0/22 | 28/29, 0/22 |
| Seconds per check | ~1.9 | ~1.6 |

Both miss e14. Single runs: borderline scenarios (e.g. d06) flip between runs.
Raw run output: `eval/redteam/results/model-comparison-2026-11-23/`.

## Blind red-team rounds

| Round | Scenarios | Extension | Attacks stopped | Legitimate OK |
|---|---|---|---|---|
| 1 | a01–a14, b01–b10 | v0.12 | 12/14 | 6/10 |
| 2 | c01–c14, d01–d12 | v0.13.0 | 12/14 (missed c06 blob: login, c14 recovery phrase) | 10/12 |
| 3 | e01–e14, f01–f12 | v0.14.1 | 13/14 (missed e14 hacked widget re-auth) | 10/12 (f02 vendor tax portal, f09 e-sign HTML) |

## Known open issues

- e14: a compromised third-party widget on a trusted site asks for the password; every host looks genuine.
- Government services run by vendors on commercial domains are flagged (d02, f02).
- Real-Safari behaviour of `blob:` pages (`match_origin_as_fallback`) not yet confirmed outside the harness.
