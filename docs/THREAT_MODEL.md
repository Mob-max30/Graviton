# TrustLedger Threat Model

This document outlines the assets, adversary models, trust boundaries, assumptions, defenses, and honest limitations of TrustLedger.

## 1. Protected Assets & Security Goals
- **Protected Resources & Content Bodies:** Confidentiality and integrity of stored assets.
- **Cryptographic Key Material:** Secrecy of long-term identity keys, ephemeral KEM private keys, symmetric ratchet keys, and backup encryption keys.
- **Authorization & Revocation State:** Immediacy, durability, and tamper-resistance of revocation tombstones.
- **Audit Logs:** Immutability, non-repudiation, and append-only tamper-evidence for all access and administrative decisions.
- **Service Availability:** Bounded resource consumption, lock timeouts, HTTP body size limits, and rate limiting.

## 2. Adversaries & Threat Vectors
- **Network Eavesdropper & Active Attacker:** Can intercept, inject, drop, duplicate, reorder, or corrupt network frames. Attempts packet replay, reflection, downgrade of cryptographic suites, or MITM.
- **Malicious Insider / Compromised Client:** Possesses valid client credentials but attempts unauthorized access to unowned resources, privilege escalation without approvals, or lateral movement across services.
- **State-Dir Tamperer:** Has local read/write access to `TRACK4_STATE_DIR` (without access to `TRACK4_KEY_DIR`) and attempts to alter `state.json`, inject forged audit entries, or restore outdated state.
- **Quantum Adversary (Store Now, Decrypt Later):** Records encrypted traffic today with the objective of breaking classical public-key cryptography once cryptanalytically relevant quantum computers exist.

## 3. Trust Boundaries
- **Client-to-Service Boundary:** Handled at `track4_service.py` via strict JSON parsing, configurable `TRACK4_MAX_INPUT_BYTES` (default 1 MiB), 64 KiB identifier limits, and default-deny access checks.
- **Dashboard HTTP Boundary:** Read-only `/api/adapter/dispatch` vs bearer-token authenticated `/api/adapter/admin` and expensive endpoints (`TRUSTLEDGER_UI_TOKEN`), bounded `Content-Length`, same-origin CORS default, and security headers.
- **Key Storage Boundary:** Derived HMAC keys (`k_state`, `k_audit`) are stored in `TRACK4_KEY_DIR` (strictly separate from `TRACK4_STATE_DIR`) with `0700`/`0600` permissions.
- **Peer Trust Boundary:** Handshake requires out-of-band pinned public key fingerprints in `TrustedPeerStore`.

## 4. Defenses Mapped to Evidence
| Threat Vector | Defense Mechanism | Evidence Verification |
|---|---|---|
| **Quantum Eavesdropping** | NIST FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65) | `tests/adapter/test_protected_read.py` & `tests/unit/test_suites.py` |
| **MITM / Unpinned Peer** | `TrustedPeerStore` fingerprint pinning checked before signature verify | `tests/unit/test_suites.py::test_unpinned_or_attacker_key_rejected` |
| **Replay, Reordering & UKS** | Bounded skipped-key ratchet, 12-field Associated Data binding, transcript binding | `tests/unit/test_ratchet.py` & `tests/unit/test_suites.py` |
| **Forward Secrecy Loss** | Ephemeral KEM exchange; immediate deletion of ephemeral keys | `tests/unit/test_suites.py` |
| **Network Loss / Chunk Forgery** | 16 KiB chunking + Reed-Solomon FEC + keyed HMAC-SHA256 chunk & whole-message tags | `tests/property/test_fec_and_delivery.py` |
| **Revocation TOCTOU Race** | Advisory file lock synchronization on every operation; use-time check | `tests/adversarial/test_adversarial_suite.py` |
| **State-Dir Tampering & Rollback** | HMAC-SHA256 + `.head.json` anti-rollback head isolated in `TRACK4_KEY_DIR`; fail-closed `integrity_violation` | `tests/adapter/test_core_security_fixes.py` & `tests/adversarial/test_redteam_regressions.py` |
| **Log Forgery / Tail Truncation** | Canonical JSONL, SHA-256 hash chains, ML-DSA-65 / HMAC verification (`verify-log --mode signed|hmac`) | `tests/unit/test_audit_log.py` |
| **Lateral Movement** | Graph analysis grouping unexpected denied edges into candidate sequences | `tests/unit/test_practice_golden.py` |

## 5. Exclusions & Honest Residual Risks
1. **Host / TPM Boundary:** TrustLedger isolates `TRACK4_KEY_DIR` from `TRACK4_STATE_DIR`, but without a hardware TPM/HSM or separate OS privilege account, a root attacker with read/write access to **both** directories can still forge local MACs or wipe state.
2. **PKI Scope:** Peer authentication relies on out-of-band key pinning in `TrustedPeerStore`, not a full X.509 certificate authority or revocation distribution point.
3. **Side-Channel Timing:** Cryptographic primitives rely on vetted C libraries (`pqcrypto`, `cryptography`), but high-level Python code cannot guarantee cycle-constant-time execution.
4. **Synthetic Event Limits:** Compliance on the 22-event practice dataset proves functional compatibility; it does not constitute an operational guarantee against unseen zero-day attacks.
5. **Simulated Cluster Gossip:** Cluster revocation nodes run as an in-process simulated anti-entropy gossip layer; measured propagation reflects localhost simulation, not multi-datacenter network RTT.
6. **Judged-Core At-Rest Confidentiality:** Judged-core stored asset bodies rely on OS file permissions (`0600`/`0700`) because third-party AEAD libraries are excluded from the judged fast-path import tier.
7. **FEC & AEAD Layer Separation:** The Reed-Solomon FEC channel uses keyed HMAC-SHA256 chunk and whole-message tags, while end-to-end payload confidentiality comes from the ChaCha20-Poly1305 AEAD ratchet layer; the two layers are tested separately.
8. **Detector Scope:** The detector uses deterministic rules + median/MAD non-parametric statistics only (zero ML); evaluation is on synthetic + public practice data, not a production dataset.
9. **Memory Zeroization:** Ephemeral key deletion/zeroization in Python is best-effort due to interpreter garbage collection and immutable `bytes` objects.
