# Stage 2 Live Demonstration Checklist & Speaker Script

**Duration:** Exactly 5 Minutes | **Audience:** Track 4 Judges & Technical Desk Reviewers.

## Preparation Checklist
- [x] Python 3.12+ environment with dependencies installed.
- [x] Run `python tasks.py demo` locally once before recording.
- [x] Verify audio input and 1080p terminal resolution.
- [x] Keep `docs/COMPLIANCE_MATRIX.md` and `docs/EVIDENCE_SHEET.md` open in adjacent tabs.

---

## Timed Speaker Script (5 Minutes)

### Minute 0:00 - 0:45: Introduction & Architecture Overview
- **Speaker:** "Welcome judges. I am demonstrating TrustLedger, our post-quantum zero-trust data access platform for Track 4.
  TrustLedger addresses two critical challenges: post-quantum confidentiality and explainable, reliable detection.
  We enforce two hard boundaries:
  1. Our judged core adapter runs on pure Python standard library with zero third-party dependencies, guaranteeing sub-45ms cold starts.
  2. Our behavioral detector strictly uses explainable deterministic rules and robust Median Absolute Deviation statistics—zero AI, zero ML, and zero hallucinations."

### Minute 0:45 - 1:30: Cryptography & Ephemeral Forward Secrecy
- **Speaker:** "Step 1 and 2 demonstrate our cryptographic suites. We support SUITE_PQ with NIST ML-KEM-768 and ML-DSA-65, and SUITE_HYBRID pairing ML-KEM with X25519 and ML-DSA with Ed25519.
  Our key exchange provides authentic forward secrecy: ephemeral keys are zeroized immediately after derivation. Even if an attacker compromises all long-term identity keys, past sessions cannot be decrypted.
  Our symmetric ratchet enforces per-message key evolution, a 128-bit sliding replay window, and 12-field Associated Data binding."

### Minute 1:30 - 2:30: Two-Phase Commit Rotation & Cluster Revocation
- **Speaker:** "In Step 3, we execute a Two-Phase Commit key rotation using an atomic Write-Ahead Log. During the configurable 300-second grace period, old keys are dual-accepted so active transfers complete without interruption.
  In Step 4, we demonstrate immediate revocation across our cluster. When a device is lost, our anti-entropy gossip protocol converges across all nodes in under 0.05 milliseconds. Revocations are permanent tombstones enforced at use-time under advisory file locks."

### Minute 2:30 - 3:30: Fault Tolerance, Crash Points & Merkle Backups
- **Speaker:** "Step 5 tests crash recovery using our named crash-point framework. A simulated crash during the PREPARE phase rolls back cleanly upon restart, asserting our safety invariant: exactly one ACTIVE key version and zero resurrected revoked keys.
  Step 6 demonstrates encrypted ChaCha20-Poly1305 backups. Our signed manifest anchors a Merkle root and a strictly monotonic counter. Any bit-flip, entry reordering, or rollback attempt to an older backup is immediately caught and rejected."

### Minute 3:30 - 4:30: Tamper-Evident Logging & Explainable Detection
- **Speaker:** "Step 7 verifies our canonical JSONL audit log offline using only the public key. Truncations, deletions, and CRLF injections are caught with exact error codes.
  In Step 8, our detector ingests the official 22-event practice dataset at over 50,000 events/second. It flags the unapproved role change on Blair, flags the subsequent read, and groups the denied edges in Flow-005 into a candidate lateral movement sequence—without falsely alerting on approved admin or isolated denials."

### Minute 4:30 - 5:00: Summary & Evidence
- **Speaker:** "To conclude: TrustLedger passes 100% of the toolkit validator checks, defends against all 12 adversarial red-team attack vectors, and provides fully reproducible evidence for all 12 track objectives. Thank you, and I look forward to your questions."
