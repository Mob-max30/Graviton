=====================================================================
GRAVITON - Post-Quantum Organisational Trust and Security Prototype
Hackathon Track 4: "Trust, but verify"
(Post-quantum cryptography, identity and access control)
=====================================================================

STATUS NOTE (READ FIRST)
------------------------
This README is written as the design and verification specification for
the prototype. Every section describes WHAT the system must do and HOW
it will be proven. Anything in square brackets [ ] is a placeholder that
must be filled in from the real implementation or from the organizer
Toolkit before submission. Do not submit this file with any placeholder
left in it, and do not claim a behaviour here that the code and tests do
not actually demonstrate.


TABLE OF CONTENTS
-----------------
 1. One-line USP
 2. What Graviton is (and what it deliberately is not)
 3. Scope and priorities
 4. Sandbox adapter integration (built first)
 5. System architecture
 6. Cryptographic design
 7. Key rotation
 8. Revocation across nodes
 9. Device loss and re-enrolment
10. Crash recovery
11. Backup integrity
12. Audit log integrity
13. Detection engine (routine vs suspicious, lateral movement)
14. Clock differences
15. Replay protection and recipient binding
16. Forward secrecy
17. Delivery under loss or reordering
18. Session resumption
19. Objective-to-test matrix (all 12 objectives)
20. Measurements and benchmark script
21. Disqualification-risk checklist
22. Threat model (summary; full one-page version is in the PDF brief)
23. Known limits
24. Clean-machine setup
25. Running the demo and the tests
26. Repository layout
27. Dependencies
28. Deliverables checklist
29. Live security assessment readiness
30. Build order


---------------------------------------------------------------------
1. ONE-LINE USP
---------------------------------------------------------------------
Every one of the 12 Track 4 objectives is a one-command,
machine-checkable test that produces evidence output.

Graviton is pitched as a verifiable trust platform, not as a feature
list. The claim is only made where a test proves it.


---------------------------------------------------------------------
2. WHAT GRAVITON IS (AND WHAT IT IS NOT)
---------------------------------------------------------------------
Graviton is a self-contained, offline-capable, multi-user security
engine that protects messages as keys, devices and user permissions
change, and that uses its own access logs to show an operator when an
identity gains unexpected privileges or starts accessing other
services.

Core of the product:
  - A Python security engine (library plus plain command-line
    interface) that works on Linux and Windows.
  - Independent enforcement nodes, each holding its own persisted
    security state.
  - A signed, versioned, hash-chained policy/revocation feed.
  - A tamper-evident key-event / audit log.
  - A rule/statistics/graph-based detector with explainable alerts.
  - A thin management layer on top of the engine for administrators.

Deliberately NOT the target of the build (see section 3):
  - Installers or executables.
  - PowerShell as the primary interface.
  - A polished admin UI.
  - File transfer features.
  - Multi-machine LAN deployment.
  - Invitation-flow user experience.
These earn no direct points. The grading is an automated harness
running in a clean sandbox, so they are deferred or cut.


---------------------------------------------------------------------
3. SCOPE AND PRIORITIES
---------------------------------------------------------------------
Correction applied: the original plan was aimed at product polish. The
build is now aimed at the automated Stage 1 assessment.

Priority order (highest first):
  1. Sandbox adapter integration (Toolkit interface).
  2. Cryptographic core.
  3. Rotation, revocation and crash recovery.
  4. Audit log integrity.
  5. Detector with metrics.
  6. Management interface and polish.

Cut or deferred:
  - Installer / executable packaging.
  - File transfer (messages only for the prototype).
  - Multi-machine LAN deployment.
  - Invitation user experience (enrolment is done through a minimal
    admin-approved command).

Interface rule: the engine is a library plus a plain CLI. PowerShell
may call the CLI but is not required, because the clean sandbox is
likely Linux. The CLI must run identically on Linux and Windows.


---------------------------------------------------------------------
4. SANDBOX ADAPTER INTEGRATION (BUILT FIRST)
---------------------------------------------------------------------
Toolkit: https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit

Correction applied: the adapter was previously mentioned only at the
end of the plan. It is now the first thing built.

Rules:
  - The adapter interface defined by the Toolkit is read and mapped
    before any other component is written.
  - The terminal/management layer is never a substitute for the
    security implementation. The adapter calls the same engine code
    that the CLI calls.
  - Adapter behaviour, confirmed from Toolkit v1.0.0 and
    docs/adapter-v1.md:

      Entry point:   exactly ONE file at the repo root, one of
                     track4_service.py / .cjs / .js / .mjs. We use
                     track4_service.py. Application code sits beside it.
      Invocation:    the worker starts a NEW PROCESS PER REQUEST from the
                     submission directory. Read one UTF-8 JSON object from
                     stdin to EOF, write one JSON object to stdout, exit.
                     Diagnostics go to stderr only. Never print keys,
                     shared secrets or protected contents anywhere.
      Identifiers:   treated as opaque strings.
      Runtime:       offline Linux container, Python 3.12, pqcrypto==0.4.0,
                     Node.js 24.11.1. Root filesystem is READ-ONLY. The
                     worker does NOT install dependencies from the
                     submission.
      State:         must live in a writable temp path and be persisted
                     BEFORE a change is acknowledged. Locally the checker
                     sets TRACK4_STATE_DIR; in judging, falls back to
                     `<os_temp_dir>/graviton_state` via
                     `tempfile.gettempdir()`. A fresh container starts
                     empty. State directory is created with mode 0o700
                     and state/log files with 0o600 (where supported).
                     Writes use temp file + flush + os.fsync +
                     os.replace under an exclusive cross-process file lock
                     (`fcntl.flock` on POSIX, `msvcrt.locking` on Windows).

      Operations (request fields besides "op"):
        setup           owners {asset: actor}, contents {asset: body},
                        disabled [actors], key_material (synthetic secret).
                        Initialise; return {"ready":true}. key_material
                        must never appear in stdout/stderr.
        read            actor, asset, request_id. Authorised owner ->
                        {"decision":"allow","body":"<exact body>"};
                        otherwise {"decision":"deny"} with NO protected
                        content. Record the decision under request_id.
        revoke          actor. Revoke, persist, return a JSON object
                        (e.g. {}). Other actors keep access.
        audit           request_id. Return {"request_id":...,
                        "decision":...} as recorded for that read.
        protected_read  actor, asset, challenge, public_key. If
                        authorised: public_key is a Base64 raw ML-KEM-768
                        public key; encapsulate with it and return
                        "ciphertext" (Base64 KEM ciphertext) and "proof"
                        (lowercase hex HMAC-SHA-256 keyed by the shared
                        secret over UTF-8 of challenge + stored_body, no
                        separator). Shared secret never leaves the app.

      Round-trip example from the contract:
        {"op":"revoke","actor":"maya"} then read r02 -> {"decision":"deny"}
        and audit r02 -> {"request_id":"r02","decision":"deny"}.

      threat-model.json:  optional root-level file; the worker recognises
                          {"asset":"protected-resource",
                          "boundary":"identity-check"}. Use only if it
                          accurately describes our design.

      Local checks:  python quickstart.py (demo), and from the Toolkit
                     folder: python validate.py --entry
                     "../Graviton/track4_service.py". The public
                     validator awards no points; it checks setup, read
                     decisions, returned content, revocation, unaffected
                     peer access and audit correlation on the lost-device
                     scenario only. The official worker also runs the
                     protected_read cryptography check.
      Practice data: Toolkit "practice" folder holds practice events and
                     labels; it is a separate exercise and adds NO
                     operation to the judging adapter. Evidence sheet and
                     brief template are in the Toolkit "templates" folder.
      Keep the Toolkit OUT of our submission repository.

    CONSEQUENCES FOR THE DESIGN (these override earlier sections):
      1. The adapter covers only the five operations above. Distributed
         revocation, rotation, crash recovery, messaging, replay,
         forward secrecy, resumption and detection quality are NOT
         exercised by it and need separate evidence (tests, benchmark
         output, evidence sheet).
      2. No long-lived processes inside the adapter. "Enforcement nodes"
         are implemented as separate per-node persisted state
         directories that each call loads and checks; propagation time
         is measured by our own harness across those node states.
      3. Every request reloads state from disk, so persistence must be
         atomic and crash-safe (write temp file, fsync, rename).
      4. Judging dependencies are the Python 3.12 standard library plus
         pqcrypto==0.4.0 ONLY. See section 6 for the effect on AEAD,
         KDF and password hashing.
      5. read and audit must never leak content on deny, and
         key_material must never be logged.

  - An adapter smoke test runs on every commit so integration never
    silently breaks.

  Adapter wiring (Phase 4):
    - Revocation truth lives in the node's signed feed (`Node.check_actor`),
      not in a separate adapter-level disabled list.
    - `setup` generates a random `feed_id` (`secrets.token_hex(16)`) and
      an ML-DSA-65 admin keypair stored in the state area (`admin_key.json`,
      mode `0o600` inside `0o700` generation directory).
    - `setup` is crash-safe via a fresh generation directory plus atomic
      `current_generation.json` pointer switch.
    - `read` and `protected_read` deny outputs never carry reason codes or
      hints; internal reason codes are stored only in `audit_log.jsonl`.


---------------------------------------------------------------------
5. SYSTEM ARCHITECTURE
---------------------------------------------------------------------
Components (distinct modules sharing the same security logic):

  a) Security engine (core library)
       Identity verification, permissions, key lifecycle, session
       security, recipient binding, replay prevention.
  b) Enforcement nodes
       Each node keeps its own persisted state: current key
       versions, revoked keys, policy epoch. Each node decides on its
       own whether to accept a request.
  c) Policy / revocation feed
       Signed, versioned, hash-chained, with a monotonic epoch.
  d) Audit / key-event log
       Hash-chained, signed checkpoints, canonical encoding.
  e) Detection engine
       Rules, statistics and graph methods only.
  f) Communication layer
       Authenticated messaging with a delivery queue.
  g) Management layer
       Thin CLI (and optional thin UI) over the engine for enrolment,
       rotation, revocation, backup verification, log verification.
  h) Sandbox adapter
       Maps the Toolkit interface to the engine.

Central storage correction:
  The earlier plan used one central SQLite database that all nodes
  would effectively trust. That conflicts with "independent
  enforcement nodes": revocation propagation would be trivial, could
  not be honestly measured, and the database would be a single point
  of failure.

  Rectified design:
    - SQLite is used on the organisation host for records (users,
      devices, public keys, queued encrypted messages, events) but is
      NOT the enforcement authority.
    - Authority for key versions, revocation and permissions is the
      signed policy feed (section 8).
    - Each enforcement node persists its own state locally and
      enforces from that state.
    - A node that cannot confirm the freshness of its state fails
      closed (rejects) rather than trusting stale data.

Identity checks, permissions and decision recording (required by the
brief):
  - Identity: every request carries an identity claim verified by an
    ML-DSA signature against the registered public key.
  - Permissions: the node evaluates the verified identity against the
    current policy epoch.
  - Recording: every decision (allow or deny, with reason) is written
    to the audit log with actor taken from the authenticated session.
  - NOTE (Adapter path): in the adapter path (`track4_service.py`),
    the Toolkit harness is the authenticated caller and the `actor`
    field is trusted input. ML-DSA-65 request signatures (`Node.authenticate_request`)
    are used by the node's request authentication API, not by the adapter.


---------------------------------------------------------------------
6. CRYPTOGRAPHIC DESIGN
---------------------------------------------------------------------
Correction applied: the earlier plan said "ML-KEM and suitable
signatures" without specifics. The design is now explicit.

Rule zero: no custom cryptographic primitives. No invented ratchet. No
invented hybrid KDF. Only a vetted PQC library plus standard AEAD and
HKDF.

Algorithms:
  - Key establishment: ML-KEM, using an EPHEMERAL keypair per session.
  - Identity signatures: ML-DSA (SLH-DSA is an alternative).
  - Optional hybrid: X25519 combined with ML-KEM, with the two shared
    secrets combined through a standard HKDF.
  - Message protection: standard authenticated symmetric encryption
    (AEAD), e.g. AES-256-GCM or ChaCha20-Poly1305.
  - Key derivation: HKDF.
  - Library: pqcrypto==0.4.0 (the version in the judging runtime).
    Verified ML-KEM-768 API:
      * Import: `from pqcrypto.kem import ml_kem_768`
      * Key generation: `ml_kem_768.generate_keypair()` -> `(public_key, secret_key)` (1184 B, 2400 B)
      * Encapsulation: `ml_kem_768.encrypt(public_key)` -> `(ciphertext, shared_secret)` (1088 B, 32 B)
      * Decapsulation: `ml_kem_768.decrypt(secret_key, ciphertext)` -> `shared_secret` (32 B)
      * Constants: `PUBLIC_KEY_SIZE = 1184`, `SECRET_KEY_SIZE = 2400`, `CIPHERTEXT_SIZE = 1088`, `PLAINTEXT_SIZE = 32`
      * Installs via prebuilt wheel on Python 3.12 with no extra system packages or compiler steps.
    Verified ML-DSA-65 API:
      * Import: `from pqcrypto.sign import ml_dsa_65`
      * Key generation: `ml_dsa_65.generate_keypair()` -> `(public_key, secret_key)` (1952 B, 4032 B)
      * Signing: `ml_dsa_65.sign(secret_key, message)` -> `signature` (3309 B)
      * Verification: `ml_dsa_65.verify(public_key, message, signature)` -> `bool`
      * Constants: `PUBLIC_KEY_SIZE = 1952`, `SECRET_KEY_SIZE = 4032`, `SIGNATURE_SIZE = 3309`
  - OPEN QUESTION (ask organizers before relying on it): the judging
    container is stated to have only Python 3.12 and pqcrypto==0.4.0,
    and submissions' dependencies are not installed. The standard
    library has no AEAD cipher. Confirm whether an AEAD library (for
    example "cryptography") is present. Until confirmed, the adapter
    path uses only ML-KEM + HMAC-SHA-256 (what the contract needs),
    HKDF is built on stdlib hmac per RFC 5869, and any AEAD-dependent
    messaging features are developed against a documented, clearly
    labelled fallback. Do not invent a custom cipher.

Long-term key rule:
  Long-term identity keys SIGN and never ENCRYPT. This is what gives
  forward secrecy (section 16).

AEAD associated data (bound into every message):
  - recipient ID
  - sender ID
  - session ID
  - message counter
  Any change to the recipient information therefore fails
  authentication (section 15).

Private key storage:
  Correction applied: "protected separately" was hand-waving.
  - Private keys are never stored as ordinary database records.
  - The keystore file is encrypted at rest with a password-derived
    key using scrypt (hashlib.scrypt, standard library) followed by
    AEAD (subject to the open question above).
  - Private keys are never shared with the administrator or other
    users; each user generates their own pair locally.

No hard-coded secrets:
  - No demo keys, passwords or tokens in source or in tests.
  - Test secrets are generated at runtime or passed through
    environment variables / prompts.


---------------------------------------------------------------------
7. KEY ROTATION
---------------------------------------------------------------------
Objective: authorised transfers continue during rotation; every node
rejects new requests using the old key after the documented cutoff;
state whether a grace period applies.

Correction applied: previously there were no cutoff semantics and no
stated grace period.

Design:
  - Each key has a numbered version and a status:
    ACTIVE -> ROTATING -> RETIRED (and REVOKED, section 8).
  - Rotation announces a new version through the signed policy feed
    with an explicit cutoff expressed as a policy epoch (and
    wall-clock time for human reading).
  - Before the cutoff (`applied_epoch < cutoff_epoch`): both the old
    and new key versions are accepted (the transition window) so
    authorised transfers continue uninterrupted.
  - After the cutoff (`applied_epoch >= cutoff_epoch`): nodes reject
    NEW requests that use the old key (`KEY_RETIRED`).
  - Grace period: none (0 epochs / 0 seconds after the cutoff epoch).
    This value is documented here, in the PDF brief and in the test
    that asserts it.
  - Messages already in flight at the cutoff: [state behaviour,
    e.g. completed if the session was established before cutoff].

Test evidence: transfers succeed during rotation; a request with the
old key is accepted before the cutoff and rejected after it on every
node.


---------------------------------------------------------------------
8. REVOCATION ACROSS NODES
---------------------------------------------------------------------
Objective: every node rejects a revoked key; report the time from
revocation until the last node enforces it.

Correction applied: previously "respected by every node" with no
propagation mechanism or latency measurement.

Mechanism:
  - Revocations are entries in a signed, versioned, hash-chained feed
    with a monotonic epoch.
  - Feed encoding: canonical big-endian length-prefixed binary format
    (`graviton/feed/encoding.py`), `MAX_ID_LEN = 256`,
    `MAX_ENTRY_LEN = 16384`, signed with ML-DSA-65 (`domain=b"feed"`),
    hash-chained via SHA-256 over the full serialized entry.
  - Each node verifies the feed signature and chain before applying.
  - Each node persists its applied epoch (`node_state.json`, version 1:
    pinned `feed_id`, `admin_public_key_b64`, `applied_epoch`,
    `last_entry_hash_hex`, `applied_entries`, `last_issued_at`,
    `registry`, `revoked_actors`) and REFUSES to roll back to an
    older epoch.
  - Freshness window: default `None` (freshness not enforced, used by
    the adapter path); the multi-node harness uses `30` seconds. When
    set, a node that cannot confirm freshness within `freshness_window`
    seconds (`clock() - last_issued_at > freshness_window`) fails
    closed with `STALE_STATE`.
  - Revocations are never undone by any recovery path (section 10).

Measurement:
  - A timestamp (`time.monotonic_ns`) is recorded immediately before
    the revocation entry delivery begins.
  - Nodes are simulated as separate state directories on one host
    (not separate machines), with entries delivered in parallel
    threads and configurable seeded millisecond delays.
  - Each node records when a real `Node.authorize()` call first
    returns `deny` after its atomic apply has persisted.
  - Reported figure: time from revocation issue until the LAST node
    enforces it, alongside node count, delay range, and pure compute
    time.

Phase 3 status and known limits:
  - Admin key is pinned at node initialisation and is not rotatable.
  - `applied_entries` grows without bound in `node_state.json`.
  - Clocks are not synchronised across real machines; freshness
    compares the admin's `issued_at` timestamp against the node's own
    clock.


---------------------------------------------------------------------
9. DEVICE LOSS AND RE-ENROLMENT
---------------------------------------------------------------------
Objective: after device loss, its owner can re-enrol and other users
retain access.

Correction applied: previously not addressed at all.

Design:
  - Administrator revokes the lost device's key through the feed
    (section 8).
  - Only that device's key is revoked. Other devices and other users
    keep valid keys and keep access.
  - The owner generates a new keypair locally and re-enrols; the
    administrator approves; the new device receives a fresh
    registration under the same user identity.
  - The revoked device key stays revoked permanently.

Test evidence: after revocation, the lost device is rejected on all
nodes, the owner's new device works, and other users' sessions and
permissions are unaffected.


---------------------------------------------------------------------
10. CRASH RECOVERY
---------------------------------------------------------------------
Objective: after an interrupted rotation the service recovers a
consistent, authorised key version; revoked keys stay revoked;
committed keys and protected data remain available.

Correction applied: previously mentioned only as a goal with no
design.

Rotation as a write-ahead state machine:
  PREPARE  -> COMMIT -> ACTIVATE -> RETIRE
  - Each step is written durably (write-ahead record) before it is
    acted on.
  - The recovery routine reads the last durable step and always lands
    on exactly one consistent version.

Rules enforced by recovery:
  - Revocations are never un-done.
  - Keys committed before the crash remain usable.
  - Protected data remains decryptable with committed keys.
  - Backup material is verified before use (section 11).

Fault injection:
  - A test harness injects a crash after EVERY step of the sequence
    (before/after PREPARE, COMMIT, ACTIVATE, RETIRE) and after each
    write.
  - After each injected crash, recovery is run and the assertions
    above are checked.


---------------------------------------------------------------------
11. BACKUP INTEGRITY
---------------------------------------------------------------------
Objective: recovery detects a damaged key backup and reports the
failure; the service uses only verified key material.

Correction applied: previously "verify backups" was only an admin
action with no mechanism.

Design:
  - Every backup carries a MAC or signature covering its full
    contents plus version metadata.
  - The check runs BEFORE any key material is loaded into memory for
    use.
  - On failure: the backup is rejected, the failure is reported to the
    operator (clear error) and logged in the audit log, and the
    service continues using only previously verified material.
  - Corrupted-backup test: flip bytes, truncate, and swap versions;
    all must be detected.


---------------------------------------------------------------------
12. AUDIT LOG INTEGRITY
---------------------------------------------------------------------
Objective: each event keeps its original identity, action and record
boundary; user-supplied text cannot create an apparent second event or
change the recorded actor; operators can verify the integrity of the
key-event log.

Correction applied: previously only "tamper evident" was stated.

Design:
  - Hash chain: each record includes the hash of the previous
    record.
  - Signed checkpoints: periodic signature over the chain head.
  - Canonical encoding: records use a length-prefixed (or properly
    escaped) encoding so user-supplied text, including newlines or
    delimiter characters, cannot be mistaken for a record boundary or
    a second event.
  - Actor binding: the actor field is taken ONLY from the
    authenticated session, never from user-supplied input.
  - Append-only: enforced at the database level (no UPDATE/DELETE
    permitted on the log table, e.g. via restrictions/triggers).
  - External head hash: the latest chain head (`seq` + `head_hash_hex`)
    is persisted atomically in a separate `audit_head.json` file outside
    the SQLite database so a wholesale rewrite of the database is
    detectable.
  - Operator verification: `python -m graviton.audit verify --db <db>
    --head <head.json> [--pubkey-b64 <pk>]` walks the chain, checks
    signatures and head hash, and reports the first inconsistency.

Test evidence: injected newline/fake-record text appears as inert data
inside a single event; attempts to edit or delete rows are rejected or
detected by verification; actor spoofing attempts are recorded with the
real authenticated actor.


---------------------------------------------------------------------
13. DETECTION ENGINE
---------------------------------------------------------------------
Objectives: distinguish approved administration from suspicious
privilege changes or data access (report F1, median time to alert,
false alerts per 1,000 benign events on labelled logs); flag unusual
access paths between services even with valid credentials (each alert
identifies identity, services, events and the rule or path).

Correction applied: previously no metrics, no labelled dataset, no
context model, no method for lateral movement.

Constraint: rules, statistics and graph-based methods ONLY. There is
no machine-learning component anywhere in the detector, because
AI/ML components are grounds for disqualification.

Context used to separate routine from suspicious:
  - Role of the actor (e.g. administrator vs ordinary user).
  - Approved change window.
  - Presence of an approving ticket / change record.
  - Historical behaviour of the identity (baseline statistics).
  - Target sensitivity.

Privilege-change rules (examples; final list documented in code):
  - Privilege increase by a non-administrator identity: alert.
  - Privilege change by an administrator inside a window with a
    matching ticket: routine.
  - Privilege change by an administrator outside any window or
    without a ticket: alert.

Lateral movement:
  - An allowed-edge graph of service-to-service paths is defined for
    the organisation.
  - Each observed access (identity -> service A -> service B) is
    checked against the allowed edges and the identity's usual paths.
  - Valid credentials do not suppress the alert; an unusual path
    triggers it anyway.

Explainable alerts: every alert contains
  - the identity,
  - the services involved,
  - the event IDs,
  - the rule or graph path that fired and why.

Labelled data:
  - Labelled logs are taken from the Toolkit if supplied; otherwise
    a labelled generator produces benign and malicious scenarios with
    ground truth. [state which]
  - The generator and its seeds are committed so results are
    reproducible.

Metrics reported by the evaluation script (section 20):
  - F1
  - Median time to alert
  - False alerts per 1,000 benign events


---------------------------------------------------------------------
14. CLOCK DIFFERENCES
---------------------------------------------------------------------
Objective: handle events that arrive out of order or carry different
clock offsets; state the supported timing range; flag cases where
event order is uncertain.

Correction applied: previously only listed as a test scenario.

Design:
  - Events are buffered behind a watermark so late arrivals within
    the window are reordered correctly.
  - Per-source clock offsets are estimated and applied.
  - Supported timing range: events with skew up to +/- [N] seconds
    and arrival delay up to [M] seconds are ordered correctly.
    These numbers are stated here, in the PDF brief and in the tests.
  - Outside the supported range, or when two events' ordering depends
    on an offset uncertainty larger than their time gap, the detector
    emits an explicit "order uncertain" flag instead of guessing.
  - Detection rules that depend on order (e.g. "privilege change
    followed by data access") downgrade to the flagged state when
    order is uncertain.

Test evidence: shuffled and skewed log inputs within range produce the
same alerts as clean inputs; inputs beyond range produce
"order uncertain" flags.


---------------------------------------------------------------------
15. REPLAY PROTECTION AND RECIPIENT BINDING
---------------------------------------------------------------------
Objective: only the intended recipient can read an end-to-end
encrypted message; the receiver rejects duplicate messages and
messages whose authenticated recipient information has changed.

Correction applied: previously mentioned with no mechanism.

Design:
  - Message encryption keys derive from a session established with
    the recipient's key material, so only that recipient can decrypt.
  - Recipient ID, sender ID, session ID and a counter are in the AEAD
    associated data; changing the recipient information makes
    authentication fail and the message is rejected.
  - The receiver keeps a cache of seen message IDs / counters per
    session and rejects duplicates.
  - Cache size and retention behaviour: [state, including what
    happens when the cache is full or after restart; the cache is
    persisted so replay across restart is also rejected].

Test evidence: a replayed message is rejected; a message with altered
recipient field is rejected; a third party cannot decrypt.


---------------------------------------------------------------------
16. FORWARD SECRECY
---------------------------------------------------------------------
Objective: later exposure of a long-term identity key alone does not
reveal the contents of earlier, completed sessions.

Correction applied: previously mentioned with no design.

Design:
  - Session keys come from an ephemeral ML-KEM exchange.
  - Long-term identity keys only sign (authenticate) the exchange;
    they never encrypt session content or wrap session keys.
  - Ephemeral private material is erased when the session completes.

Test evidence: record a completed session's transcript, then reveal
the long-term identity key; decryption of the transcript still fails.


---------------------------------------------------------------------
17. DELIVERY UNDER LOSS OR REORDERING
---------------------------------------------------------------------
Objective: the receiver delivers complete, authenticated messages when
recovery succeeds, discards incomplete or invalid messages, and
reports delivery failures.

Correction applied: previously only an offline queue was described,
with nothing on reassembly or failure reporting.

Design:
  - Messages are split into numbered chunks with total-count
    metadata, each authenticated.
  - The receiver reassembles by number so reordering is tolerated.
  - Missing chunks are requested for retransmission up to
    [N retries / T timeout].
  - If recovery succeeds: the complete, authenticated message is
    delivered.
  - If recovery fails or any chunk is invalid: the partial message is
    DISCARDED (never delivered), and a delivery failure is reported
    to the sender/operator and logged.
  - The persistent queue for offline recipients stores only
    encrypted payloads and delivery state.

Test evidence: packet loss and reordering simulation with
deliver-on-recovery, discard-on-failure and failure-report assertions.


---------------------------------------------------------------------
18. SESSION RESUMPTION
---------------------------------------------------------------------
Objective: if supported, a resumed session remains bound to its
authenticated peer; a different identity cannot inherit the session by
presenting the same session identifier.

Correction applied: previously mentioned with no binding.

Design (resumption is supported):
  - Resumption tickets are bound to the authenticated peer's
    identity key.
  - On resume, the peer must prove possession of that identity key;
    presenting the session ID alone is insufficient.
  - A different identity presenting the same session ID is rejected
    and the attempt is logged.
  - Tickets are revoked when the peer's key is rotated or revoked.
  - Tickets expire after [state lifetime].

Test evidence: legitimate resume succeeds; resume by another identity
with the same session ID fails.


---------------------------------------------------------------------
19. OBJECTIVE-TO-TEST MATRIX
---------------------------------------------------------------------
Correction applied: this matrix maps each of the 12 objectives to a
test, an expected outcome and a stated limit. It doubles as the demo
script.

 #  Objective            Test (command / file)        Expected outcome                               Stated limit
 -- -------------------- ---------------------------- ---------------------------------------------- ------------------------------
 1  Key rotation         [test_rotation]              Transfers succeed during rotation; old key     Grace period = [value]
                                                      rejected on all nodes after cutoff
 2  Revocation + device  [test_revocation,            Revoked key rejected by every node; time to    Propagation window = [value];
    loss                  test_device_loss]            last node reported; re-enrol works; others     fail-closed on stale state
                                                      keep access
 3  Crash recovery       [test_crash_recovery]        Consistent authorised version after crash at   Covers injected crash points
                                                      every step; revocations persist                listed in section 10
 4  Backup integrity     [test_backup_integrity]      Damaged backup detected and reported; only     Detects corruption; does not
                                                      verified material used                         restore lost data by itself
 5  Log integrity        [test_log_integrity]         Injection cannot fake events or actor; chain   Assumes external head hash
                                                      verifies; tampering detected                   location is not also rewritten
 6  Routine vs           [eval_detection]             F1, median time to alert, false alerts per     Measured on [dataset]
    suspicious                                         1,000 benign events reported
 7  Lateral movement     [test_lateral_movement]      Unusual path flagged with identity, services,  Depends on a correct allowed-edge
                                                      events and rule/path                           graph
 8  Clock differences    [test_clock_skew]            In-range skew/reorder handled; out-of-range    Supported range +/-[N]s,
                                                      flagged "order uncertain"                      delay [M]s
 9  Replay + recipient   [test_replay_binding]        Duplicates rejected; altered recipient         Replay cache retention = [value]
    binding                                            rejected; only recipient reads
10  Forward secrecy      [test_forward_secrecy]       Past sessions stay unreadable after long-term  Does not protect a session whose
                                                      key exposure                                   ephemeral keys were also leaked
11  Delivery under       [test_lossy_delivery]        Complete messages delivered on recovery;       Retry limit = [value]
    loss/reordering                                    incomplete discarded; failures reported
12  Session resumption   [test_resumption]            Resume bound to peer; other identity with      Ticket lifetime = [value]
                                                      same session ID rejected

(Objectives 1 and 2 above bundle "revocation" and "device loss" because
the brief lists them together in one checklist item; each still has its
own test.)


---------------------------------------------------------------------
20. MEASUREMENTS AND BENCHMARK SCRIPT
---------------------------------------------------------------------
Correction applied: previously nothing was measured. Performance is 10
points and "verifiable outcomes" is part of Functionality, so a single
script prints all required figures.

Command: [e.g. `python -m graviton.bench`]

Outputs:
  - Detection: F1, median time to alert, false alerts per 1,000
    benign events.
  - Revocation: time from revocation until the last node enforces,
    with node count.
  - Rotation: rotation latency and any transfer interruption.
  - Messaging: message encrypt/decrypt latency, session setup latency
    (including ML-KEM and ML-DSA operation costs).
  - Overhead: log-append cost, verification cost, storage overhead.

Results are written to a machine-readable file and a human-readable
summary. Hardware and library versions are printed with every run so
numbers are reproducible. Measured values: [fill in from actual runs].


---------------------------------------------------------------------
21. DISQUALIFICATION-RISK CHECKLIST
---------------------------------------------------------------------
Correction applied: these traps were previously unaddressed.

  [ ] No AI/ML components anywhere. The detector is rules,
      statistics and graph methods only; this is stated in the
      detector docs and the PDF brief.
  [ ] No hard-coded secrets (including demo keys, test passwords,
      tokens). A secret scan runs before submission.
  [ ] No custom cryptographic primitives presented as secure; only
      vetted PQC library + standard AEAD + HKDF. No invented
      ratchet or hybrid KDF.
  [ ] Repository created during the hackathon, with a visible,
      honest commit history (no single bulk import commit).
  [ ] Third-party libraries and any borrowed code are attributed;
      no plagiarism.
  [ ] Testing is limited to the assigned sandbox, mock services and
      test identities. No attacks on other teams or out-of-scope
      systems. No denial-of-service against shared services.


---------------------------------------------------------------------
22. THREAT MODEL (SUMMARY)
---------------------------------------------------------------------
Correction applied: the threat model was previously absent. It is
worth 10 points and rewards honesty. The full one-page version goes in
the PDF brief; this is the working summary.

Protected assets:
  - Long-term identity private keys and ephemeral session keys.
  - Message contents.
  - Key versions, revocation state and permission policies.
  - Audit / key-event log integrity.
  - Backups of key material.

Attackers considered:
  - Network attacker (eavesdrop, replay, reorder, drop, alter).
  - Compromised ordinary user / valid credentials used abnormally
    (lateral movement).
  - Holder of a lost or stolen device.
  - Insider attempting unauthorised database operations or log
    tampering.
  - Attacker who later obtains a long-term key (forward secrecy).
  - Attacker supplying malicious text to the log.

Assumptions:
  - The vetted PQC library implements the standard algorithms
    correctly.
  - The administrator's signing key is protected at enrolment time.
  - Enforcement nodes run the unmodified Graviton code.
  - The external head-hash location is not controlled by the
    attacker.

Limits: see section 23.


---------------------------------------------------------------------
23. KNOWN LIMITS (STATED HONESTLY)
---------------------------------------------------------------------
  - Phase 1 scope covers only the five Toolkit adapter operations
    (`setup`, `read`, `revoke`, `audit`, `protected_read`); key
    rotation, multi-node feed propagation, hash-chained audit logs,
    messaging, and detection are deferred to later phases.
  - Phase 1 state and `key_material` are persisted in JSON with
    restrictive file permissions (0o600/0o700 where supported), not
    yet encrypted at rest pending AEAD availability confirmation.
  - Actor IDs in Phase 1 adapter requests are treated as opaque
    strings per the Toolkit contract without external signature
    verification.
  - Phase 4 adapter wiring limits: the admin ML-DSA-65 secret key sits
    in the state directory in plaintext (mode 0o600) because the
    per-process model gives no other place, so admin and node share a
    trust domain in the adapter path; the feed grows with each revoke;
    `Node.check_actor()` cost grows linearly with feed length (measured
    median on Windows: 1.90 ms at 1 entry, 11.18 ms at 10 entries,
    43.08 ms at 100 entries; end-to-end `read` subprocess p50: 468.85 ms
    at 1 revoke, 493.07 ms at 10 revokes, 506.10 ms at 100 revokes).
  - A compromised host administrator or a compromised host machine
    is out of scope; the SQLite host is trusted for availability and
    for storing queued ciphertext.
  - Queue metadata (who messages whom, when, sizes) is visible to the
    host.
  - No hardware security module; keystore protection relies on a
    password-derived key and may be weakened by a weak password.
  - Side-channel attacks (timing, power, cache) are not defended
    beyond what the underlying library provides.
  - Detection quality depends on the labelled data and the
    configured allowed-edge graph; numbers are only valid for the
    evaluated dataset.
  - Clock handling is correct only within the stated skew and delay
    range; outside it, order is flagged uncertain rather than
    resolved.
  - Fail-closed behaviour on stale state favours security over
    availability.
  - Denial of service is out of scope (and prohibited against shared
    services).
  - [Add any further limits discovered during implementation.]


---------------------------------------------------------------------
24. CLEAN-MACHINE SETUP
---------------------------------------------------------------------
Usability is graded on setup repeatability on a clean machine, so the
steps below must be tested on a fresh sandbox before submission.

Prerequisites:
  - OS: Linux (judging runtime is an offline Linux container); the CLI
    should also run on Windows for development.
  - Python: 3.12 (verified on CPython 3.12.13)
  - System packages needed by pqcrypto==0.4.0: none (installs from
    prebuilt wheel with cffi and pycparser; no compiler required).
  - Node.js is NOT needed (Python adapter).

Steps:
  1. git clone https://github.com/Mob-max30/Graviton.git
  2. cd Graviton
  3. python -m venv .venv   (or: uv venv --python 3.12 .venv)
  4. Activate the environment:
       Linux/macOS:  source .venv/bin/activate
       Windows:      .venv\Scripts\activate
  5. pip install -r requirements.txt
  6. Verify the PQC library imports and runs a self-test:
       python -c "from pqcrypto.kem import ml_kem_768; pk, sk = ml_kem_768.generate_keypair(); ct, ss1 = ml_kem_768.encrypt(pk); ss2 = ml_kem_768.decrypt(sk, ct); assert ss1 == ss2; print('ML-KEM-768 OK')"
  7. Run the adapter test suite:
       python -m unittest discover -s tests -v

Note: confirm that the PQC library installs without manual compilation
steps on a clean machine; if extra system packages are needed, they are
listed above. This is a common failure point.


---------------------------------------------------------------------
25. RUNNING THE DEMO AND THE TESTS
---------------------------------------------------------------------
  - Run Phase 1 adapter tests:      python -m unittest discover -s tests -v
  - Run Toolkit validator (from Toolkit directory):
                                    python validate.py --entry "../Graviton/track4_service.py"
  - Run all objective tests:        [command]
  - Run a single objective test:    [command, see section 19]
  - Run the benchmark/evaluation:   [command, see section 20]
  - Run the demo walkthrough:       [command or script mirroring the
                                      section 19 matrix]
  - Fault-injection suite:          python -m unittest tests/test_crash_recovery.py -v
  - Log verification:               python -m graviton.audit verify --db <db> --head <head.json>
  - Backup verification:            python -m unittest tests/test_backup_integrity.py -v

The demo script follows the objective-to-test matrix order so the
5-minute video and the live demo cover the same ground.


---------------------------------------------------------------------
26. REPOSITORY LAYOUT
---------------------------------------------------------------------
[Fill in to match the real tree. Planned structure:]

  graviton/
    crypto/         ML-KEM-768, ML-DSA-65, RFC 5869 HKDF, AEAD/AAD, scrypt keystore
    nodes/          Enforcement node logic and local persisted state
    feed/           Signed, hash-chained policy/revocation feed
    lifecycle/      Rotation state machine, recovery, backups
    audit/          Hash-chained log, canonical encoding, verification
    detect/         Rules, statistics, graph paths, clock handling
    comms/          Messaging, replay cache, chunking, resumption
    cli/            Plain command-line interface (and thin UI if any)
  tests/            One test module per objective, plus fault injection
  bench/            Benchmark and evaluation scripts, log generator
  docs/             Threat model, architecture, brief sources
  requirements.txt  Dependency list
  README.txt        This file


---------------------------------------------------------------------
27. DEPENDENCIES
---------------------------------------------------------------------
The dependency list is required by the brief. Pin exact versions in
requirements.txt and list them here.

  - PQC library (ML-KEM, ML-DSA):  pqcrypto==0.4.0
  - HMAC, HKDF (RFC 5869 over hmac), scrypt: Python 3.12 standard
    library
  - AEAD / X25519: [pending organizer confirmation, see section 6]
  - Storage: SQLite (Python standard library)
  - Detection: standard library and [any statistics/graph library,
    documented]; NO machine-learning libraries.
  - Test tooling: [name, version]


---------------------------------------------------------------------
28. DELIVERABLES CHECKLIST
---------------------------------------------------------------------
  [ ] Working prototype demonstrated in the organizer sandbox.
  [ ] Public GitHub repository with source, dependency list and this
      README with clean-machine setup steps.
  [ ] 2-page project brief (PDF) containing: USP, system
      architecture, the one-page threat model, and the link to the
      5-minute demo video.
  [ ] 5-minute demo video, publicly accessible (e.g. unlisted
      YouTube or Google Drive), linked inside the PDF as a
      fallback if the live demo fails.
  [ ] README tested on a clean machine.
  [ ] Requirements-to-test matrix (section 19) complete with real
      commands and results.


---------------------------------------------------------------------
29. LIVE SECURITY ASSESSMENT READINESS
---------------------------------------------------------------------
Scoring note: the live assessment starts at 25 points; each confirmed
critical/high/medium/low finding deducts 10/6/3/1, and detecting and
responding restores up to half the deduction.

Preparation:
  - Run the team's own adversarial scenarios beforehand: compromised
    test credentials, unauthorised database operations, replayed
    messages, altered recipient information, corrupted backups,
    interrupted key rotations, clock differences, unreliable
    delivery.
  - Fix findings before the assessment; each unpatched finding
    costs points.
  - Make sure detection and response are visible (alerts and audit
    entries appear while an attack happens) so deductions can be
    partly restored.
  - Practise the 5-minute demo and the 5-minute technical Q&A for
    the desk review.


---------------------------------------------------------------------
30. BUILD ORDER
---------------------------------------------------------------------
  1. Read the Toolkit; build the adapter smoke test.
  2. Cryptographic core (ephemeral ML-KEM, ML-DSA, AEAD, keystore).
  3. Policy/revocation feed and independent node enforcement.
  4. Rotation state machine, crash recovery, backup verification.
  5. Audit log integrity.
  6. Messaging: replay, binding, chunked delivery, resumption.
  7. Detection engine with clock handling and metrics.
  8. Benchmark script and the objective-to-test matrix filled with
     real results.
  9. Threat model, 2-page PDF, README finalisation, demo video.
 10. Management layer polish, only if time remains.

=====================================================================
END OF README
=====================================================================
