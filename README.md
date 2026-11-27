# Graviton — Post-Quantum Identity, Encrypted Vault & E2EE Chat

**Track 4: "Trust, but verify"** — Built on the `TrustLedger` post-quantum cryptographic backend (`ML-KEM-768`, `ML-DSA-65`, `X25519`, `Ed25519`, `ChaCha20-Poly1305`) with tamper-evident audit logging and explainable rule/graph detection (zero AI/ML).

---

## Installation

### Ubuntu / Linux (One-Command Setup)
```bash
git clone https://github.com/Mob-max30/Graviton.git
cd Graviton
source setup.sh
```
*(In a bare Ubuntu Docker container without `git`, run `DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y git` first.)*

### Windows / Manual Setup
```bash
git clone https://github.com/Mob-max30/Graviton.git
cd Graviton
python -m pip install -r requirements.txt
python -m pip install --no-deps -e .
```

---

## Usage (`gt` CLI)

### 1. Register Organization & Start Server (Admin)
```bash
gt -register <company-name>
gt -serve &
```
* Registers the organization, creates its encrypted vault under `data/orgs/<company>_<id>/resources/`, and displays `(<company-name>)` in your bash prompt when on the admin IP.

### 2. Add & List Encrypted Files / Folders
```bash
gt -add <file-or-folder-path>
gt ls
gt ls <folder-name>
```
* Encrypts and stores files under the company vault (`ChaCha20-Poly1305` + `AssociatedData` binding).
* Re-running `gt -add` on an existing file or folder updates modified files and adds new ones in-place while preserving ACLs.

### 3. Define Access & Add People
```bash
gt -add-people
gt people
```
* Choose an existing access identifier (position) or select **Define new access** to name an identifier and assign which files/folders it can access.
* Verifies the member's device IP is reachable and enrolls them as `<position> - <number>` (e.g., `finance - 1`, `finance - 2`).

### 4. Connect User Devices & Switch Organizations
On another container or machine:
```bash
gt -connect <admin-server-ip>
gt orgs
gt use <company-name>
```

### 5. Real-Time Pairwise E2EE Chat
```bash
gt -chat
```
* Lists other members (excluding yourself) and establishes a dedicated pairwise `ML-KEM-768 + X25519` session.
* Listens in real time for incoming messages (your messages appear in **green**, peer messages in **white**; type `/quit` to exit).

---

## Automated Judging Adapter
The root-level [track4_service.py](track4_service.py), [team_app.py](team_app.py), and [threat-model.json](threat-model.json) implement the `Track-4-Toolkit` `stdin`/`stdout` JSON contract (`setup`, `read`, `revoke`, `audit`, `protected_read`).

---

## Security & Operational Policies
* **Cryptography:** `ML-DSA-65` + `Ed25519` signatures, hybrid `ML-KEM-768 + X25519` ephemeral forward-secret handshakes, and `ChaCha20-Poly1305` AEAD with strict Associated Data binding.
* **Key Rotation & Revocation:** Two-phase rotation with explicit cutoff & grace policy; revocations propagate across cluster nodes and persist across restarts/crash recovery.
* **Audit & Detection:** Canonical JSON hash-chained + `ML-DSA-65`-signed logs with Merkle checkpoints; deterministic contextual rules, clock-skew handling, and graph-based lateral movement detection (no AI/ML).
