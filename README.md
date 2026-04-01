# SecureLogPlug

A plug-and-play tamper-evident logging engine designed for secure audit logging in Python applications.

SecureLogPlug is a tamper-evident logging utility for Python applications. It **cryptographically links each log entry** to the previous one using HMAC-SHA256 so unauthorized changes are detectable.

---

## Features

- HMAC-SHA256 based tamper-evident logging
- Detection of modification, deletion, and reordering
- Append-only JSON log storage (`logs.json`)
- Alert system for tampering detection (`alerts.log`)
- Pluggable library design for easy integration

---

## What is tamper-evident logging?

Tamper-evident logging records events in a way that makes unauthorized edits detectable. If someone modifies, deletes, or reorders historical entries, verification reveals cryptographic inconsistencies.

---

## How HMAC works (brief)

HMAC combines a secret key with message data and a cryptographic hash function (SHA-256 here) to generate an authentication tag. Without the secret key, an attacker cannot forge valid tags for changed log entries.

---

## How SecureLogPlug works

Each log entry stores:

- `index`
- `timestamp`
- `event_type`
- `description`
- `metadata`
- `previous_hash`
- `current_hash`

Hash-chain formula:

```text
current_hash = HMAC(secret_key, serialized_log_data + previous_hash)
```

Logs are stored as append-only JSON Lines in `logs.json`. Tamper alerts are written to `alerts.log`.

---

## Integration Example

SecureLogPlug can be used directly inside any Python application:

```python
from tamperlog import SecureLogPlug

logger = SecureLogPlug(secret_key="mykey")

logger.add_log(
    event_type="LOGIN_FAILED",
    description="User failed login",
    metadata={"ip": "127.0.0.1"},
)

result = logger.verify_logs()
print("Integrity OK:" if result.ok else f"Tampered at index {result.index}")
```

---

## How to run

### 1) Provide a secret key

Via CLI argument:

```bash
python logger.py --secret mykey add LOGIN "User failed login"
```

Via environment variable:

```bash
export SECURELOGPLUG_SECRET=mykey
python logger.py add LOGIN "User failed login"
```

If missing, the CLI exits with an error.

### 2) Add logs

```bash
python logger.py --secret mykey add LOGIN "User failed login" --metadata '{"ip":"127.0.0.1"}'
python logger.py --secret mykey add ACCESS "Viewed confidential file"
```

### 3) Verify chain integrity

```bash
python logger.py --secret mykey verify
```

### 4) View logs

```bash
python logger.py --secret mykey view
python logger.py --secret mykey view --verify
```

---

## Security note

If an attacker deletes the entire log file and recreates it, detection requires external anchoring.

Examples of anchoring:

- Periodically publishing checkpoint hashes to a remote database
- Sending signed checkpoints to SIEM / log management systems
- Writing periodic root hashes to an immutable ledger

---

## Design Philosophy

SecureLogPlug is designed to be secure-by-default:

- No default secret keys
- Append-only storage model
- Immediate tamper detection and alerting

