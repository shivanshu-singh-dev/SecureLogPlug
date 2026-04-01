# SecureLogPlug

SecureLogPlug is a tamper-evident logging utility for Python applications.
It links each log entry to the previous one using HMAC-SHA256 so unauthorized changes are detectable.

## What is tamper-evident logging?
Tamper-evident logging is a way to record events so any modification, reordering, or deletion of historical entries leaves cryptographic evidence. Instead of preventing writes, it makes unauthorized edits detectable during verification.

## How HMAC works (brief)
HMAC combines a secret key with message data and a cryptographic hash (SHA-256 here) to produce an authentication tag. Without the secret key, attackers cannot forge valid tags for modified log entries.

## How SecureLogPlug works
Each entry stores:
- `index`
- `timestamp`
- `event_type`
- `description`
- `metadata`
- `previous_hash`
- `current_hash`

Hash chain formula:

`current_hash = HMAC(secret_key, serialized_log_data + previous_hash)`

The logger stores data in append-only JSON Lines (`logs.json`) and writes tamper alerts to `alerts.log`.

## How to run

### 1) Provide a secret key
Via CLI:

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

## Security note
If an attacker deletes the entire log file and recreates it, detection requires external anchoring.
Examples of anchoring include periodically publishing a trusted checkpoint hash to an external system (database, SIEM, signed ledger, etc.).

