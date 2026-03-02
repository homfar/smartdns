# Sync protocol
Signature: HMAC(token, timestamp + "\n" + nonce + "\n" + body_sha256), replay window 300s.
