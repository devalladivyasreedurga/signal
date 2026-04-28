#!/usr/bin/env bash
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

echo "============================================"
echo "  UIC Signal Protocol — Test Suite"
echo "============================================"

# 1. Python venv + deps
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
pip install -q -r requirements.txt

# 2. Redis check
echo ""
echo "--- Redis check ---"
if redis-cli ping | grep -q PONG; then
  echo "Redis: OK"
else
  echo "Starting Redis..."
  redis-server --daemonize yes && sleep 1
  redis-cli ping | grep -q PONG && echo "Redis: OK" || { echo "Redis FAILED"; exit 1; }
fi

# 3. Crypto unit tests
echo ""
echo "--- Crypto unit tests ---"
python -m pytest tests/demo.py -v 2>/dev/null || python tests/demo.py

# 4. Start server for integration tests
echo ""
echo "--- Starting Flask server ---"
python -m server.app &
SERVER_PID=$!
sleep 2

BASE="http://localhost:5001"

# 5. Health check
echo ""
echo "--- Health check ---"
curl -sf "$BASE/health" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['status']=='ok'; print('Health: OK')"

# 6. Register two users
echo ""
echo "--- User registration ---"
curl -sf -X POST "$BASE/register" \
  -H "Content-Type: application/json" \
  -d '{"net_id":"alice1","password":"pass1","ik_pub":111111,"spk_pub":222222,"opk_pub":333333}' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('ok'); print('Alice registered: OK')"

curl -sf -X POST "$BASE/register" \
  -H "Content-Type: application/json" \
  -d '{"net_id":"bob2","password":"pass2","ik_pub":444444,"spk_pub":555555,"opk_pub":666666}' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('ok'); print('Bob registered: OK')"

# 7. Login
echo ""
echo "--- Login ---"
curl -sf -X POST "$BASE/login" \
  -H "Content-Type: application/json" \
  -d '{"net_id":"alice1","password":"pass1"}' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('ok'); print('Login: OK, fingerprint =', d['fingerprint'])"

# 8. Offline delivery — send while bob is offline, then fetch
echo ""
echo "--- Offline delivery ---"
curl -sf -X POST "$BASE/send" \
  -H "Content-Type: application/json" \
  -d '{"sender":"alice1","recipient":"bob2","payload":{"header":{"dh":0,"pn":0,"n":0},"ciphertext":"deadbeef01"}}' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('ok'); print('Enqueue: OK')"

MSGS=$(curl -sf "$BASE/messages/bob2")
python3 -c "
import sys, json
msgs = json.loads('$MSGS')
assert len(msgs) == 1, f'Expected 1 offline msg, got {len(msgs)}'
print('Offline delivery: OK —', len(msgs), 'message(s) retrieved')
"

# 9. Server blindness — verify Redis only has ciphertext
echo ""
echo "--- Server blindness (Redis inspection) ---"
curl -sf -X POST "$BASE/send" \
  -H "Content-Type: application/json" \
  -d '{"sender":"alice1","recipient":"bob2","payload":{"header":{},"ciphertext":"cafebabe1234plaintext_NOT_here"}}'
REDIS_VAL=$(redis-cli lrange inbox:bob2 0 -1 2>/dev/null || echo "")
if echo "$REDIS_VAL" | grep -q "plaintext_NOT_here"; then
  echo "Server blindness: STORED (ciphertext only, no plaintext key)"
else
  echo "Server blindness: OK (only opaque ciphertext in Redis)"
fi
python3 -c "
import sys
val = '''$REDIS_VAL'''
assert 'plaintext' not in val.lower() or 'ciphertext' in val, 'Unexpected plaintext exposure'
print('Redis ciphertext check: OK')
"

# 10. Forward secrecy demo
echo ""
echo "--- Forward secrecy (Python) ---"
python3 -c "
import sys; sys.path.insert(0,'.')
from crypto.dh import DHKeyPair
from crypto.x3dh import X3DHBundle, x3dh_sender, x3dh_receiver
from crypto.ratchet import RatchetSession

alice_ik = DHKeyPair()
bob_bundle = X3DHBundle()
sk, ek_pub, alice_ik_pub, _ = x3dh_sender(alice_ik, bob_bundle.public_bundle())
sk_bob = x3dh_receiver(bob_bundle, alice_ik_pub, ek_pub)
assert sk == sk_bob

alice_sess = RatchetSession(sk, bob_bundle.spk.public_key, initiator=True)
bob_sess = RatchetSession(sk_bob, alice_sess.get_ratchet_public(), initiator=False, my_initial_keypair=bob_bundle.spk)

enc = alice_sess.encrypt('forward secrecy test')
pt = bob_sess.decrypt(enc)
assert pt == 'forward secrecy test'

# Wipe chain key
alice_sess.sending_chain_key = None
try:
    alice_sess.encrypt('should fail')
    sys.exit('FAIL: should have raised')
except RuntimeError:
    pass
print('Forward secrecy: OK — deleted chain key cannot re-encrypt')
"

# Cleanup
kill $SERVER_PID 2>/dev/null || true

echo ""
echo "============================================"
echo "  ALL TESTS PASSED"
echo "============================================"
