"""
Redis-backed message queue.
Messages are stored as JSON in a Redis list keyed by recipient net_id.
Pub/sub notifies connected clients of new messages.
"""
import json
import redis

_r = redis.Redis(host="localhost", port=6379, decode_responses=True)


def _inbox_key(net_id: str) -> str:
    return f"inbox:{net_id}"


def enqueue_message(recipient: str, message: dict):
    _r.rpush(_inbox_key(recipient), json.dumps(message))
    _r.publish(f"notify:{recipient}", "new")


def dequeue_messages(recipient: str) -> list[dict]:
    key = _inbox_key(recipient)
    pipe = _r.pipeline()
    pipe.lrange(key, 0, -1)
    pipe.delete(key)
    results, _ = pipe.execute()
    return [json.loads(m) for m in results]


def get_pubsub():
    return _r.pubsub()


def ping() -> bool:
    try:
        return _r.ping()
    except Exception:
        return False
