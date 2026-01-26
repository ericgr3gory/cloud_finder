import os
import redis
import logging
from dotenv import load_dotenv
from time import sleep
from redis.exceptions import RedisError, ConnectionError
import json


logger = logging.getLogger(__name__)


class RedisConnection:
    def __init__(self):

        load_dotenv()
        self.redis_host = os.getenv("REDIS_HOST", "127.0.0.1")
        self.redis_port = int(os.getenv("REDIS_PORT", "6379"))
        self.redis_db = int(os.getenv("REDIS_DB", "0"))
        self.queue_key = os.getenv("QUEUE_KEY", "hashkitty:jobs")
        self.queue_key_inflight = "hashkitty:jobs_inflight"
        self.queue_key_background = "hashkitty:jobs_background"
        self.queue_key_background_inflight = "hashkitty:jobs_background_inflight"
        self.queue_key_restore = "hashkitty:jobs_restore"
        self.queue_key_restore_inflight = "hashkitty:jobs_restore_inflight"
        self.queue_key_download_hashz = "hashkitty:jobs_dl"
        self.r = self.connect_to_redis()

    def connect_to_redis(self):
        while True:
            try:
                r = redis.Redis(
                    host=self.redis_host,
                    port=self.redis_port,
                    db=self.redis_db,
                    decode_responses=True,
                )
                r.ping()
                logger.info(
                    "Connected to redis %s:%s db=%s",
                    self.redis_host,
                    self.redis_port,
                    self.redis_db,
                )
                return r

            except (RedisError, ConnectionError) as e:
                logger.warning(f"Redis fail {e}")
                sleep(2)

    def _blmove(self, q_key, q_key_inflight, timeout):
        try:
            item: str | None = self.r.execute_command(
                "BLMOVE", q_key, q_key_inflight, "LEFT", "LEFT", timeout
            )
            return item

        except (ConnectionError, RedisError) as e:
            logger.warning(f"Redis pop failure {e}")
            self.r = self.connect_to_redis()
            return None

    def _decode_job(self, item):
        payload = item
        try:
            return json.loads(payload)

        except Exception as e:
            logger.error("JSON parse error: %s", e)
            return None

    def pop_priority_job(self):
        if item := self._blmove(self.queue_key, self.queue_key_inflight, 3):
            return self._decode_job(item), item

        return None, None

    def pop_background_job(self, box):
        inflight_key = f"{self.queue_key_background_inflight}:{box}"
        if item := self._blmove(self.queue_key_background, inflight_key, 0.1):
            return self._decode_job(item), item

        return None, None

    def pop_restore_job(self, box):
        restore_key = f"{self.queue_key_restore}:{box}"
        inflight_key = f"{self.queue_key_restore_inflight}:{box}"
        if item := self._blmove(restore_key, inflight_key, 0.1):
            return self._decode_job(item), item

        return None, None

    def _lrem(self, q_key, payload):
        try:
            success_removal = self.r.lrem(q_key, 1, payload)

        except (ConnectionError, RedisError) as e:
            logger.warning(f"Redis lrem failure {e}")
            self.r = self.connect_to_redis()
            return None

        if success_removal == 1:
            return True
        else:
            return False

    def _lpush(self, q_key, payload):

        try:
            push_status = self.r.lpush(q_key, payload)

        except (ConnectionError, RedisError) as e:
            logger.warning(f"Redis lrem failure {e}")
            self.r = self.connect_to_redis()
            return None

        if push_status >= 1:
            return True
        else:
            return False

    def _set_url(self, q_key, message):
        try:
            self.r.set(q_key, message, ex=10)
            return True
        except (ConnectionError, RedisError) as e:
            logger.warning(f"Redis set failure {e}")
            self.r = self.connect_to_redis()
            return None

    def _get_url(self, q_key):
        try:
            url = self.r.get(q_key)
            return url
        except (ConnectionError, RedisError) as e:
            logger.warning(f"Redis set failure {e}")
            self.r = self.connect_to_redis()
            return None

    def remove_priorty_inflight(self, payload):
        return self._lrem(self.queue_key_inflight, payload)

    def remove_background_inflight(self, box, payload):
        inflight_queue = f"{self.queue_key_background_inflight}:{box}"
        return self._lrem(inflight_queue, payload)

    def remove_restore_inflight(self, box, payload):
        inflight_queue = f"{self.queue_key_restore_inflight}:{box}"
        return self._lrem(inflight_queue, payload)

    def send_job_to_restore(self, job, box):
        payload = json.dumps(job, ensure_ascii=False, separators=(",", ":"))
        q_key = f"{self.queue_key_restore}:{box}"
        return self._lpush(q_key, payload)

    def send_job_to_background(self, job, box):
        payload = json.dumps(job, ensure_ascii=False, separators=(",", ":"))
        q_key = f"{self.queue_key_background}:{box}"
        return self._lpush(q_key, payload)

    def send_job_to_priority(self, job):
        payload = json.dumps(job, ensure_ascii=False, separators=(",", ":"))
        return self._lpush(self.queue_key, payload)

    def set_download_url(self, url):
        return self._set_url(self.queue_key_download_hashz, url)

    def get_dowload_url(self):
        return self._get_url(self.queue_key_download_hashz)


if __name__ == "__main__":
    pass
