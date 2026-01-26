#!/home/ericgr3gory/python-hashes/.venv/bin/python3

from inotify_simple import INotify, flags
from dotenv import load_dotenv
import os
import logging
import sys
from pathlib import Path
from time import sleep
import time
import redis
import json
import socket
from redis.exceptions import RedisError, ConnectionError


load_dotenv()

API_KEY = os.getenv("HASHES_API_KEY")
POTS_DIR = Path("~/.hashcat/pots").expanduser()
POTS_DIR.mkdir(parents=True, exist_ok=True)
FOUNDS_PATH = Path("~/.hashcat/cracked").expanduser()
FOUNDS_PATH.mkdir(parents=True, exist_ok=True)
LOG_DIR = Path("~/.hashcat/logs").expanduser()
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "watcher.log"
FAILED_UPLOADS_FILE = "/tmp/failed_uploads.txt"
UPLOAD_TIME_LAST = time.time() - 2.0
UPLOAD_TIMES = []
NUMBER_OF_UPLOADS = 0
REDIS_HOST = os.getenv("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB = int(os.getenv("REDIS_DB", "0"))
REDIS_QUEUE = "hashkitty:founds_queue"
HOSTNAME = socket.gethostname()


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, mode="a"),
        logging.StreamHandler(sys.stdout),
    ],
    force=True,
)

logger = logging.getLogger(__name__)


def connect_redis():
    while True:
        try:
            r = redis.Redis(
                host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True
            )
            r.ping()
            logger.info(
                "Connected to redis %s:%s db=%s; consuming from %s",
                REDIS_HOST,
                REDIS_PORT,
                REDIS_DB,
                REDIS_QUEUE,
            )
            return r
        except RedisError as e:
            logger.warning(f"Redis fail {e}")
            sleep(2)


def push_to_redis(r_connect, founds_data):
    payload = json.dumps(founds_data, ensure_ascii=False, separators=(",", ":"))
    for _ in range(3):
        try:
            r_connect.rpush(REDIS_QUEUE, payload)
            logger.info("Founds payload sent")
            return True, r_connect
        except (ConnectionError, RedisError) as e:
            logger.warning(f"Redis push failure {e}")
            r_connect = connect_redis()

    return False, r_connect


def read_found_file(file: str):
    found_hashes = set()

    with open(file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            sline = line.strip()
            if sline:
                found_hashes.add(sline)

    return found_hashes


def write_to_file(founds: set):
    with open(FAILED_UPLOADS_FILE, "a", encoding="utf-8") as f:
        for found in founds:
            f.write(found + "\n")


def check_for_founds(file_name, uploaded_hashes):

    found_file = str(FOUNDS_PATH / file_name)

    try:
        found_hashes = read_found_file(found_file)

    except FileNotFoundError as e:
        logger.error(e)
        return False

    return found_hashes - uploaded_hashes


def get_algo(file):
    algo = file.split(".")
    return algo[-2]


inotify = INotify()
watch_flags = flags.CLOSE_WRITE
wd = inotify.add_watch(str(FOUNDS_PATH), watch_flags)

logger.info(f"Monitoring {FOUNDS_PATH} started...")
already_uploaded_hashes = set()
r = connect_redis()

while True:
    for event in inotify.read():
        if not event.name or not event.name.endswith(".txt"):
            continue
        if not (event.mask & flags.CLOSE_WRITE):
            continue

        logger.info(f"Event: CLOSE_WRITE on {event.name}")

        algorithm = get_algo(event.name)
        new_founds = check_for_founds(event.name, already_uploaded_hashes)
        if new_founds:
            founds_data = {
                "algorithm": algorithm,
                "source_host": HOSTNAME,
                "filename": event.name,
                "founds": list(new_founds),
                "ts": int(time.time()),
            }

            push_founds = push_to_redis(r, founds_data)
            push_status, r = push_founds
            if push_status:
                already_uploaded_hashes.update(new_founds)
                count = len(new_founds)
                logger.info(
                    f"{event.name} {algorithm} pushed to redis ({count} cracks)"
                )

            else:
                write_to_file(new_founds)
                logger.info("failed to push new founds saved to file")
                r = connect_redis()
