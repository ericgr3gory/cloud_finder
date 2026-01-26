#!/home/ericgr3gory/python-hashes/.venv/bin/python3
import json
import requests
import logging
from pathlib import Path
from redis_connection import RedisConnection
from time import sleep


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger()


HASH_DIR = Path("~/.hashcat/hashz").expanduser()
HASH_DIR.mkdir(parents=True, exist_ok=True)


def dl_hashz(data) -> str | None:
    job = json.loads(data)
    algorithm_id = str(job.get("algorithmId"))
    unfound_left = job.get("leftList")

    if not unfound_left:
        logger.warning("No unfound_left path provided")
        return None

    url = f"https://hashes.com{unfound_left}"
    file_name = f"{algorithm_id}-{unfound_left.rsplit('/', 1)[-1]}"
    unfounds_file = HASH_DIR / file_name

    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
    except requests.HTTPError as e:
        logger.warning("HTTP %s for %s", e.response.status_code, url)
        return None
    except requests.RequestException as e:
        logger.warning("Request failed for %s: %s", url, e)
        return None

    unfounds_file.write_text(r.text, encoding="utf-8")
    logger.info("Downloaded unfound hashes to %s", unfounds_file)

    return str(unfounds_file)


def main():
    r = RedisConnection()
    last_dl = None

    while True:
        download = r.get_dowload_url()
        if download and download != last_dl:
            dl_hashz(download)
            last_dl = download
        sleep(0.2)


if __name__ == "__main__":
    pass
