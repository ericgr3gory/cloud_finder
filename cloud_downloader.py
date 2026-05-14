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


def to_absolute(p):
    p = Path(p)
    if p.is_absolute():
        return str(p)
    return str(Path.home() / p)


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


def write_blob(job):
    file_name = job.get("hashz")
    file_name = to_absolute(file_name)
    blob = job.get("blob")
    Path(file_name).write_text(blob, encoding="utf-8")


def parse_download(job_data):
    job = json.loads(job_data)
    if not job.get("blob"):
        dl_hashz(job_data)
    else:
        write_blob(job)


def main():
    r = RedisConnection()
    previous_download = None

    while True:
        latest_download = r.get_latest_download()

        if not latest_download:
            sleep(0.2)
            continue

        if latest_download == previous_download:
            sleep(0.2)
            continue

        download = r.get_dowload_url(latest_download)

        if download:
            parse_download(download)
            previous_download = latest_download

        sleep(0.2)


if __name__ == "__main__":
    main()
