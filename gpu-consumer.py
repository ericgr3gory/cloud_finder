#!/home/ericgr3gory/python-hashes/.venv/bin/python3


import os
import signal
import subprocess
import sys
from pathlib import Path
import logging
from time import sleep
from subprocess import Popen
from redis_connection import RedisConnection
import socket

LOG_DIR = Path("~/.hashcat/logs").expanduser()
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "redis_consumer.log"
HOST_NAME = socket.gethostname()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(str(LOG_FILE), mode="a"),
        logging.StreamHandler(sys.stdout),
    ],
    force=True,
)
logger = logging.getLogger(__name__)

stop = False


def _stop(*_):
    global stop
    stop = True


signal.signal(signal.SIGINT, _stop)
signal.signal(signal.SIGTERM, _stop)


def check_file(filename):
    filename = Path(filename)
    for _ in range(99):
        if filename.is_file():
            return True
        sleep(0.1)

    return False


def validate_job(job: dict) -> bool | None:
    """
    job: {'job_id': str, 'algorithm_id': str, 'total_hashz': int, 'hashz': str, 'cmd': list[str]}
    """
    if job is None:
        return False
    try:
        hashz = job["hashz"]
        hashcat_cmd = job["cmd"]
        job_id = job["job_id"]
        algo = job["algorithm_id"]
        total_hashz = job["total_hashz"]
    except KeyError as e:
        logger.error(f"error parsing job keys {e}")
        return False

    if not hashz or not check_file(hashz):
        logger.error(f"hashz or hashz file doesn't exsist: {hashz}")
        return False

    if not isinstance(hashcat_cmd, (list, tuple)) or not hashcat_cmd:
        logger.error(f"Job {job_id} has no command")
        return False

    if not isinstance(algo, str):
        logger.error(f"algo is not a str {algo}")
        return False

    if not isinstance(total_hashz, int):
        logger.error(f"total hashz is not an int {total_hashz}")
        return False

    return True


def get_crackin(job: dict) -> None | Popen:
    """
    job: {'job_id': str, 'algorithm_id': str, 'total_hashz': int, 'hashz': str, 'cmd': list[str]}
    """
    hashcat_cmd = job["cmd"]
    job_id = job.get("job_id")
    algo = job.get("algorithm_id")
    total_hashz = job.get("total_hashz")
    log_path = str(LOG_DIR / f"hashcat.{job_id}.log")

    try:
        with open(log_path, "a", buffering=1) as logf:
            proc = subprocess.Popen(
                hashcat_cmd,
                stdout=logf,
                stderr=logf,
                text=True,
                start_new_session=True,
            )
    except Exception as e:
        logger.exception("Failed to launch hashcat for job %s: %s", job_id, e)
        return None

    msg_parts = [
        "Launched",
        f"Job: {job_id}",
        f"Algo: {algo}",
        f"Total hashz: {total_hashz}",
        f"Pid: {proc.pid}",
        f"Log: {log_path}",
        f"Command: {' '.join(hashcat_cmd)}",
    ]
    msg = "\n".join(msg_parts)
    logger.info(msg)
    return proc


def kill_process(process):
    for k in range(4):
        try:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=1)
            return process
        except subprocess.TimeoutExpired:
            pass
        except ProcessLookupError:
            return process


def term_process(process):
    for k in range(4):
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=1)
            return process
        except subprocess.TimeoutExpired:
            logger.warning("TERM timed out; sending KILL to %s", process.pid)
        except ProcessLookupError:
            return process
    return kill_process(process)


def restore_command_parser(job):
    cmd = job["cmd"]
    new_cmd = []
    for n, c in enumerate(cmd):
        if "--session" in c:
            new_cmd = ["hashcat", "--restore", "--session", cmd[n + 1]]
            job["cmd"] = new_cmd
            return job

    logger.warning(f"restore job creation fialed {job}")
    return None


def main():
    r = RedisConnection()
    proc = None
    running_job: dict | None = None

    while not stop:

        """
        clean up any closed procs
        """

        if proc and proc.poll() is not None:
            proc.wait(timeout=0)
            exitcode = proc.returncode
            logger.info(f"Job: {proc.args}\nExited: {exitcode}")
            proc = None
            if running_job:
                if running_job.get("background"):
                    r.remove_background_inflight(
                        HOST_NAME, running_job.get("redis_payload")
                    )
                if running_job.get("restore"):
                    r.remove_restore_inflight(
                        HOST_NAME, running_job.get("redis_payload")
                    )
            running_job = None

        """
        check for new priority job
        """

        priority_job, redis_payload = r.pop_priority_job()

        if priority_job:
            if not validate_job(priority_job):
                r.remove_priorty_inflight(redis_payload)
                continue

            if proc and proc.poll() is None:
                proc = term_process(proc)

            if running_job:
                if running_job.get("background"):
                    r.remove_background_inflight(
                        HOST_NAME, running_job["redis_payload"]
                    )
                if running_job.get("restore"):
                    r.remove_restore_inflight(HOST_NAME, running_job["redis_payload"])

                job_restore_command = restore_command_parser(running_job.get("job"))
                if job_restore_command:
                    r.send_job_to_restore(job_restore_command, HOST_NAME)

            proc = get_crackin(priority_job)
            if proc:
                running_job = {
                    "job": priority_job,
                    "priority": True,
                    "redis_payload": redis_payload,
                }
            if proc:
                proc.wait()
                r.remove_priorty_inflight(redis_payload)

        """
        restore job from reedis if no priority and no current restore and no background jobs are running
        """
        if proc is None:
            restore_job, redis_payload = r.pop_restore_job(HOST_NAME)
            if restore_job:
                if not validate_job(restore_job):
                    r.remove_restore_inflight(HOST_NAME, redis_payload)
                    continue
                proc = get_crackin(restore_job)
                if proc:
                    running_job = {
                        "job": restore_job,
                        "restore": True,
                        "redis_payload": redis_payload,
                    }

            """
            start a job on background queue if nothing is running and restore list is empty
            """
            if not restore_job:
                background_job, redis_payload = r.pop_background_job(HOST_NAME)

                if background_job:
                    if not validate_job(background_job):
                        r.remove_background_inflight(HOST_NAME, redis_payload)
                        continue
                    proc = get_crackin(background_job)
                    if proc:
                        running_job = {
                            "job": background_job,
                            "background": True,
                            "redis_payload": redis_payload,
                        }

    logger.info("Shutting down cleanly.")


if __name__ == "__main__":
    main()
