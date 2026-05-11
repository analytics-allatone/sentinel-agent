"""
Sentinel Agent - Output Writer
Writes events to:
  1. Rotating JSONL files (primary storage)
  2. stdout (optional, for piping to SIEM/Splunk/ELK)
  3. SQLite (optional, for local querying)
"""

import json
import gzip
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from queue import Queue
<<<<<<< HEAD:src/agent/output/writer.py
# from ..db.db import DBWriter
from ..logger import Logger
from .raw_writer import RawLogWriter
import asyncio
=======
>>>>>>> 054876c48453f3eef355b7426b79420d85c45659:agent/output/writer.py

import asyncio


# ─────────────────────────────────────────────
#  JSONL ROTATING WRITER
# ─────────────────────────────────────────────

class RotatingJSONLWriter:
    """
    Writes events as newline-delimited JSON.
    Rotates file when it exceeds max_size_mb.
    Keeps last max_files rotated archives (gzip compressed).
    """

    def __init__(
        self,
        output_dir: str = "./logs",
        base_name: str = "sentinel",
        max_size_mb: float = 50.0,
        max_files: int = 20,
        compress: bool = True,
    ):
        self.output_dir  = Path(output_dir)
        self.base_name   = base_name
        self.max_size    = int(max_size_mb * 1024 * 1024)
        self.max_files   = max_files
        self.compress    = compress
        self._lock       = threading.Lock()
        self._fh         = None
        self._current_path: Optional[Path] = None

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._open_file()

    def _current_filename(self) -> Path:
        return self.output_dir / f"{self.base_name}.jsonl"

    def _open_file(self):
        self._current_path = self._current_filename()
        self._fh = open(self._current_path, "a", encoding="utf-8")

    def _rotate(self):
        if self._fh:
            self._fh.close()

        # Rename current → timestamped
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        rotated = self.output_dir / f"{self.base_name}.{ts}.jsonl"
        self._current_path.rename(rotated)

        # Compress
        if self.compress:
            gz_path = rotated.with_suffix(".jsonl.gz")
            with open(rotated, "rb") as fin, gzip.open(gz_path, "wb") as fout:
                fout.write(fin.read())
            rotated.unlink()
            rotated = gz_path

        # Prune old archives
        archives = sorted(
            self.output_dir.glob(f"{self.base_name}.*.jsonl*"),
            key=lambda p: p.stat().st_mtime
        )
        while len(archives) > self.max_files:
            archives.pop(0).unlink(missing_ok=True)

        self._open_file()

    def write(self, event_dict: dict):
        line = json.dumps(event_dict, ensure_ascii=False, default=str) + "\n"
        with self._lock:
            self._fh.write(line)
            self._fh.flush()
            if self._current_path.stat().st_size > self.max_size:
                self._rotate()

    def close(self):
        with self._lock:
            if self._fh:
                self._fh.close()




class EventDispatcher:
    def __init__(
        self,
        jsonl_dir: str = "./logs",
        stdout: bool = False,
        category_split: bool = True,
    ):
        self._queue     = Queue(maxsize=50000)
        self._stdout    = stdout
        self._cat_split = category_split
        self._stop      = threading.Event()
        self.event_list = []

        # Primary writer (all events)
        self._main_writer = RotatingJSONLWriter(jsonl_dir, "sentinel-all")

        # Per-category writers
        self._cat_writers: dict = {}
        self._raw_writer = RawLogWriter(jsonl_dir, "sentinel-raw")

        if category_split:
            for cat in ("file", "authentication", "network", "process", "system"):
                self._cat_writers[cat] = RotatingJSONLWriter(jsonl_dir, f"sentinel-{cat}")
        # Dedicated per-collector writers (keyed on event["collector"] field)
        # This gives us e.g. sentinel-usb.jsonl, sentinel-harddisk.jsonl independently
        self._collector_writers: dict = {
            "usb_monitor":      RotatingJSONLWriter(jsonl_dir, "sentinel-usb"),
            "harddisk_monitor": RotatingJSONLWriter(jsonl_dir, "sentinel-harddisk"),
        }

        # The worker thread owns its own event loop AND creates DBWriter inside it
        self._loop: asyncio.AbstractEventLoop = None
<<<<<<< HEAD:src/agent/output/writer.py
        # self._db_writer: DBWriter = None
=======
>>>>>>> 054876c48453f3eef355b7426b79420d85c45659:agent/output/writer.py
        self._loop_ready = threading.Event()

        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="sentinel-writer"
        )
        self._thread.start()
        self._loop_ready.wait()   # wait until the loop + DBWriter are ready

    # ── thread entry point ──────────────────────────────────────────────────
    def _run_loop(self):
        """Creates a dedicated event loop for this thread and runs it forever."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        # Init DBWriter here so its engine/pool belong to THIS loop
<<<<<<< HEAD:src/agent/output/writer.py
        async def _init():
            # self._db_writer = DBWriter()   # asyncio.run inside __init__ is gone (see db.py fix below)
            # await self._db_writer.init()
            pass
        self._loop.run_until_complete(_init())
=======
        # async def _init():
        #     self._db_writer = DBWriter()   # asyncio.run inside __init__ is gone (see db.py fix below)
        #     await self._db_writer.init()

        # self._loop.run_until_complete(_init())
>>>>>>> 054876c48453f3eef355b7426b79420d85c45659:agent/output/writer.py
        self._loop_ready.set()

        # Drain the queue until stopped
        self._loop.run_until_complete(self._drain())
        self._loop.close()

    async def _drain(self):
        while not self._stop.is_set():
            try:
                # non-blocking peek; sleep briefly if empty
                try:
                    event = self._queue.get_nowait()
                except Exception:
                    await asyncio.sleep(0.05)
                    continue
                await self._write(event)
            except Exception as ex:
                print(f"Dispatcher error: {ex}")

    # ── public API ──────────────────────────────────────────────────────────
    def push(self, event_dict: dict):
        try:
            self._queue.put_nowait(event_dict)
        except Exception:
            print("Event queue full, dropping event")

    async def _write(self, event: dict):
        # Main JSONL
        self._main_writer.write(event)

        # Batch accumulation
        self.event_list.append(event)
        print(f"len of events {len(self.event_list)}")
        if len(self.event_list) >= 30:
            batch = self.event_list[:]      # snapshot
            self.event_list = []            # clear BEFORE await, so failures don't re-queue
<<<<<<< HEAD:src/agent/output/writer.py
            try:
                await self._db_writer.write_into_db_batch(batch)
            except Exception as ex:
                # logger.error(f"Batch DB write failed, dropping {len(batch)} events: {ex}")
=======
            # try:
            #     await self._db_writer.write_into_db_batch(batch)
            # except Exception as ex:
            #     logger.error(f"Batch DB write failed, dropping {len(batch)} events: {ex}")
>>>>>>> 054876c48453f3eef355b7426b79420d85c45659:agent/output/writer.py
                # optionally: write failed batch to a dead-letter JSONL here
                pass
        # Category-split JSONL
        cat = event.get("category", "system")
        if cat in self._cat_writers:
            self._cat_writers[cat].write(event)

        # Collector-specific JSONL (e.g. sentinel-usb.jsonl, sentinel-harddisk.jsonl) 
        collector = event.get("collector", "")
        if collector in self._collector_writers:
            self._collector_writers[collector].write(event)


        # Stdout
        if self._stdout:
            print(json.dumps(event, default=str), flush=True)
        # Raw human-readable log
        self._raw_writer.write(event)

    def flush_and_stop(self):
        self._stop.set()
        self._thread.join(timeout=10)
        self._main_writer.close()
        self._raw_writer.close()
        for w in self._cat_writers.values():
            w.close()
        for w in self._collector_writers.values():
            w.close()  