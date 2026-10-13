"""
speedtest_runner.py - Periodic bandwidth testing via speedtest-cli
"""
import subprocess
import json
import threading
import time
import storage
from storage import utcnow

_thread = None
_stop_event = threading.Event()


def run_once() -> dict | None:
    """Run a single speedtest and return results dict."""
    try:
        # speedtest-cli installs as "speedtest-cli", not "speedtest"
        result = subprocess.run(
            ["speedtest-cli", "--json"],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            print(f"[Speedtest] speedtest-cli exited {result.returncode}: {result.stderr.strip()[:200]}")
            return None
        data = json.loads(result.stdout)
        out = {
            "timestamp": utcnow().isoformat(),
            "download_mbps": round(data["download"] / 1_000_000, 2),
            "upload_mbps": round(data["upload"] / 1_000_000, 2),
            "ping_ms": round(data["ping"], 2),
            "server": data.get("server", {}).get("name", ""),
            "isp": data.get("client", {}).get("isp", ""),
        }
        if not storage.valid_speedtest(out):
            print(f"[Speedtest] Discarding implausible result: {out}")
            return None
        return out
    except Exception as e:
        print(f"[Speedtest] Failed: {e}")
        return None


def run_once_streaming(emit) -> dict | None:
    """Run speedtest using the Python API, streaming live speed via emit(phase, dict).

    Phases emitted:
      ("init", {})
      ("ping", {"ping_ms": float, "server": str})
      ("download", {"speed": float})          -- repeated ~every 300ms
      ("download_done", {"download_mbps": float})
      ("upload", {"speed": float, "download_mbps": float})  -- repeated ~every 300ms
      ("complete", {full result dict})
      ("error", {"message": str})
    """
    try:
        import speedtest as _st
        s = _st.Speedtest()
        emit("init", {})

        s.get_best_server()
        ping = round(s.results.ping, 1)
        server = (s.results.server or {}).get("name", "")
        emit("ping", {"ping_ms": ping, "server": server})

        # ── Download ──────────────────────────────────────────────────────────
        # s.results.bytes_received is only written after download() returns, so
        # we monkey-patch HTTPDownloader to track running threads and sum their
        # live result lists directly.
        emit("download", {"speed": 0})
        dl_done = threading.Event()

        _dl_active = []
        _dl_lock = threading.Lock()
        _dl_done_bytes = [0]
        _OrigDL = _st.HTTPDownloader

        class _TrackedDL(_OrigDL):
            def run(self):
                with _dl_lock:
                    _dl_active.append(self)
                try:
                    super().run()
                finally:
                    with _dl_lock:
                        _dl_active.remove(self)
                        _dl_done_bytes[0] += sum(self.result)

        _st.HTTPDownloader = _TrackedDL

        def _poll_dl():
            start_t = time.perf_counter()
            while not dl_done.is_set():
                time.sleep(0.1)
                with _dl_lock:
                    cur_b = _dl_done_bytes[0] + sum(sum(t.result) for t in _dl_active)
                dt = time.perf_counter() - start_t
                if dt >= 0.3 and cur_b > 0:
                    emit("download", {"speed": round(cur_b * 8 / (dt * 1_000_000), 1)})

        t = threading.Thread(target=_poll_dl, daemon=True)
        t.start()
        dl_bps = s.download()
        dl_done.set()
        t.join(timeout=1)
        _st.HTTPDownloader = _OrigDL

        dl_mbps = round(dl_bps / 1_000_000, 2)
        emit("download_done", {"download_mbps": dl_mbps})

        # ── Upload ────────────────────────────────────────────────────────────
        # Same issue: s.results.bytes_sent is only written after upload() returns.
        # Track live upload bytes via request.data.total (a list appended per chunk).
        emit("upload", {"speed": 0, "download_mbps": dl_mbps})
        ul_done = threading.Event()

        _ul_active = []
        _ul_lock = threading.Lock()
        _ul_done_bytes = [0]
        _OrigUL = _st.HTTPUploader

        class _TrackedUL(_OrigUL):
            def run(self):
                with _ul_lock:
                    _ul_active.append(self)
                try:
                    super().run()
                finally:
                    with _ul_lock:
                        _ul_active.remove(self)
                        _ul_done_bytes[0] += sum(self.request.data.total)

        _st.HTTPUploader = _TrackedUL

        def _poll_ul():
            start_t = time.perf_counter()
            while not ul_done.is_set():
                time.sleep(0.1)
                with _ul_lock:
                    cur_b = _ul_done_bytes[0] + sum(sum(t.request.data.total) for t in _ul_active)
                dt = time.perf_counter() - start_t
                if dt >= 0.3 and cur_b > 0:
                    emit("upload", {"speed": round(cur_b * 8 / (dt * 1_000_000), 1),
                                    "download_mbps": dl_mbps})

        t2 = threading.Thread(target=_poll_ul, daemon=True)
        t2.start()
        ul_bps = s.upload()
        ul_done.set()
        t2.join(timeout=1)
        _st.HTTPUploader = _OrigUL

        ul_mbps = round(ul_bps / 1_000_000, 2)
        isp = (s.results.client or {}).get("isp", "")

        result = {
            "timestamp": utcnow().isoformat(),
            "download_mbps": dl_mbps,
            "upload_mbps": ul_mbps,
            "ping_ms": ping,
            "server": server,
            "isp": isp,
        }
        if not storage.valid_speedtest(result):
            print(f"[Speedtest streaming] Discarding implausible result: {result}")
            emit("error", {"message": "Speedtest returned an implausible result"})
            return None
        emit("complete", result)
        return result
    except Exception as e:
        print(f"[Speedtest streaming] Failed: {e}")
        emit("error", {"message": str(e)})
        return None


_TICK_SEC = 60  # how often the scheduler re-reads speedtest_interval_minutes


def _interval_minutes() -> int:
    try:
        return max(0, int(storage.load_settings().get("speedtest_interval_minutes", 60) or 0))
    except (TypeError, ValueError, OSError):
        return 0


def is_due(interval_sec: float, last_run: float | None, now: float) -> bool:
    """True when a periodic job with this interval (0 = disabled) should run now."""
    return interval_sec > 0 and (last_run is None or now - last_run >= interval_sec)


def _loop(stop: threading.Event):
    """Run speedtests every speedtest_interval_minutes, re-reading the setting
    each tick so changes apply without a restart (0 disables)."""
    last_run = None
    while not stop.is_set():
        try:
            if is_due(_interval_minutes() * 60, last_run, time.monotonic()):
                last_run = time.monotonic()
                result = run_once()
                if result:
                    storage.save_speedtest(result)
                    print(f"[Speedtest] ↓{result['download_mbps']} ↑{result['upload_mbps']} ping:{result['ping_ms']}ms")
        except Exception as e:
            print(f"[Speedtest] Scheduler error: {e!r}")
        stop.wait(_TICK_SEC)


def start():
    global _thread, _stop_event
    _stop_event = threading.Event()
    _thread = threading.Thread(target=_loop, args=(_stop_event,), daemon=True, name="speedtest")
    _thread.start()


def stop():
    if _stop_event:
        _stop_event.set()
