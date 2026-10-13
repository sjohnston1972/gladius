"""
main.py - PingPlotter entry point
"""
import uvicorn
import collector
import storage
import speedtest_runner
import digest as digest_mod

storage.init_storage()
storage.start_retention()   # purge now, then daily (retention_days setting)
collector.start_all()

# Both schedulers re-read their interval from settings every minute, so
# changing speedtest_interval_minutes / digest_interval_hours (0 = off)
# applies without a restart.
speedtest_runner.start()
digest_mod.start()

if __name__ == "__main__":
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=False)
