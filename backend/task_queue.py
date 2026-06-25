"""NetVision Scan Task Queue — priority-based asyncio queue, scheduling, diffing.

Replaces the fragile `global is_scanning` + `BackgroundTasks` pattern with a
proper async task manager supporting priority levels, scheduled recurring scans,
and cross-scan result diffing.

Key features:
- Priority queue: critical > high > normal > low
- Concurrent scan limit (max 1 active by default for safety)
- Scheduled recurring scans (stored in DB, checked every 30s)
- Scan result diffing (what changed since last scan on same target)
- Queue statistics and management endpoints
"""
import asyncio
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import IntEnum
from typing import Callable, Dict, List, Optional, Any

from loguru import logger

log = logger.bind(component="task_queue")


class Priority(IntEnum):
    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3


@dataclass(order=True)
class ScanTask:
    priority: Priority
    created_at: float = field(compare=False)
    target: str = field(compare=False)
    profile: str = field(compare=False, default="deep")
    duration: Optional[int] = field(compare=False, default=None)
    trace_hops: bool = field(compare=False, default=False)
    scan_id: Optional[int] = field(compare=False, default=None)
    requester: str = field(compare=False, default="system")
    profile_args: Optional[str] = field(compare=False, default=None)
    schedule_id: Optional[int] = field(compare=False, default=None)
    callback: Optional[Callable] = field(compare=False, default=None)


@dataclass
class ScanSchedule:
    """Recurring scan schedule stored in DB."""
    id: int
    target: str
    profile: str
    interval_minutes: int
    enabled: bool
    created_at: str
    last_run: Optional[str] = None
    requester: str = "system"


@dataclass
class ScanDiff:
    """Differences between two scans on the same target."""
    new_devices: List[Dict] = field(default_factory=list)
    missing_devices: List[Dict] = field(default_factory=list)
    changed_ports: List[Dict] = field(default_factory=list)
    new_vulnerabilities: List[Dict] = field(default_factory=list)
    resolved_vulnerabilities: List[Dict] = field(default_factory=list)


class ScanTaskQueue:
    """Priority-based scan queue with scheduling, concurrency enforcement, diffing."""

    def __init__(self, db_path: str):
        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._active_task: Optional[ScanTask] = None
        self._active_future: Optional[asyncio.Future] = None
        self._running = False
        self._db_path = db_path
        self._worker_task: Optional[asyncio.Task] = None
        self._scheduler_task: Optional[asyncio.Task] = None
        self._history: List[Dict] = []  # Completed task history (in-memory, max 100)
        self._on_complete: Optional[Callable] = None
        self._default_executor: Optional[Callable] = None

    # ── Public API ──────────────────────────────────────────────────────────

    def enqueue(
        self,
        target: str,
        profile: str = "deep",
        duration: Optional[int] = None,
        trace_hops: bool = False,
        priority: Priority = Priority.NORMAL,
        requester: str = "system",
        scan_id: Optional[int] = None,
        profile_args: Optional[str] = None,
        schedule_id: Optional[int] = None,
        callback: Optional[Callable] = None,
    ) -> ScanTask:
        """Add a scan task to the priority queue."""
        task = ScanTask(
            priority=priority,
            created_at=datetime.now().timestamp(),
            target=target,
            profile=profile,
            duration=duration,
            trace_hops=trace_hops,
            scan_id=scan_id,
            requester=requester,
            profile_args=profile_args,
            schedule_id=schedule_id,
            callback=callback,
        )
        # PriorityQueue orders by (priority, created_at) via dataclass order
        self._queue.put_nowait(task)
        log.info("Scan task enqueued", target=target, profile=profile, priority=priority.name)
        return task

    @property
    def is_active(self) -> bool:
        return self._active_task is not None

    @property
    def active_task(self) -> Optional[ScanTask]:
        return self._active_task

    @property
    def pending_count(self) -> int:
        return self._queue.qsize()

    def pending_tasks(self) -> List[Dict]:
        """Snapshot of pending queue (best-effort, since PriorityQueue doesn't iterate)."""
        return [
            {
                "priority": t.priority.name,
                "target": t.target,
                "profile": t.profile,
                "created_at": datetime.fromtimestamp(t.created_at).isoformat(),
                "requester": t.requester,
            }
            for t in list(self._queue._queue)
        ]

    def history(self, limit: int = 20) -> List[Dict]:
        return self._history[-limit:]

    def register_executor(self, executor: Callable):
        """Register the default scan execution function.
        Called for every task that doesn't have its own callback.
        Must be async and accept a ScanTask argument."""
        self._default_executor = executor

    def on_task_complete(self, callback: Callable):
        """Register a callback for when a scan task completes.
        Called with (task, scan_diff_or_none)."""
        self._on_complete = callback

    async def start(self):
        """Start the queue worker and scheduler loops."""
        if self._running:
            return
        self._running = True
        self._worker_task = asyncio.create_task(self._worker_loop())
        self._scheduler_task = asyncio.create_task(self._scheduler_loop())
        log.info("Scan task queue started")

    async def stop(self):
        """Gracefully stop the queue."""
        self._running = False
        if self._worker_task:
            self._worker_task.cancel()
        if self._scheduler_task:
            self._scheduler_task.cancel()
        if self._active_future and not self._active_future.done():
            self._active_future.cancel()
        log.info("Scan task queue stopped")

    # ── Scheduling ──────────────────────────────────────────────────────────

    def add_schedule(
        self,
        target: str,
        profile: str,
        interval_minutes: int,
        requester: str = "system",
    ) -> int:
        """Add a recurring scan schedule to the database."""
        conn = sqlite3.connect(self._db_path)
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO scan_schedules (target, profile, interval_minutes, requester)
               VALUES (?, ?, ?, ?)""",
            (target, profile, interval_minutes, requester),
        )
        schedule_id = cursor.lastrowid
        conn.commit()
        conn.close()
        log.info("Scan schedule added", schedule_id=schedule_id, target=target,
                 interval=interval_minutes)
        return schedule_id

    def remove_schedule(self, schedule_id: int) -> bool:
        conn = sqlite3.connect(self._db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scan_schedules WHERE id = ?", (schedule_id,))
        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()
        if deleted:
            log.info("Scan schedule removed", schedule_id=schedule_id)
        return deleted

    def toggle_schedule(self, schedule_id: int, enabled: bool) -> bool:
        conn = sqlite3.connect(self._db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE scan_schedules SET enabled = ? WHERE id = ?",
                       (1 if enabled else 0, schedule_id))
        changed = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return changed

    def get_schedules(self, enabled_only: bool = False) -> List[ScanSchedule]:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        if enabled_only:
            cursor.execute("SELECT * FROM scan_schedules WHERE enabled = 1")
        else:
            cursor.execute("SELECT * FROM scan_schedules")
        rows = cursor.fetchall()
        conn.close()
        return [
            ScanSchedule(
                id=r["id"],
                target=r["target"],
                profile=r["profile"],
                interval_minutes=r["interval_minutes"],
                enabled=bool(r["enabled"]),
                created_at=r["created_at"],
                last_run=r.get("last_run"),
                requester=r.get("requester", "system"),
            )
            for r in rows
        ]

    def _update_schedule_last_run(self, schedule_id: int):
        conn = sqlite3.connect(self._db_path)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE scan_schedules SET last_run = CURRENT_TIMESTAMP WHERE id = ?",
            (schedule_id,),
        )
        conn.commit()
        conn.close()

    # ── Scan Diffing ────────────────────────────────────────────────────────

    def compute_diff(self, task: ScanTask, current_devices: List[Dict]) -> Optional[ScanDiff]:
        """Compare current scan results against the previous scan on same target.
        Returns ScanDiff or None if no previous scan exists."""
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Find the most recent previous scan on this target
        cursor.execute(
            """SELECT id FROM scans
               WHERE target = ? AND status = 'completed'
               ORDER BY id DESC LIMIT 1 OFFSET 1""",
            (task.target,),
        )
        row = cursor.fetchone()
        if not row:
            conn.close()
            return None

        prev_scan_id = row["id"]

        # Get previous devices (IPs and port sets)
        cursor.execute(
            "SELECT ip, ports_json FROM scan_results WHERE scan_id = ?",
            (prev_scan_id,),
        )
        prev_ips: Dict[str, set] = {}
        for r in cursor.fetchall():
            ports = json.loads(r["ports_json"]) if r["ports_json"] else []
            prev_ips[r["ip"]] = set(p["port"] for p in ports if p.get("state") == "open")

        # Build current device map
        current_ips: Dict[str, set] = {}
        current_by_ip: Dict[str, Dict] = {}
        for dev in current_devices:
            ip = dev["ip"]
            ports = set(p["port"] for p in dev.get("ports", []) if p.get("state") == "open")
            current_ips[ip] = ports
            current_by_ip[ip] = dev

        diff = ScanDiff()

        # New devices
        for ip in current_ips:
            if ip not in prev_ips:
                diff.new_devices.append(current_by_ip[ip])

        # Missing devices
        for ip in prev_ips:
            if ip not in current_ips:
                diff.missing_devices.append({"ip": ip})

        # Changed ports
        for ip in current_ips & prev_ips:
            old_ports = prev_ips[ip]
            new_ports = current_ips[ip]
            added = new_ports - old_ports
            removed = old_ports - new_ports
            if added or removed:
                diff.changed_ports.append({
                    "ip": ip,
                    "added": list(added),
                    "removed": list(removed),
                })

        conn.close()

        if not any([diff.new_devices, diff.missing_devices, diff.changed_ports]):
            return None  # No meaningful changes

        return diff

    # ── Schedule Management ──────────────────────────────────────────────────

    def add_schedule(self, target: str, profile: str, interval_minutes: int,
                     requester: str = "manual") -> dict:
        """Create a recurring scan schedule."""
        conn = sqlite3.connect(self._db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO scan_schedules (target, profile, interval_minutes, enabled, requester)
            VALUES (?, ?, ?, 1, ?)
        ''', (target, profile, interval_minutes, requester))
        schedule_id = cursor.lastrowid
        conn.commit()
        conn.close()
        log.info("Schedule created", id=schedule_id, target=target, interval=interval_minutes)
        return {"schedule_id": schedule_id, "status": "created"}

    def list_schedules(self) -> list:
        """List all scan schedules."""
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scan_schedules ORDER BY created_at DESC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_schedules(self, enabled_only: bool = False) -> list:
        """Get all schedules, optionally only enabled ones."""
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        if enabled_only:
            cursor.execute("SELECT * FROM scan_schedules WHERE enabled = 1")
        else:
            cursor.execute("SELECT * FROM scan_schedules")
        rows = cursor.fetchall()
        conn.close()
        result = []
        for r in rows:
            result.append(ScanSchedule(
                id=r["id"],
                target=r["target"],
                profile=r["profile"],
                interval_minutes=r["interval_minutes"],
                enabled=r["enabled"],
                created_at=r["created_at"],
                last_run=r.get("last_run"),
                requester=r.get("requester", "system"),
            ))
        return result

    def delete_schedule(self, schedule_id: int) -> dict:
        """Delete a scan schedule."""
        conn = sqlite3.connect(self._db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scan_schedules WHERE id = ?", (schedule_id,))
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        if deleted:
            log.info("Schedule deleted", id=schedule_id)
            return {"status": "deleted", "schedule_id": schedule_id}
        return {"status": "not_found", "schedule_id": schedule_id}

    def toggle_schedule(self, schedule_id: int) -> dict:
        """Toggle a schedule between enabled/disabled."""
        conn = sqlite3.connect(self._db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT enabled FROM scan_schedules WHERE id = ?", (schedule_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return {"status": "not_found", "schedule_id": schedule_id}
        new_state = 0 if row[0] else 1
        cursor.execute("UPDATE scan_schedules SET enabled = ? WHERE id = ?", (new_state, schedule_id))
        conn.commit()
        conn.close()
        return {"status": "toggled", "schedule_id": schedule_id, "enabled": bool(new_state)}

    def _update_schedule_last_run(self, schedule_id: int):
        """Update last_run timestamp for a schedule."""
        conn = sqlite3.connect(self._db_path)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE scan_schedules SET last_run = datetime('now') WHERE id = ?",
            (schedule_id,),
        )
        conn.commit()
        conn.close()

    # ── Internal loops ──────────────────────────────────────────────────────

    async def _worker_loop(self):
        """Continuously process tasks from the queue, one at a time."""
        while self._running:
            try:
                # Wait for a task
                task: ScanTask = await self._queue.get()
                self._active_task = task
                log.info("Worker picked up task", target=task.target, profile=task.profile,
                         priority=task.priority.name)

                # Create a future we can cancel
                self._active_future = asyncio.Future()
                try:
                    # Delegate to the default executor or per-task callback
                    if task.callback:
                        result = await task.callback(task)
                    elif hasattr(self, '_default_executor') and self._default_executor:
                        result = await self._default_executor(task)
                    else:
                        log.warning("No executor registered for task — skipping")
                        result = {"status": "skipped", "reason": "no_executor"}
                except asyncio.CancelledError:
                    log.warning("Scan task cancelled", target=task.target)
                    result = {"status": "cancelled"}
                except Exception as e:
                    log.error("Scan task failed", target=task.target, error=str(e))
                    result = {"status": "failed", "error": str(e)}
                finally:
                    self._active_future.set_result(result)

                # Record in history
                self._history.append({
                    "target": task.target,
                    "profile": task.profile,
                    "priority": task.priority.name,
                    "status": result.get("status", "unknown"),
                    "completed_at": datetime.now().isoformat(),
                })
                # Keep history bounded
                if len(self._history) > 100:
                    self._history = self._history[-100:]

                # Notify completion callback
                if self._on_complete:
                    try:
                        # The task callback returns a ScanDiff dict, pass diff to _on_complete
                        diff = result if isinstance(result, ScanDiff) else None
                        if asyncio.iscoroutinefunction(self._on_complete):
                            asyncio.create_task(self._on_complete(task, diff))
                        else:
                            self._on_complete(task, diff)
                    except Exception as e:
                        log.warning("Task complete callback error", error=str(e))

                # Update schedule last_run if this came from a schedule
                if task.schedule_id:
                    self._update_schedule_last_run(task.schedule_id)

                self._active_task = None
                self._active_future = None
                self._queue.task_done()

            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error("Worker loop error", error=str(e))
                await asyncio.sleep(1)

    async def _scheduler_loop(self):
        """Check for due scheduled scans every 30 seconds."""
        while self._running:
            try:
                await asyncio.sleep(30)
                schedules = self.get_schedules(enabled_only=True)
                now = datetime.now()

                for sched in schedules:
                    # Determine if the schedule is due
                    if sched.last_run:
                        last = datetime.fromisoformat(sched.last_run.replace("Z", "+00:00")
                                                      if sched.last_run.endswith("Z")
                                                      else sched.last_run)
                        elapsed = (now - last).total_seconds() / 60
                        if elapsed < sched.interval_minutes:
                            continue
                    # Due — enqueue a scan
                    self.enqueue(
                        target=sched.target,
                        profile=sched.profile,
                        priority=Priority.NORMAL,
                        requester=sched.requester,
                        schedule_id=sched.id,
                    )
                    log.info("Scheduled scan triggered", target=sched.target,
                             schedule_id=sched.id, interval=sched.interval_minutes)

            except asyncio.CancelledError:
                break
            except Exception as e:
                log.warning("Scheduler loop error", error=str(e))
