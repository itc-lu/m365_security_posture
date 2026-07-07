"""Automation runner: executes assessment tools and scheduled imports.

Three task types, each runnable manually ("Run now") or on a per-tenant
schedule (daily / weekly / monthly):

- ``secure_score``: imports Microsoft Secure Score via the Graph API using
  the tenant's app-only credentials (certificate preferred, client secret
  otherwise). Fully non-interactive.
- ``scuba``: runs CISA ScubaGear (``Invoke-SCuBA``) via PowerShell 7 and
  imports the resulting report automatically.
- ``zero_trust``: runs the Zero Trust Assessment (``Invoke-ZTAssessment``)
  via PowerShell 7 and imports the resulting report automatically.

PowerShell-based tasks need ``pwsh`` plus the respective module installed on
the machine running this tool, and app-only credentials on the tenant so the
run works unattended (ScubaGear supports certificate auth via
``-CertificateThumbprint``/``-AppID``/``-Organization`` or a config file).

The scheduler is a daemon thread started by ``run_server``; it checks for
due schedules once a minute and never runs more than one task at a time.
"""

from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import traceback
import zipfile
from datetime import datetime
from pathlib import Path

from .database import Database
from .import_pipeline import process_file_import, import_secure_scores_with_token

TASK_TYPES = ("secure_score", "scuba", "zero_trust")

# Only one tool run at a time — the PowerShell tools are heavy and the
# import pipeline writes to the same SQLite file.
_run_lock = threading.Lock()


def find_pwsh(config: dict = None) -> str | None:
    """Locate the PowerShell executable (config override > pwsh > powershell)."""
    override = (config or {}).get("pwsh_path", "")
    if override:
        return override if os.path.isfile(override) else None
    return shutil.which("pwsh") or shutil.which("powershell")


def _acquire_app_token(tenant: dict) -> str:
    """Get an app-only Graph token for a tenant (certificate first, then
    secret), honouring the tenant's enabled auth methods."""
    from .graph_api import client_credentials_token, client_credentials_token_cert
    from .database import Database

    tenant_id = tenant.get("tenant_id", "")
    client_id = tenant.get("client_id", "")
    if not tenant_id or not client_id:
        raise RuntimeError(
            "Tenant needs tenant_id and client_id configured for unattended runs.")

    cert_path = tenant.get("certificate_path", "")
    if cert_path and Database.auth_method_enabled(tenant, "certificate"):
        result = client_credentials_token_cert(
            tenant_id, client_id, cert_path,
            tenant.get("certificate_thumbprint", ""))
        return result["access_token"]

    client_secret = tenant.get("client_secret", "")
    if client_secret and Database.auth_method_enabled(tenant, "client_secret"):
        result = client_credentials_token(tenant_id, client_id, client_secret)
        return result["access_token"]

    raise RuntimeError(
        "Tenant needs an enabled app-only auth method (certificate or client "
        "secret) for unattended runs. Configure one under Control Plane > "
        "Tenant Config.")


def run_secure_score(db: Database, tenant_name: str) -> dict:
    """Import Secure Score via Graph API using app-only credentials."""
    tenant = db.get_tenant(tenant_name)
    if not tenant:
        raise RuntimeError(f"Tenant '{tenant_name}' not found")
    token = _acquire_app_token(tenant)
    result = import_secure_scores_with_token(db, tenant_name, token)
    return {
        "summary": (f"Imported {result['total_parsed']} controls "
                    f"({result['new_actions']} new, {result['updated_actions']} updated), "
                    f"score {result['snapshot'].get('percentage', 0)}%"),
        "result": result,
    }


def _zip_directory(src_dir: str, zip_path: str):
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _dirs, files in os.walk(src_dir):
            for fn in files:
                full = os.path.join(root, fn)
                zf.write(full, os.path.relpath(full, src_dir))


def _run_powershell(pwsh: str, command: str, timeout: int = 3600) -> subprocess.CompletedProcess:
    return subprocess.run(
        [pwsh, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, timeout=timeout,
    )


def _tail(text: str, lines: int = 60) -> str:
    return "\n".join((text or "").strip().splitlines()[-lines:])


def _proc_failure_detail(label: str, proc) -> str:
    """Readable failure report: exit code plus the tail of both streams."""
    parts = [f"{label} failed (exit {proc.returncode})."]
    err = _tail(proc.stderr)
    out = _tail(proc.stdout)
    if err:
        parts.append("--- stderr (last lines) ---\n" + err)
    if out:
        parts.append("--- stdout (last lines) ---\n" + out)
    if not err and not out:
        parts.append("(no output captured)")
    return "\n".join(parts)


def _module_import_prefix(module_path: str, module_name: str) -> str:
    """PowerShell snippet importing a module from a local folder (a git
    checkout or extracted release) instead of the installed module."""
    if not module_path:
        return ""
    p = module_path.rstrip("/\\")
    # Accept either the repo root (ScubaGear checkout has PowerShell/ScubaGear
    # inside) or the module folder itself.
    candidates = [
        os.path.join(p, "PowerShell", module_name),
        os.path.join(p, module_name),
        p,
    ]
    for c in candidates:
        if (os.path.isfile(os.path.join(c, f"{module_name}.psd1"))
                or os.path.isfile(os.path.join(c, f"{module_name}.psm1"))):
            return f"Import-Module '{c}' -Force; "
    raise RuntimeError(
        f"No {module_name} module found under '{module_path}'. Point the "
        f"folder setting at the {module_name} checkout (containing "
        f"PowerShell/{module_name}) or at the module folder itself.")


def run_scuba(db: Database, tenant_name: str) -> dict:
    """Run ScubaGear with the tenant's uploaded YAML config and import the report.

    Everything about the run (products, tenant, auth, environment) comes from
    the ScubaGear config file; only -OutPath is overridden so the results can
    be collected and imported.
    """
    tenant = db.get_tenant(tenant_name)
    if not tenant:
        raise RuntimeError(f"Tenant '{tenant_name}' not found")
    cfg = db.get_tool_config(tenant_name, "scuba")
    ps_cfg = db.get_tool_config(tenant_name, "powershell")
    pwsh = find_pwsh(ps_cfg)
    if not pwsh:
        raise RuntimeError(
            "PowerShell not found. Install PowerShell 7 (pwsh), or set the "
            "PowerShell path in the tool configuration.")

    config_yaml = (cfg.get("config_yaml") or "").strip()
    if not config_yaml:
        raise RuntimeError(
            "No ScubaGear config file uploaded. Upload a YAML config on the "
            "Automation page — it defines products, organization, auth "
            "(certificate/app for unattended runs) and all other options.")

    import_prefix = _module_import_prefix(
        (cfg.get("scubagear_path") or "").strip(), "ScubaGear")

    out_dir = tempfile.mkdtemp(prefix="scuba_run_")
    try:
        cfg_file = os.path.join(out_dir, "scuba_config.yaml")
        with open(cfg_file, "w") as f:
            f.write(config_yaml)
        # Command-line parameters override config-file values in ScubaGear,
        # so -OutPath reliably lands the report where we can pick it up.
        cmd = (f"{import_prefix}Invoke-SCuBA -ConfigFilePath '{cfg_file}' "
               f"-OutPath '{out_dir}' -Quiet $true")

        proc = _run_powershell(pwsh, f"$ErrorActionPreference='Stop'; {cmd}",
                               timeout=int(cfg.get("timeout", 3600)))
        if proc.returncode != 0:
            raise RuntimeError(_proc_failure_detail("Invoke-SCuBA", proc))

        # ScubaGear writes a M365BaselineConformance_* directory below OutPath
        report_dirs = sorted(glob.glob(os.path.join(out_dir, "M365BaselineConformance*")))
        report_dir = report_dirs[-1] if report_dirs else out_dir
        results = glob.glob(os.path.join(report_dir, "ScubaResults*.json"))
        if not results:
            raise RuntimeError(
                "ScubaGear finished but no ScubaResults*.json was produced.\n"
                "--- stdout (last lines) ---\n" + _tail(proc.stdout))

        zip_path = os.path.join(out_dir, "scuba_report.zip")
        _zip_directory(report_dir, zip_path)
        result = process_file_import(
            db, tenant_name, "scuba", zip_path,
            f"scheduled_scuba_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.zip")
        return {
            "summary": (f"ScubaGear run imported: {result['total_parsed']} controls "
                        f"({result['new_actions']} new, {result['updated_actions']} updated)"),
            "result": result,
            "report_id": result.get("scuba_report_id", ""),
        }
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


def run_zero_trust(db: Database, tenant_name: str) -> dict:
    """Run the Zero Trust Assessment and import the resulting report."""
    tenant = db.get_tenant(tenant_name)
    if not tenant:
        raise RuntimeError(f"Tenant '{tenant_name}' not found")
    cfg = db.get_tool_config(tenant_name, "zero_trust")
    ps_cfg = db.get_tool_config(tenant_name, "powershell")
    pwsh = find_pwsh(ps_cfg)
    if not pwsh:
        raise RuntimeError(
            "PowerShell not found. Install PowerShell 7 (pwsh) and the "
            "ZeroTrustAssessment module, or set the PowerShell path in the "
            "tool configuration.")

    import_prefix = _module_import_prefix(
        (cfg.get("module_path") or "").strip(), "ZeroTrustAssessment")

    out_dir = tempfile.mkdtemp(prefix="zt_run_")
    try:
        cmd = f"{import_prefix}Invoke-ZTAssessment -Path '{out_dir}'"
        extra = cfg.get("extra_args", "").strip()
        if extra:
            cmd += " " + extra
        proc = _run_powershell(pwsh, f"$ErrorActionPreference='Stop'; {cmd}",
                               timeout=int(cfg.get("timeout", 3600)))
        if proc.returncode != 0:
            raise RuntimeError(_proc_failure_detail("Invoke-ZTAssessment", proc))

        reports = glob.glob(os.path.join(out_dir, "**", "ZeroTrustAssessmentReport*.json"),
                            recursive=True)
        htmls = glob.glob(os.path.join(out_dir, "**", "ZeroTrustAssessmentReport*.html"),
                          recursive=True)
        if not reports and not htmls:
            raise RuntimeError(
                "Zero Trust Assessment finished but produced no report files.\n"
                "--- stdout (last lines) ---\n" + _tail(proc.stdout))

        zip_path = os.path.join(tempfile.gettempdir(),
                                f"zt_report_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.zip")
        _zip_directory(out_dir, zip_path)
        try:
            result = process_file_import(
                db, tenant_name, "zero-trust-report", zip_path,
                f"scheduled_zt_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.zip")
        finally:
            os.unlink(zip_path)
        return {
            "summary": (f"Zero Trust run imported: {result['total_parsed']} tests "
                        f"({result['new_actions']} new, {result['updated_actions']} updated)"),
            "result": result,
            "report_id": result.get("zt_report_id", ""),
        }
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


_TASK_RUNNERS = {
    "secure_score": run_secure_score,
    "scuba": run_scuba,
    "zero_trust": run_zero_trust,
}


def execute_task(db: Database, tenant_name: str, task_type: str,
                 trigger: str = "manual") -> int:
    """Execute a task synchronously, recording a tool_runs row.

    Returns the run id. Errors are captured in the run record, not raised.
    """
    if task_type not in _TASK_RUNNERS:
        raise ValueError(f"Unknown task type: {task_type}")
    run_id = db.start_tool_run(tenant_name, task_type, trigger)
    with _run_lock:
        try:
            outcome = _TASK_RUNNERS[task_type](db, tenant_name)
            db.finish_tool_run(run_id, "success", outcome.get("summary", ""),
                               outcome.get("report_id", ""))
            status = "success"
        except Exception as e:
            db.finish_tool_run(run_id, "error", str(e))
            status = "error"
        if trigger == "schedule":
            db.mark_schedule_run(tenant_name, task_type, status)
    return run_id


def execute_task_async(db_path: str, tenant_name: str, task_type: str,
                       trigger: str = "manual") -> int:
    """Start a task in a background thread. Returns the run id immediately."""
    db = Database(db_path)
    if task_type not in _TASK_RUNNERS:
        raise ValueError(f"Unknown task type: {task_type}")
    run_id = db.start_tool_run(tenant_name, task_type, trigger)

    def _work():
        worker_db = Database(db_path)
        with _run_lock:
            try:
                outcome = _TASK_RUNNERS[task_type](worker_db, tenant_name)
                worker_db.finish_tool_run(run_id, "success", outcome.get("summary", ""),
                                          outcome.get("report_id", ""))
            except Exception as e:
                worker_db.finish_tool_run(run_id, "error", str(e))

    threading.Thread(target=_work, daemon=True).start()
    return run_id


# ── Scheduler ──

_scheduler_started = False
_scheduler_lock = threading.Lock()


def start_scheduler(db_path: str, poll_seconds: int = 60):
    """Start the background schedule checker (idempotent)."""
    global _scheduler_started
    with _scheduler_lock:
        if _scheduler_started:
            return
        _scheduler_started = True

    def _loop():
        # Mark any runs left 'running' by a previous process as aborted.
        try:
            db = Database(db_path)
            with db._conn() as conn:
                conn.execute(
                    """UPDATE tool_runs SET status='error', finished_at=?,
                              detail='Aborted: application restarted during run'
                        WHERE status='running'""",
                    (datetime.utcnow().isoformat(),),
                )
        except Exception:
            traceback.print_exc()

        while True:
            try:
                db = Database(db_path)
                for sched in db.get_due_schedules():
                    execute_task(db, sched["tenant_name"], sched["task_type"],
                                 trigger="schedule")
            except Exception:
                traceback.print_exc()
            time.sleep(poll_seconds)

    threading.Thread(target=_loop, daemon=True, name="posture-scheduler").start()
    print("[INFO] Automation scheduler started (checks every "
          f"{poll_seconds}s).", flush=True)
