"""Cross-project integration coverage for the Promeo CI telemetry bridge.

This test deliberately exercises the production boundary instead of mocking
the sender or the monitor:

    Promeo PowerShell helper -> runner-observability CLI -> loopback HTTP ->
    monitor Store(SQLite) -> history/dashboard APIs

It is Windows-only because the Promeo bridge is a PowerShell script. The
Promeo checkout can be supplied with ``PROMEO_ROOT``; the default is the
Desktop sibling layout used by the local development workspace.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from threading import Thread
from typing import Iterator
import unittest
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from runner_observability.server import create_server
from runner_observability.store import Store


TOKEN = "cross-project-integration-token"
REPOSITORY = "example/runner-observability"
WORKFLOW_RUN_ID = 987654321
RUN_ATTEMPT = 1


def _default_promeo_root() -> Path:
    return Path(__file__).resolve().parents[2] / "promeo-pc-promeo"


def _promeo_root() -> Path:
    configured = os.environ.get("PROMEO_ROOT")
    return Path(configured) if configured else _default_promeo_root()


def _helper_path() -> Path:
    return _promeo_root() / "promeo_trunk" / "scripts" / "pr_validation" / "Telemetry-Helpers.ps1"


def _copy_agent_release(source_root: Path, install_root: Path) -> None:
    release_root = install_root / "releases" / "integration-test"
    shutil.copytree(source_root / "src", release_root / "src")
    (install_root / "current-release.txt").write_text("integration-test\n", encoding="ascii")


def _write_helper_script(path: Path) -> None:
    path.write_text(
        """
. $env:TELEMETRY_HELPER
$identity = New-JobIdentity -JobName 'Cross-project integration job'
$results = @(
    [bool](Send-JobStartedEvent -JobIdentity $identity)
    [bool](Send-JobHeartbeatEvent -JobIdentity $identity)
    [bool](Send-JobProgressEvent -JobIdentity $identity `
        -StageId 'selective_test' -StageKind 'selective_test' -State 'completed' `
        -Determinate $true -Total 3 -Completed 3 -Failed 0 -Pending 0 `
        -FallbackGroupCount 0 -AffectedTestCount 0 -Attempt 1)
    [bool](Send-JobFinishedEvent -JobIdentity $identity -Outcome 'succeeded')
)
Write-Output ('RESULTS=' + (($results | ForEach-Object { [string]$_ }) -join ','))

$expectedFailure = $env:EXPECT_TELEMETRY_FAILURE -eq '1'
$hasFailure = $results -contains $false
if ($expectedFailure -and -not $hasFailure) { exit 21 }
if (-not $expectedFailure -and $hasFailure) { exit 20 }
exit 0
""".lstrip(),
        encoding="utf-8-sig",
    )


def _json_get(endpoint: str) -> object:
    with urlopen(Request(endpoint, method="GET"), timeout=3) as response:
        return json.loads(response.read().decode("utf-8"))


@contextmanager
def _running_monitor() -> Iterator[tuple[str, Store]]:
    with tempfile.TemporaryDirectory(prefix="runner-observability-cross-project-") as temporary:
        database = Path(temporary) / "monitor.sqlite"
        store = Store(str(database))
        server = create_server(
            store,
            TOKEN,
            host="127.0.0.1",
            port=0,
            clock=lambda: datetime(2026, 9, 19, 12, 0, tzinfo=timezone.utc),
        )
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address
        try:
            yield f"http://{host}:{port}", store
        finally:
            server.shutdown()
            thread.join(timeout=3)
            server.server_close()
            store.close()


@unittest.skipUnless(
    sys.platform == "win32" and shutil.which("powershell.exe"),
    "Promeo CI integration requires Windows PowerShell",
)
class PromeoCiIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.promeo_root = _promeo_root()
        self.helper = _helper_path()
        if not self.helper.is_file():
            self.skipTest(f"Promeo helper not found: {self.helper}")

    def _run_helper(
        self, endpoint: str, token: str, temporary: Path, expect_failure: bool
    ) -> subprocess.CompletedProcess[str]:
        install_root = temporary / ("install-failure" if expect_failure else "install-success")
        install_root.mkdir()
        _copy_agent_release(Path(__file__).resolve().parents[1], install_root)

        token_path = temporary / ("wrong-token.txt" if expect_failure else "token.txt")
        token_path.write_text(token, encoding="ascii")
        script_path = temporary / ("send-failure.ps1" if expect_failure else "send-success.ps1")
        _write_helper_script(script_path)

        environment = os.environ.copy()
        environment.update(
            {
                "TELEMETRY_HELPER": str(self.helper),
                "RUNNER_OBSERVABILITY_INSTALL_ROOT": str(install_root),
                "RUNNER_OBSERVABILITY_ENDPOINT": f"{endpoint}/v1/events",
                "RUNNER_OBSERVABILITY_TOKEN_PATH": str(token_path),
                "GITHUB_REPOSITORY": REPOSITORY,
                "GITHUB_RUN_ID": str(WORKFLOW_RUN_ID),
                "GITHUB_RUN_ATTEMPT": str(RUN_ATTEMPT),
                "GITHUB_JOB": "cross-project-integration",
                "GITHUB_SERVER_URL": "https://github.com",
                "EXPECT_TELEMETRY_FAILURE": "1" if expect_failure else "0",
            }
        )
        return subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script_path),
            ],
            cwd=self.promeo_root,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def test_real_promeo_events_reach_monitor_and_dashboard(self) -> None:
        with tempfile.TemporaryDirectory(prefix="promeo-ci-integration-") as temporary_name:
            with _running_monitor() as (endpoint, _store):
                result = self._run_helper(
                    endpoint, TOKEN, Path(temporary_name), expect_failure=False
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("RESULTS=True,True,True,True", result.stdout)

                query = urlencode({"workflow_run_id": str(WORKFLOW_RUN_ID)})
                history = _json_get(f"{endpoint}/api/history?{query}")
                self.assertIsInstance(history, dict)
                events = history["events"]
                self.assertEqual(
                    [event["event_type"] for event in events],
                    ["job.finished", "job.progress", "job.heartbeat", "job.started"],
                )
                self.assertTrue(
                    all(event["payload"]["job"]["repository"] == REPOSITORY for event in events)
                )
                self.assertEqual(events[0]["payload"]["outcome"], "succeeded")

                dashboard = _json_get(f"{endpoint}/api/dashboard")
                self.assertFalse(dashboard["health"]["degraded"])
                self.assertEqual(len(dashboard["runners"]), 1)
                self.assertEqual(len(dashboard["active_runners"]), 1)
                current_job = dashboard["runners"][0]["current_job"]
                self.assertEqual(current_job["workflow_run_id"], WORKFLOW_RUN_ID)
                self.assertEqual(current_job["outcome"], "succeeded")
                self.assertEqual(current_job["phases"]["selective_test"]["completed"], 3)

                health = _json_get(f"{endpoint}/api/health")
                self.assertEqual(health, {"degraded": False, "reasons": []})

    def test_wrong_token_is_reported_as_helper_failure_even_when_cli_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory(prefix="promeo-ci-integration-failure-") as temporary_name:
            with _running_monitor() as (endpoint, store):
                result = self._run_helper(
                    endpoint, "wrong-token", Path(temporary_name), expect_failure=True
                )
                combined_output = result.stdout + result.stderr

                self.assertEqual(result.returncode, 0, combined_output)
                self.assertIn("RESULTS=False,False,False,False", result.stdout)
                self.assertIn(
                    "[WARN] telemetry: agent_delivery_failed reason=rejected_http_response",
                    combined_output,
                )
                self.assertNotIn("telemetry_delivery_failed reason=", combined_output)
                self.assertEqual(store.history(), [])


if __name__ == "__main__":
    unittest.main()
