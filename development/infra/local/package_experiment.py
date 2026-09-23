#!/usr/bin/env python3
"""Install the built artifact into a clean environment and use it there.

`SAFE-PACKAGE-01` exists because everything this project has proved so far
was proved from a repository checkout with `PYTHONPATH` pointing into
`development/src`. That is not what anybody installs. A package that omits a
subpackage, ships no entry point, or silently depends on a file that only
exists in the source tree fails on a user's machine and nowhere else — and
the failure looks like a broken product rather than a broken build.

So this deliberately makes the checkout unusable: it builds a wheel, creates
a virtual environment with no access to the source tree, installs only the
wheel, and then runs from a working directory where importing the repository
is impossible. Anything that still works is genuinely in the package.

It does not test that containment works — that is the full-chain experiment's
job, and this runs on hosts that may have no kernel support. It tests that
the *artifact* is complete and honest about what it can do.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]


def _run(argv, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=600,
                          **kwargs)


def build_wheel(outdir: Path) -> Path | None:
    result = _run([sys.executable, "-m", "build", "--wheel", "--outdir",
                   str(outdir)], cwd=str(REPO))
    if result.returncode != 0:
        return None
    wheels = sorted(outdir.glob("annulon-*.whl"))
    return wheels[-1] if wheels else None


def run(keep: bool = False) -> dict:
    report: dict = {"python": sys.version.split()[0], "repo": str(REPO)}
    workspace = Path(tempfile.mkdtemp(prefix="annulon-pkg-"))
    try:
        dist = workspace / "dist"
        dist.mkdir()
        wheel = build_wheel(dist)
        report["wheel_built"] = wheel is not None
        if wheel is None:
            report["completion"] = "EVIDENCE_INCOMPLETE"
            report["reason"] = "the wheel did not build"
            return report
        report["wheel"] = wheel.name
        report["wheel_bytes"] = wheel.stat().st_size

        # A virtual environment with no system packages and no path into the
        # source tree.
        venv = workspace / "venv"
        created = _run([sys.executable, "-m", "venv", "--without-pip", str(venv)])
        if created.returncode != 0:
            created = _run([sys.executable, "-m", "venv", str(venv)])
        python = venv / "bin" / "python"
        if not python.exists():
            report["completion"] = "EVIDENCE_INCOMPLETE"
            report["reason"] = "could not create a clean environment"
            return report

        install = _run([sys.executable, "-m", "pip", "install", "--quiet",
                        "--target", str(workspace / "site"), str(wheel)])
        report["install_ok"] = install.returncode == 0
        if install.returncode != 0:
            report["install_error"] = install.stderr[-400:]
            report["completion"] = "EVIDENCE_INCOMPLETE"
            return report

        site = workspace / "site"
        # A working directory from which the repository cannot be imported,
        # and an environment with no PYTHONPATH into it.
        elsewhere = workspace / "elsewhere"
        elsewhere.mkdir()
        clean_env = {k: v for k, v in os.environ.items()
                     if k not in ("PYTHONPATH", "ANNULON_SRC")}
        clean_env["PYTHONPATH"] = str(site)

        report["checks"] = {}

        def check(name: str, code: str) -> None:
            result = _run([sys.executable, "-c", code], cwd=str(elsewhere),
                          env=clean_env)
            report["checks"][name] = {
                "ok": result.returncode == 0,
                "output": (result.stdout or result.stderr).strip()[:300]}

        check("annulon_imports",
              "import annulon, annulon.response.broker, annulon.network.tracefs;"
              "print('ok')")
        check("sdnguard_imports",
              "import sdnguard, sdnguard.v2.findings; print('ok')")
        check("no_repo_on_path",
              "import annulon, pathlib, sys;"
              "p = pathlib.Path(annulon.__file__).resolve();"
              "print('installed' if 'site' in p.parts else f'LEAKED {p}')")
        check("detector_usable",
              "from annulon.detect.egress_policy import EgressPolicyDetector,"
              " EgressAllowlist, WorkloadRule;"
              "d = EgressPolicyDetector(EgressAllowlist((WorkloadRule(uid=1,"
              " service_name='s'),)), host_id='h', boot_id='b');"
              "print(d.kind)")
        check("broker_contract_usable",
              "from annulon.response.contract import ActionType, TargetKind;"
              "print(len(list(ActionType)), len(list(TargetKind)))")
        check("capability_probe_is_honest",
              "from annulon.network.tracefs import TracefsNetworkSensor as S;"
              "print('available' if S.available() else "
              "'unavailable: ' + '; '.join(S.missing_requirements())[:120])")

        # Entry points must exist as executables, since the systemd units
        # invoke them by path rather than importing anything.
        scripts = {}
        for name in ("annulon-broker", "annulon-agent"):
            found = shutil.which(name, path=str(site / "bin")) or shutil.which(
                name, path=str(workspace / "site" / "bin"))
            scripts[name] = bool(found)
        report["entry_points_present"] = scripts

        # And they must actually run. `--check` exits without serving.
        runners = {}
        for name, module in (("annulon-broker", "annulon.cli.broker"),
                             ("annulon-agent", "annulon.cli.agent")):
            result = _run([sys.executable, "-m", module, "--check",
                           "--config", str(workspace / "absent.json")],
                          cwd=str(elsewhere), env=clean_env)
            runners[name] = {"exit": result.returncode,
                             "ran": result.returncode in (0, 1, 2),
                             "output": (result.stdout or result.stderr).strip()[:200]}
        report["entry_points_runnable"] = runners

        # Nothing in the package may reach for a repository-relative file.
        offenders = []
        for path in site.rglob("*.py"):
            text = path.read_text(errors="replace")
            for needle in ("development/src", "development/tests", "/annulon/development"):
                if needle in text:
                    offenders.append(f"{path.relative_to(site)}: {needle}")
        report["repository_paths_in_package"] = offenders[:5]

        report["completion"] = _completion(report)
        return report
    finally:
        if keep:
            print(f"workspace kept at {workspace}", file=sys.stderr)
        else:
            shutil.rmtree(workspace, ignore_errors=True)


def _completion(report: dict) -> str:
    checks = report.get("checks", {})
    required = [
        report.get("wheel_built"), report.get("install_ok"),
        checks.get("annulon_imports", {}).get("ok"),
        checks.get("sdnguard_imports", {}).get("ok"),
        checks.get("no_repo_on_path", {}).get("output", "").startswith("installed"),
        checks.get("detector_usable", {}).get("ok"),
        checks.get("broker_contract_usable", {}).get("ok"),
        checks.get("capability_probe_is_honest", {}).get("ok"),
        all(report.get("entry_points_present", {}).values()),
        all(r["ran"] for r in report.get("entry_points_runnable", {}).values()),
        not report.get("repository_paths_in_package"),
    ]
    return "COMPLETE" if all(required) else "EVIDENCE_INCOMPLETE"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    report = run(keep=args.keep)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("completion") == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
