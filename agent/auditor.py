#!/usr/bin/env python3
"""
Supply-Chain Security Auditor Agent
Runs npm package install in Celesto sandboxes with network isolation,
snapshots, and safety hooks to detect malicious behavior.
"""

import os
import json
import time
import uuid
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from contextlib import contextmanager

try:
    from celesto import Computer, Celesto
except ImportError:
    Computer = None
    Celesto = None

import httpx

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

API_URL = os.getenv("API_URL", "http://localhost:8080")
PROBLEM_ID = "supply-chain-audit"


@dataclass
class AuditResult:
    package_name: str
    package_version: str
    success: bool
    risk_level: str  # "none", "low", "medium", "high", "critical"
    findings: List[str]
    file_changes: List[Dict[str, Any]]
    blocked_commands: List[str]
    network_attempts: List[str]
    error: Optional[str] = None
    wall_clock_s: float = 0.0
    boot_to_ready_s: float = 0.0
    cost_usd: float = 0.0


@dataclass
class CommandLogEntry:
    ts: str
    sandbox_name: str
    command: str
    decision: str
    execution_target: str = "celesto_sandbox"


class SafetyHooks:
    """Safety hooks that intercept commands before execution."""

    DESTRUCTIVE_PATTERNS = [
        r"rm\s+-rf\s+/",
        r"rm\s+-rf\s+~",
        r"dd\s+if=.*of=/dev/",
        r":\(\)\{\s*:\|:&\s*\};:",
        r"chmod\s+-R\s+777\s+/",
        r"chown\s+-R\s+.*\s+/",
        r"mkfs\.",
        r"fdisk",
        r">\s*/dev/sd",
    ]

    EXFILTRATION_PATTERNS = [
        r"curl.*\$\(.*\)",
        r"wget.*\$\(.*\)",
        r"nc\s+.*\d+\.\d+\.\d+\.\d+",
        r"netcat\s+.*\d+\.\d+\.\d+\.\d+",
        r"bash\s+-i\s*>&\s*/dev/tcp/",
        r"python.*socket.*connect",
        r"env\s+\|\s*curl",
        r"cat\s+.*\.env\s+\|\s*curl",
        r"cat\s+.*id_rsa\s+\|\s*curl",
    ]

    def __init__(self, log_callback=None):
        self.log_callback = log_callback
        self.blocked_commands = []
        self.network_attempts = []

    def pre_command(self, command: str, sandbox_name: str) -> tuple[bool, Optional[str]]:
        """Returns (allow, block_reason)."""
        import re

        # Check destructive patterns
        for pattern in self.DESTRUCTIVE_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                reason = f"Destructive command blocked: matches pattern '{pattern}'"
                self._log(sandbox_name, command, "block", reason)
                return False, reason

        # Check exfiltration patterns
        for pattern in self.EXFILTRATION_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                reason = f"Exfiltration attempt blocked: matches pattern '{pattern}'"
                self.network_attempts.append(command)
                self._log(sandbox_name, command, "block", reason)
                return False, reason

        self._log(sandbox_name, command, "allow", "Command allowed")
        return True, None

    def _log(self, sandbox_name: str, command: str, decision: str, reason: str):
        entry = CommandLogEntry(
            ts=datetime.utcnow().isoformat() + "Z",
            sandbox_name=sandbox_name,
            command=command,
            decision=decision,
            execution_target="celesto_sandbox"
        )
        if self.log_callback:
            self.log_callback(entry)
        logger.info(f"[{decision.upper()}] {sandbox_name}: {command} ({reason})")


class SupplyChainAuditor:
    def __init__(
        self,
        provider: str = "local",
        api_key: Optional[str] = None,
        network_mode: str = "off",
        enable_snapshots: bool = True,
        enable_safety_hooks: bool = True,
    ):
        self.provider = provider
        self.api_key = api_key
        self.network_mode = network_mode
        self.enable_snapshots = enable_snapshots
        self.enable_safety_hooks = enable_safety_hooks
        self.safety_hooks = SafetyHooks(log_callback=self._log_command) if enable_safety_hooks else None
        self.command_log: List[CommandLogEntry] = []
        self.sandbox_name = None
        self.computer = None

    def _log_command(self, entry: CommandLogEntry):
        self.command_log.append(entry)

    def _get_sandbox_name(self) -> str:
        return f"sbx-audit-{uuid.uuid4().hex[:10]}"

    @contextmanager
    def sandbox(self):
        """Context manager for sandbox lifecycle with guaranteed cleanup."""
        self.sandbox_name = self._get_sandbox_name()
        boot_start = time.time()

        try:
            if self.provider == "cloud":
                self.computer = Computer(provider="cloud", api_key=self.api_key)
            else:
                self.computer = Computer(provider="local")

            self.computer.__enter__()
            boot_to_ready = time.time() - boot_start

            # Configure network policy
            if hasattr(self.computer, "set_network_policy"):
                self.computer.set_network_policy(mode=self.network_mode)

            # Apply safety hooks if supported
            if self.enable_safety_hooks and hasattr(self.computer, "set_pre_command_hook"):
                self.computer.set_pre_command_hook(self._pre_command_hook)

            yield self.computer, boot_to_ready

        except Exception as e:
            logger.error(f"Sandbox error: {e}")
            raise
        finally:
            self._cleanup()

    def _pre_command_hook(self, command: str) -> bool:
        """Called by Celesto before command execution. Return False to block."""
        if self.safety_hooks and self.sandbox_name:
            allowed, reason = self.safety_hooks.pre_command(command, self.sandbox_name)
            if not allowed:
                raise PermissionError(f"Command blocked by safety hook: {reason}")
        return True

    def _cleanup(self):
        """Guaranteed cleanup on success, failure, or interrupt."""
        if self.computer:
            try:
                self.computer.__exit__(None, None, None)
                logger.info(f"Cleaned up sandbox: {self.sandbox_name}")
            except Exception as e:
                logger.error(f"Cleanup error: {e}")

    def _run_with_hooks(self, command: str) -> Any:
        """Run command with safety hook checking."""
        if self.safety_hooks and self.sandbox_name:
            allowed, reason = self.safety_hooks.pre_command(command, self.sandbox_name)
            if not allowed:
                raise PermissionError(f"Command blocked: {reason}")

        result = self.computer.run(command)
        return result

    def audit_package(self, package_name: str, version: str = "latest") -> AuditResult:
        """Audit a single npm package."""
        start_time = time.time()
        sandbox_name = self.sandbox_name or self._get_sandbox_name()
        findings = []
        file_changes = []
        blocked_commands = []
        network_attempts = []

        try:
            with self.sandbox() as (computer, boot_to_ready):
                self.computer = computer

                # Step 1: Create working directory
                self._run_with_hooks("mkdir -p /workspace/audit && cd /workspace/audit")

                # Step 2: Snapshot clean state
                snapshot_id = None
                if self.enable_snapshots and hasattr(computer, "snapshot"):
                    snapshot_id = f"pre-audit-{uuid.uuid4().hex[:8]}"
                    computer.snapshot(snapshot_id=snapshot_id, resume_source=True)
                    findings.append(f"Created snapshot: {snapshot_id}")

                # Step 3: Get package tarball info
                result = self._run_with_hooks(f"npm pack {package_name}@{version} --dry-run 2>&1 | head -20")
                if result.exit_code != 0:
                    # Try fetching tarball directly
                    result = self._run_with_hooks(f"npm view {package_name}@{version} dist.tarball 2>&1")
                    if result.exit_code != 0:
                        return AuditResult(
                            package_name=package_name,
                            package_version=version,
                            success=False,
                            risk_level="unknown",
                            findings=[f"Failed to resolve package: {result.stderr}"],
                            file_changes=[],
                            blocked_commands=self.safety_hooks.blocked_commands if self.safety_hooks else [],
                            network_attempts=self.safety_hooks.network_attempts if self.safety_hooks else [],
                            error=result.stderr,
                            wall_clock_s=time.time() - start_time,
                            boot_to_ready_s=boot_to_ready,
                            cost_usd=0.001
                        )

                # Step 4: Install package in isolated directory
                result = self._run_with_hooks(f"cd /workspace/audit && npm install {package_name}@{version} --ignore-scripts=false 2>&1")

                # Step 5: Capture filesystem changes
                result = self._run_with_hooks("find /workspace/audit -type f -name '*' 2>/dev/null | head -100")
                if result.exit_code == 0:
                    files = result.stdout.strip().split('\n')
                    for f in files:
                        if f:
                            stat = self._run_with_hooks(f"stat -c '%n %s %Y' '{f}' 2>/dev/null")
                            if stat.exit_code == 0:
                                file_changes.append({"path": f, "stat": stat.stdout.strip()})

                # Step 6: Check for suspicious files
                suspicious_patterns = [
                    ("preinstall", "preinstall script"),
                    ("postinstall", "postinstall script"),
                    ("install", "install script"),
                    ("eval", "eval usage"),
                    ("child_process", "child_process usage"),
                    ("execSync", "execSync usage"),
                    ("spawn", "spawn usage"),
                    ("require('net')", "net module"),
                    ("require('http')", "http module"),
                    ("require('https')", "https module"),
                    ("fs.writeFileSync", "file write"),
                    ("fs.unlinkSync", "file delete"),
                    ("process.env", "env access"),
                ]

                result = self._run_with_hooks("grep -r 'preinstall\\|postinstall\\|eval\\|child_process\\|execSync\\|spawn\\|require.*net\\|require.*http\\|fs.writeFileSync\\|fs.unlinkSync\\|process.env' /workspace/audit/node_modules 2>/dev/null | head -20")
                if result.exit_code == 0 and result.stdout.strip():
                    for line in result.stdout.strip().split('\n'):
                        findings.append(f"Suspicious code: {line[:200]}")

                # Step 7: Check for files outside node_modules
                result = self._run_with_hooks("find /workspace -type f ! -path '*/node_modules/*' ! -path '*/.npm/*' 2>/dev/null | head -20")
                if result.exit_code == 0 and result.stdout.strip():
                    for line in result.stdout.strip().split('\n'):
                        if line:
                            findings.append(f"File outside node_modules: {line}")
                            file_changes.append({"path": line, "type": "outside_node_modules"})

                # Step 8: Determine risk level
                risk_level = self._assess_risk(findings, blocked_commands, network_attempts)

                # Step 9: Rollback if snapshot enabled and risky
                if self.enable_snapshots and snapshot_id and risk_level in ["high", "critical"] and hasattr(computer, "restore_snapshot"):
                    try:
                        computer.restore_snapshot(snapshot_id)
                        findings.append(f"Rolled back to snapshot: {snapshot_id}")
                    except Exception as e:
                        logger.warning(f"Rollback failed: {e}")

                wall_clock = time.time() - start_time

                # Estimate cost (Micro: $0.015/hr)
                cost_usd = (wall_clock / 3600) * 0.015

                return AuditResult(
                    package_name=package_name,
                    package_version=version,
                    success=True,
                    risk_level=risk_level,
                    findings=findings,
                    file_changes=file_changes,
                    blocked_commands=self.safety_hooks.blocked_commands if self.safety_hooks else [],
                    network_attempts=self.safety_hooks.network_attempts if self.safety_hooks else [],
                    wall_clock_s=wall_clock,
                    boot_to_ready_s=boot_to_ready,
                    cost_usd=cost_usd
                )

        except Exception as e:
            wall_clock = time.time() - start_time
            return AuditResult(
                package_name=package_name,
                package_version=version,
                success=False,
                risk_level="error",
                findings=[f"Error: {str(e)}"],
                file_changes=[],
                blocked_commands=self.safety_hooks.blocked_commands if self.safety_hooks else [],
                network_attempts=self.safety_hooks.network_attempts if self.safety_hooks else [],
                error=str(e),
                wall_clock_s=wall_clock,
                boot_to_ready_s=0.0,
                cost_usd=0.0
            )

    def _assess_risk(self, findings: List[str], blocked: List[str], network: List[str]) -> str:
        if network:
            return "critical"
        if blocked:
            return "high"
        suspicious_count = sum(1 for f in findings if "Suspicious code" in f or "outside_node_modules" in f)
        if suspicious_count >= 3:
            return "high"
        elif suspicious_count >= 1:
            return "medium"
        return "low"

    def log_run_to_ledger(self, run_id: str, sandbox_name: str, state: str):
        """Log run state to the control plane API."""
        try:
            httpx.post(
                f"{API_URL}/api/runs",
                json={
                    "run_id": run_id,
                    "sandbox_name": sandbox_name,
                    "problem_id": PROBLEM_ID,
                    "state": state,
                    "execution_target": "celesto_sandbox"
                },
                timeout=10
            )
        except Exception as e:
            logger.warning(f"Failed to log run to ledger: {e}")


def run_audit_batch(packages: List[tuple[str, str]], output_dir: Path) -> List[AuditResult]:
    """Run audits on multiple packages."""
    auditor = SupplyChainAuditor(
        provider=os.getenv("CELESTO_PROVIDER", "local"),
        api_key=os.getenv("CELESTO_API_KEY"),
        network_mode=os.getenv("SANDBOX_NETWORK_MODE", "off"),
        enable_snapshots=os.getenv("SNAPSHOT_ENABLED", "true").lower() == "true",
        enable_safety_hooks=os.getenv("SAFETY_HOOKS_ENABLED", "true").lower() == "true",
    )

    results = []
    for i, (pkg, ver) in enumerate(packages):
        run_id = f"audit-{uuid.uuid4().hex[:12]}"
        auditor.log_run_to_ledger(run_id, auditor.sandbox_name or "", "created")

        logger.info(f"[{i+1}/{len(packages)}] Auditing {pkg}@{ver}")
        result = auditor.audit_package(pkg, ver)
        results.append(result)

        # Log command audit trail
        for entry in auditor.command_log:
            log_line = json.dumps(asdict(entry))
            with open(output_dir / "commands.jsonl", "a") as f:
                f.write(log_line + "\n")

        auditor.log_run_to_ledger(run_id, auditor.sandbox_name or "", "succeeded" if result.success else "failed")

    return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Supply-Chain Security Auditor")
    parser.add_argument("packages", nargs="+", help="Packages to audit (name@version or name)")
    parser.add_argument("--output", default="./reports", help="Output directory")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    packages = []
    for p in args.packages:
        if "@" in p:
            name, version = p.split("@", 1)
        else:
            name, version = p, "latest"
        packages.append((name, version))

    results = run_audit_batch(packages, output_dir)

    # Save results
    with open(output_dir / "audit_results.json", "w") as f:
        json.dump([asdict(r) for r in results], f, indent=2)

    print(f"\nAudited {len(results)} packages. Results in {output_dir}/audit_results.json")
    for r in results:
        print(f"  {r.package_name}@{r.package_version}: {r.risk_level.upper()} ({'OK' if r.success else 'FAIL'})")