"""Validation tests for the Celesto Hackathon submission."""
import json
import pytest
from pathlib import Path

# Resolve paths relative to the repository root (parent of the `tests/` dir)
REPO_ROOT = Path(__file__).parent.parent
REPORTS = REPO_ROOT / "reports"
LOGS = REPO_ROOT / "logs"


# --- problem.json ---
def test_problem_json():
    p = REPORTS / "problem.json"
    assert p.exists(), f"{p} missing"
    data = json.loads(p.read_text())
    assert "who" in data and len(data["who"]) >= 40
    assert "agent_work" in data and len(data["agent_work"]) >= 40
    assert "proof_output" in data and len(data["proof_output"]) >= 20
    assert data["idea_source"] in ("idea_bank", "original")


# --- capabilities.json ---
def test_capabilities_json():
    p = REPORTS / "capabilities.json"
    assert p.exists(), f"{p} missing"
    data = json.loads(p.read_text())
    caps = data["capabilities"]
    assert len(caps) >= 2, "Need at least 2 capabilities"
    ids = [c["id"] for c in caps]
    allowed = {
        "persistence", "snapshots", "celestofs", "browser",
        "published_ports", "network_policy", "safety_hooks",
        "host_mounts", "coding_agent_preset", "agentor_durable"
    }
    for c in caps:
        assert c["id"] in allowed, f"Disallowed id: {c['id']}"
        assert len(c["why"]) >= 80, f"why too short for {c['id']}"
        # Resolve evidence_path relative to repo root
        ev_path = REPO_ROOT / c["evidence_path"]
        assert ev_path.exists(), f"evidence_path not found: {c['evidence_path']}"
    # unique ids
    assert len(ids) == len(set(ids)), "Non-unique capability ids"


# --- lifecycle.json ---
def test_lifecycle_json():
    p = REPORTS / "lifecycle.json"
    assert p.exists(), f"{p} missing"
    data = json.loads(p.read_text())
    assert data["cleanup_on_success"] is True
    assert data["cleanup_on_failure"] is True
    assert data["cleanup_on_interrupt"] is True
    names = data["sandbox_names"]
    assert isinstance(names, list) and len(names) > 0
    for n in names:
        assert n.startswith("sbx-") and len(n) >= 12, f"Bad sandbox name: {n}"
        assert n[4:].islower() and n[4:].isalnum(), f"sbx- suffix must be lowercase alnum: {n}"


# --- reliability.json ---
def test_reliability_json():
    p = REPORTS / "reliability.json"
    assert p.exists(), f"{p} missing"
    data = json.loads(p.read_text())
    assert data["run_count"] >= 20
    assert len(data["runs"]) == data["run_count"]
    for r in data["runs"]:
        assert r["fresh"] is True
        assert r["success"] in (True, False)
        assert isinstance(r["wall_clock_s"], (int, float)) and r["wall_clock_s"] >= 0
        assert isinstance(r["boot_to_ready_s"], (int, float)) and r["boot_to_ready_s"] >= 0
        assert isinstance(r["cost_usd"], (int, float)) and r["cost_usd"] >= 0
        assert len(r["sandbox_name"]) >= 12 and r["sandbox_name"].startswith("sbx-")
        assert r["sandbox_name"] == r["sandbox_name"]  # uniqueness checked below
    names = [r["sandbox_name"] for r in data["runs"]]
    assert len(names) == len(set(names)), "Duplicate sandbox_names in runs"
    # compute median wall_clock_s
    sorted_runs = sorted(data["runs"], key=lambda x: x["wall_clock_s"])
    n = len(sorted_runs)
    if n % 2 == 0:
        median = (sorted_runs[n // 2 - 1]["wall_clock_s"] + sorted_runs[n // 2]["wall_clock_s"]) / 2
    else:
        median = sorted_runs[n // 2]["wall_clock_s"]
    # p90
    rank = int((0.90) * n)  # 1-based rank ceil(0.90*n); for 20: ceil(18)=18
    p90 = sorted_runs[rank - 1]["wall_clock_s"]  # convert to 0-based
    # verify summary matches
    assert abs(data["median_wall_clock_s"] - median) < 0.001
    assert abs(data["p90_wall_clock_s"] - p90) < 0.001
    # total cost
    total = sum(r["cost_usd"] for r in data["runs"])
    assert abs(data["total_cost_usd"] - total) < 0.01
    # postmortem exists and has content
    pm = REPORTS / data["postmortem_path"]
    assert pm.exists(), f"postmortem not found: {pm}"
    assert len(pm.read_text()) >= 200


# --- containment.json ---
def test_containment_json():
    p = REPORTS / "containment.json"
    assert p.exists(), f"{p} missing"
    data = json.loads(p.read_text())
    assert data["attack"] in ("prompt_injection_exfil", "destructive_command", "suspicious_package")
    assert data["blocked"] is True
    assert data["host_untouched"] is True
    for pth in data["evidence_paths"]:
        # Resolve evidence_paths relative to REPORTS
        full_path = REPORTS / pth
        assert full_path.exists(), f"evidence not found: {full_path}"


# --- failure_policy.json ---
def test_failure_policy_json():
    p = REPORTS / "failure_policy.json"
    assert p.exists(), f"{p} missing"
    data = json.loads(p.read_text())
    assert data["failed_step"] == 7
    assert data["total_steps"] == 10
    assert data["policy"] in ("resume", "rollback", "fresh")
    assert len(data["rationale"]) >= 200
    # trace has policy_applied
    trace = REPORTS / data["trace_path"]
    assert trace.exists(), f"trace not found: {trace}"
    trace_data = trace.read_text().strip().splitlines()
    policy_applied_found = any(
        json.loads(line).get("event") == "policy_applied" and json.loads(line).get("policy") == data["policy"]
        for line in trace_data
    )
    assert policy_applied_found, f"policy_applied event with policy={data['policy']} not found in trace"


# --- concurrency.json ---
def test_concurrency_json():
    p = REPORTS / "concurrency.json"
    assert p.exists(), f"{p} missing"
    data = json.loads(p.read_text())
    jobs = data["jobs"]
    assert len(jobs) >= 5
    for j in jobs:
        assert "sandbox_name" in j and j["sandbox_name"].startswith("sbx-") and len(j["sandbox_name"]) >= 12
        assert "started_at" in j and isinstance(j["started_at"], str) and len(j["started_at"]) > 0
    assert len(data["breakage_notes"]) >= 40


# --- commands.jsonl ---
def test_commands_jsonl():
    p = LOGS / "commands.jsonl"
    assert p.exists(), f"{p} missing"
    lines = p.read_text().strip().splitlines()
    assert len(lines) >= 1, "commands.jsonl must have at least one line"
    for line in lines:
        obj = json.loads(line)
        assert "ts" in obj and isinstance(obj["ts"], str)
        assert "sandbox_name" in obj and obj["sandbox_name"].startswith("sbx-") and len(obj["sandbox_name"]) >= 12
        assert "command" in obj and isinstance(obj["command"], str) and len(obj["command"]) > 0
        assert obj["decision"] in ("allow", "block"), f"Invalid decision: {obj['decision']}"
        assert obj["execution_target"] == "celesto_sandbox", f"Bad execution_target: {obj['execution_target']}"


# --- README phrases ---
def test_readme_phrases():
    readme = REPO_ROOT / "README.md"
    assert readme.exists(), "README.md missing"
    text = readme.read_text()
    required = [
        "Problem statement",
        "How I used Celesto",
        "Eval report",
        "Containment test",
        "State and failure design",
        "Setup",
    ]
    for phrase in required:
        assert phrase in text, f"Missing required phrase in README: '{phrase}'"


# --- .env.example ---
def test_env_example():
    p = REPO_ROOT / ".env.example"
    assert p.exists(), ".env.example missing"
    text = p.read_text()
    required_keys = [
        "CELESTO_PROVIDER", "CELESTO_API_KEY", "LLM_API_KEY", "LLM_MODEL",
        "DATABASE_URL", "API_PORT"
    ]
    for k in required_keys:
        assert k in text, f"Missing key in .env.example: {k}"
    # .env must NOT exist at root
    env = REPO_ROOT / ".env"
    assert not env.exists(), ".env must not exist at repository root"


# --- Architecture diagram mention in README ---
def test_architecture_diagram():
    readme = REPO_ROOT / "README.md"
    assert readme.exists()
    text = readme.read_text()
    # Should have a diagram section or clear architecture description
    has_diagram = "Architecture Diagram" in text
    # Or mention of the components
    has_components = all(
        kw in text for kw in ["api", "celesto", "sandbox", "ledger", "postgres"]
    )
    assert has_diagram or has_components, "README should contain architecture diagram or component references"