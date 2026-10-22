-- Seed data for the run ledger
-- This runs automatically on first Postgres boot via docker-entrypoint-initdb.d

INSERT INTO runs (run_id, sandbox_name, problem_id, state, execution_target, created_at, updated_at)
VALUES (
    'seed-run-001',
    'sbx-seeddemo1',
    'supply-chain-audit',
    'deleted',
    'celesto_sandbox',
    NOW(),
    NOW()
)
ON CONFLICT (run_id) DO NOTHING;