-- name: schema
CREATE TABLE IF NOT EXISTS security_review_jobs(
    id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, session_id TEXT NOT NULL,
    digest TEXT NOT NULL, detector TEXT NOT NULL, provider TEXT NOT NULL, model TEXT NOT NULL,
    created_at TEXT NOT NULL, created_epoch REAL NOT NULL, finished_at TEXT,
    state TEXT NOT NULL, automatic INTEGER NOT NULL, token_charge INTEGER NOT NULL,
    cost_charge INTEGER NOT NULL, tokens INTEGER, cost_usd REAL, error TEXT,
    coverage TEXT NOT NULL, report TEXT, provider_session_id TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS review_recent ON security_review_jobs(created_epoch DESC);
CREATE INDEX IF NOT EXISTS review_snapshot ON security_review_jobs(session_id,digest,detector);
CREATE TABLE IF NOT EXISTS security_review_quota(
    provider TEXT PRIMARY KEY, observation TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS security_review_quota_history(
    id INTEGER PRIMARY KEY AUTOINCREMENT, provider TEXT NOT NULL,
    observed_epoch REAL NOT NULL, observation TEXT NOT NULL
);
