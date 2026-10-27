-- name: job_interrupt_unfinished
UPDATE security_review_jobs SET state='interrupted',
    error='Review interrupted by app restart',
    finished_at=? WHERE state IN ('queued','running')

-- name: job_ledger
SELECT coalesce(sum(token_charge),0) AS tokens,
    coalesce(sum(cost_charge),0)/1000000.0 AS cost_usd,
    coalesce(sum(CASE WHEN token_charge>0 OR tokens IS NOT NULL THEN 1 ELSE 0 END),0) AS jobs
FROM security_review_jobs WHERE created_epoch>=?

-- name: job_latest_charged
SELECT id FROM security_review_jobs WHERE provider=? AND state<>'queued'
    AND (token_charge>0 OR tokens IS NOT NULL) ORDER BY created_epoch DESC LIMIT 1

-- name: job_recent
SELECT * FROM security_review_jobs ORDER BY created_epoch DESC LIMIT 50

-- name: job_latest
SELECT id,state,tokens,finished_at FROM security_review_jobs ORDER BY created_epoch DESC LIMIT 1

-- name: job_by_request
SELECT id,state,session_id FROM security_review_jobs WHERE request_id=?

-- name: job_insert_queued
INSERT INTO security_review_jobs
    (id,request_id,session_id,digest,detector,provider,model,created_at,created_epoch,
     state,automatic,token_charge,cost_charge,coverage)
VALUES (?,?,?,?,?,?,?,?,?,'queued',?,?,?,?)

-- name: job_insert_skipped
INSERT INTO security_review_jobs
    (id,request_id,session_id,digest,detector,provider,model,created_at,created_epoch,
     state,automatic,token_charge,cost_charge,coverage,finished_at,error)
VALUES (?,?,?,?,?,?,?,?,?,'skipped',1,0,0,?,?,?)

-- name: job_set_tokens
UPDATE security_review_jobs SET tokens=?,token_charge=max(token_charge,?) WHERE id=?

-- name: job_set_cost
UPDATE security_review_jobs SET cost_usd=?,cost_charge=max(cost_charge,?) WHERE id=?

-- name: job_set_provider_session
UPDATE security_review_jobs SET provider_session_id=? WHERE id=?

-- name: job_set_running
UPDATE security_review_jobs SET state='running' WHERE id=?

-- name: job_complete
UPDATE security_review_jobs SET state='completed',finished_at=?,report=?,tokens=?,
    token_charge=?,cost_usd=?,cost_charge=? WHERE id=?

-- name: job_fail
UPDATE security_review_jobs SET state=?,finished_at=?,error=? WHERE id=?

-- name: job_release_charge
UPDATE security_review_jobs SET token_charge=0,cost_charge=0 WHERE id=?

-- name: job_forget_evidence
UPDATE security_review_jobs SET report=NULL,coverage=?

-- name: job_review_runs
SELECT DISTINCT provider,provider_session_id FROM security_review_jobs WHERE provider_session_id<>''

-- name: job_reviewed
SELECT session_id,digest FROM security_review_jobs WHERE detector=?
