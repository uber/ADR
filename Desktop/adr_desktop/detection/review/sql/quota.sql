-- name: quota_get
SELECT observation FROM security_review_quota WHERE provider=?

-- name: quota_put
INSERT OR REPLACE INTO security_review_quota VALUES (?,?)

-- name: quota_delete
DELETE FROM security_review_quota WHERE provider=?

-- name: quota_history_add
INSERT INTO security_review_quota_history(provider,observed_epoch,observation) VALUES (?,?,?)

-- name: quota_history_prune
DELETE FROM security_review_quota_history WHERE id NOT IN
    (SELECT id FROM security_review_quota_history ORDER BY id DESC LIMIT 2000)

-- name: quota_history
SELECT observation FROM security_review_quota_history WHERE provider=? ORDER BY id DESC LIMIT 120
