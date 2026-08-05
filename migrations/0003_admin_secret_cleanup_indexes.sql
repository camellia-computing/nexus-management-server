CREATE INDEX admin_secret_deliveries_purge_order_idx
    ON admin_secret_deliveries (
        (acknowledged_at IS NULL),
        COALESCE(acknowledged_at, expires_at),
        id
    );

CREATE INDEX admin_enrollment_tokens_state_purge_idx
    ON admin_enrollment_tokens (
        (consumed_at IS NULL),
        COALESCE(consumed_at, expires_at),
        token_hash
    );
