-- Signer instances registry for hashring-based NIP-46 event distribution
CREATE TABLE signer_instances (
    instance_id UUID PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_heartbeat TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_signer_instances_heartbeat ON signer_instances(last_heartbeat);
