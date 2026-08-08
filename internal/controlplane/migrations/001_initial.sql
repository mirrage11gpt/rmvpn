CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    telegram_subject text UNIQUE NOT NULL,
    display_name text NOT NULL,
    username text,
    avatar_url text,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','blocked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz
);
CREATE TABLE IF NOT EXISTS user_roles (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('owner','operator','support','auditor')),
    PRIMARY KEY (user_id, role)
);
CREATE TABLE IF NOT EXISTS auth_sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash bytea UNIQUE NOT NULL,
    ip inet,
    user_agent text,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE INDEX IF NOT EXISTS auth_sessions_retention_idx ON auth_sessions(created_at);
CREATE TABLE IF NOT EXISTS admin_totp (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_ciphertext bytea NOT NULL,
    enabled boolean NOT NULL DEFAULT false,
    verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS plans (
    code text PRIMARY KEY,
    name text NOT NULL,
    price_kopecks bigint NOT NULL CHECK (price_kopecks >= 0),
    period_seconds bigint NOT NULL,
    device_limit integer NOT NULL CHECK (device_limit > 0),
    quota_bytes bigint NOT NULL,
    speed_bps bigint NOT NULL,
    throttle_bps bigint NOT NULL,
    p2p_allowed boolean NOT NULL
);
INSERT INTO plans VALUES
 ('TRIAL','Trial',0,259200,1,20000000000,30000000,0,false),
 ('LITE','Lite',14900,2592000,1,150000000000,50000000,5000000,false),
 ('PLUS','Plus',29900,2592000,3,600000000000,200000000,10000000,true),
 ('ULTRA','Ultra',49900,2592000,7,2000000000000,0,20000000,true)
ON CONFLICT (code) DO UPDATE SET name=excluded.name, price_kopecks=excluded.price_kopecks,
 period_seconds=excluded.period_seconds, device_limit=excluded.device_limit, quota_bytes=excluded.quota_bytes,
 speed_bps=excluded.speed_bps, throttle_bps=excluded.throttle_bps, p2p_allowed=excluded.p2p_allowed;

CREATE TABLE IF NOT EXISTS wallets (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE RESTRICT,
    balance_kopecks bigint NOT NULL DEFAULT 0 CHECK (balance_kopecks >= 0),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ledger_entries (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    amount_kopecks bigint NOT NULL CHECK (amount_kopecks <> 0),
    balance_after_kopecks bigint NOT NULL CHECK (balance_after_kopecks >= 0),
    reason text NOT NULL CHECK (length(reason) >= 3),
    actor_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    idempotency_key text UNIQUE NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS subscriptions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    plan_code text NOT NULL REFERENCES plans(code),
    pending_plan_code text REFERENCES plans(code),
    status text NOT NULL CHECK (status IN ('pending_trial','active','grace','expired','suspended')),
    period_started_at timestamptz,
    period_ends_at timestamptz,
    grace_ends_at timestamptz,
    quota_bytes bigint NOT NULL DEFAULT 0,
    used_bytes bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (user_id)
);
CREATE TABLE IF NOT EXISTS trial_fingerprints (
    telegram_subject text NOT NULL,
    hwid_hmac bytea NOT NULL,
    first_used_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (telegram_subject, hwid_hmac)
);
CREATE TABLE IF NOT EXISTS devices (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    slot integer NOT NULL,
    name text NOT NULL,
    hwid_hmac bytea,
    credential_ciphertext bytea NOT NULL,
    credential_hash bytea NOT NULL UNIQUE,
    subscription_token_hash bytea NOT NULL UNIQUE,
    last_bound_at timestamptz,
    last_seen_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (user_id, slot)
);
CREATE TABLE IF NOT EXISTS nodes (
    id uuid PRIMARY KEY,
    domain text UNIQUE NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','healthy','degraded','offline','draining')),
    agent_version text NOT NULL DEFAULT '',
    protocol_version integer NOT NULL DEFAULT 1,
    capabilities jsonb NOT NULL DEFAULT '[]',
    public_key bytea NOT NULL,
    certificate_serial text,
    certificate_not_after timestamptz,
    next_certificate_serial text,
    next_certificate_not_after timestamptz,
    capacity_mbps integer NOT NULL DEFAULT 0,
    load_ratio double precision NOT NULL DEFAULT 0,
    controller_rtt_ms integer,
    compliance_version text,
    compliance_fetched_at timestamptz,
    last_heartbeat_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS node_assignments (
    device_id uuid PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    score double precision NOT NULL,
    provisioned_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS node_commands (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    type text NOT NULL,
    payload jsonb NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sent','acked','nacked','expired')),
    attempts integer NOT NULL DEFAULT 0,
    not_before timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    acked_at timestamptz,
    error text,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS node_commands_delivery_idx ON node_commands(node_id,status,not_before);
CREATE TABLE IF NOT EXISTS quota_leases (
    id uuid PRIMARY KEY,
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    bytes bigint NOT NULL CHECK (bytes >= 0),
    consumed_bytes bigint NOT NULL DEFAULT 0 CHECK (consumed_bytes >= 0),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    signature bytea NOT NULL
);
CREATE TABLE IF NOT EXISTS usage_events (
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    event_id text NOT NULL,
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
    rx_bytes bigint NOT NULL CHECK (rx_bytes >= 0),
    tx_bytes bigint NOT NULL CHECK (tx_bytes >= 0),
    started_at timestamptz NOT NULL,
    ended_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (node_id, event_id)
);
CREATE TABLE IF NOT EXISTS usage_daily (
    day date NOT NULL,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    rx_bytes bigint NOT NULL DEFAULT 0,
    tx_bytes bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (day,user_id)
);
CREATE TABLE IF NOT EXISTS compliance_snapshots (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    version text UNIQUE NOT NULL,
    source_url text NOT NULL,
    etag text,
    last_modified text,
    domains jsonb NOT NULL,
    signature bytea NOT NULL,
    fetched_at timestamptz NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now(),
    valid boolean NOT NULL
);
CREATE TABLE IF NOT EXISTS compliance_manual_rules (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind text NOT NULL CHECK (kind IN ('domain','cidr','port')),
    value text NOT NULL,
    reason text NOT NULL,
    actor_user_id uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(kind,value)
);
CREATE TABLE IF NOT EXISTS alerts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    key text UNIQUE NOT NULL,
    severity text NOT NULL,
    message text NOT NULL,
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz
);
CREATE TABLE IF NOT EXISTS notifications (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind text NOT NULL,
    payload jsonb NOT NULL,
    scheduled_at timestamptz NOT NULL,
    sent_at timestamptz,
    attempts integer NOT NULL DEFAULT 0,
    last_error text,
    UNIQUE(user_id,kind,scheduled_at)
);
CREATE TABLE IF NOT EXISTS audit_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    action text NOT NULL,
    subject_type text NOT NULL,
    subject_id text NOT NULL,
    reason text,
    ip inet,
    data jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION forbid_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'append-only table'; END $$;
DROP TRIGGER IF EXISTS ledger_immutable ON ledger_entries;
CREATE TRIGGER ledger_immutable BEFORE UPDATE OR DELETE ON ledger_entries FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
DROP TRIGGER IF EXISTS audit_immutable ON audit_events;
CREATE TRIGGER audit_immutable BEFORE UPDATE OR DELETE ON audit_events FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
