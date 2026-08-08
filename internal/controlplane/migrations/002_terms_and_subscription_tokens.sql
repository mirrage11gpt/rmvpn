ALTER TABLE users
    ADD COLUMN IF NOT EXISTS terms_accepted_at timestamptz,
    ADD COLUMN IF NOT EXISTS terms_version text;

ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS subscription_token_ciphertext bytea;
