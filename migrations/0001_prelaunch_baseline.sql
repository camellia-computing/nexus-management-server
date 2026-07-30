-- Camellia Nexus prelaunch PostgreSQL baseline.
--
-- This schema was normalized from the complete prelaunch migration history. There is no
-- supported upgrade path from earlier development-only schemas; recreate those databases.

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

CREATE FUNCTION public.bind_first_workspace_device_to_owner() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    owner_id TEXT := 'member_owner_' || md5(NEW.account_id);
    observed_at BIGINT := (NEW.document ->> 'created_at')::BIGINT;
BEGIN
    IF observed_at IS NULL OR observed_at <= 0 THEN
        RAISE EXCEPTION 'device domain timestamp is required'
            USING ERRCODE = 'check_violation', CONSTRAINT = 'device_domain_timestamp';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.account_id, 7102026));
    IF NOT EXISTS (
        SELECT 1
        FROM device_member_bindings AS bindings
        JOIN devices ON devices.device_id = bindings.device_id
        WHERE devices.account_id = NEW.account_id
    ) THEN
        INSERT INTO device_member_bindings (device_id, member_id, bound_at)
        VALUES (NEW.device_id, owner_id, observed_at)
        ON CONFLICT (device_id) DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.enforce_workspace_member_device_limit() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    bound_devices BIGINT;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.member_id, 7132026));
    SELECT COUNT(*) INTO bound_devices
    FROM device_member_bindings
    WHERE member_id = NEW.member_id
      AND device_id <> NEW.device_id;
    IF bound_devices >= 3 THEN
        RAISE EXCEPTION 'workspace member device limit exceeded'
            USING ERRCODE = 'check_violation', CONSTRAINT = 'workspace_member_device_limit';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.enforce_workspace_webhook_delivery_transition() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.state = NEW.state THEN
        RETURN NEW;
    END IF;
    IF (OLD.state = 'pending' AND NEW.state IN ('in_flight', 'dead'))
        OR (OLD.state = 'retry' AND NEW.state IN ('in_flight', 'dead'))
        OR (OLD.state = 'in_flight' AND NEW.state IN ('delivered', 'retry', 'dead')) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid workspace webhook delivery transition: % -> %', OLD.state, NEW.state
        USING ERRCODE = 'check_violation';
END;
$$;

CREATE FUNCTION public.enforce_workspace_webhook_endpoint_limit() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    endpoint_count INTEGER;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NOT (OLD.deleted_at IS NOT NULL AND NEW.deleted_at IS NULL) THEN
            RETURN NEW;
        END IF;
    END IF;
    IF TG_OP = 'INSERT' OR TG_OP = 'UPDATE' THEN
        PERFORM pg_advisory_xact_lock(hashtextextended(NEW.account_id, 240024));
        SELECT COUNT(*)
        INTO endpoint_count
        FROM workspace_webhook_endpoints
        WHERE account_id = NEW.account_id AND deleted_at IS NULL;
        IF endpoint_count >= 5 THEN
            RAISE EXCEPTION 'workspace webhook endpoint limit reached'
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.ensure_workspace_owner_for_account() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    owner_id TEXT := 'member_owner_' || md5(NEW.id);
    observed_at BIGINT := (NEW.document ->> 'created_at')::BIGINT;
BEGIN
    IF observed_at IS NULL OR observed_at <= 0 THEN
        RAISE EXCEPTION 'account domain timestamp is required'
            USING ERRCODE = 'check_violation', CONSTRAINT = 'account_domain_timestamp';
    END IF;
    INSERT INTO workspace_members
        (id, account_id, email, display_name, role, status, row_version, created_at, updated_at)
    VALUES
        (owner_id, NEW.id, 'owner+' || md5(NEW.id) || '@local.invalid', NEW.id,
         'owner', 'active', 1, observed_at, observed_at)
    ON CONFLICT (account_id, email) DO NOTHING;
    RETURN NEW;
END;
$$;

CREATE FUNCTION public.observe_service_time_authority(logical_unix bigint, max_forward_jump_seconds bigint) RETURNS TABLE(trusted_unix bigint, database_unix bigint, previous_high_water_unix bigint, authority_status text, status_changed boolean)
    LANGUAGE plpgsql
    SET search_path TO 'public', 'pg_catalog'
    AS $$
DECLARE
    previous service_time_authority%ROWTYPE;
    observed_unix BIGINT;
    expected_unix BIGINT;
    next_trusted_unix BIGINT;
    next_status TEXT;
BEGIN
    IF max_forward_jump_seconds <= 0 OR logical_unix < 0 THEN
        RAISE EXCEPTION 'invalid time-authority input';
    END IF;

    SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT
    INTO observed_unix;
    IF observed_unix < 0 THEN
        RAISE EXCEPTION 'database time predates the Unix epoch';
    END IF;

    SELECT authority.*
    INTO previous
    FROM service_time_authority AS authority
    WHERE authority.singleton = 1
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'time-authority singleton is missing';
    END IF;

    expected_unix := GREATEST(
        previous.high_water_unix,
        COALESCE(logical_unix, previous.high_water_unix)
    );
    IF observed_unix::NUMERIC
        > expected_unix::NUMERIC + max_forward_jump_seconds::NUMERIC
    THEN
        next_status := 'forward_jump';
        next_trusted_unix := expected_unix;
    ELSIF observed_unix < previous.high_water_unix THEN
        next_status := 'rollback_held';
        next_trusted_unix := expected_unix;
    ELSE
        next_status := 'healthy';
        next_trusted_unix := GREATEST(expected_unix, observed_unix);
    END IF;

    UPDATE service_time_authority AS authority
    SET high_water_unix = next_trusted_unix,
        last_database_unix = observed_unix,
        anomaly_count = authority.anomaly_count
            + CASE
                WHEN next_status <> 'healthy' AND authority.status <> next_status THEN 1
                ELSE 0
              END,
        anomaly_detected_at = CASE
            WHEN next_status <> 'healthy' AND authority.status <> next_status
                THEN clock_timestamp()
            ELSE authority.anomaly_detected_at
        END,
        status = next_status,
        updated_at = clock_timestamp()
    WHERE authority.singleton = 1;

    RETURN QUERY SELECT
        next_trusted_unix,
        observed_unix,
        previous.high_water_unix,
        next_status,
        previous.status <> next_status;
END;
$$;

CREATE FUNCTION public.validate_workspace_webhook_event_types() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    canonical_types TEXT[];
    configured_type TEXT;
BEGIN
    FOREACH configured_type IN ARRAY NEW.event_types LOOP
        IF NOT configured_type = ANY(ARRAY[
            'alert.incident.acknowledged',
            'alert.incident.opened',
            'alert.incident.resolved',
            'configuration.created',
            'configuration.deleted',
            'configuration.published',
            'configuration.purged',
            'configuration.restored',
            'configuration.revised',
            'sync.conflict'
        ]::TEXT[]) THEN
            RAISE EXCEPTION 'unsupported workspace webhook event type'
                USING ERRCODE = 'check_violation';
        END IF;
    END LOOP;
    SELECT array_agg(DISTINCT value ORDER BY value)
    INTO canonical_types
    FROM unnest(NEW.event_types) AS configured(value);
    IF NEW.event_types <> canonical_types THEN
        RAISE EXCEPTION 'workspace webhook event types must be sorted and unique'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

SET default_tablespace = '';

SET default_table_access_method = heap;

CREATE TABLE public.accounts (
    id text NOT NULL,
    document jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 1 NOT NULL,
    CONSTRAINT accounts_canonical_id_check CHECK ((id ~ '^[A-Za-z0-9_.:-]{1,128}$'::text)),
    CONSTRAINT accounts_row_version_check CHECK ((row_version > 0))
);

CREATE TABLE public.activation_codes (
    code_hash text NOT NULL,
    code_prefix text NOT NULL,
    account_id text NOT NULL,
    license_id text,
    status text NOT NULL,
    expires_at bigint,
    consumed boolean DEFAULT false NOT NULL,
    consumed_at bigint,
    consumed_device_id text,
    document jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 1 NOT NULL,
    CONSTRAINT activation_codes_row_version_check CHECK ((row_version > 0)),
    CONSTRAINT activation_codes_status_check CHECK ((status = ANY (ARRAY['active'::text, 'consumed'::text, 'revoked'::text])))
);

CREATE TABLE public.admin_bulk_job_items (
    job_id text NOT NULL,
    ordinal integer NOT NULL,
    target_type text NOT NULL,
    target_id text NOT NULL,
    expected_version bigint NOT NULL,
    status text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    lease_generation bigint DEFAULT 0 NOT NULL,
    error_code text,
    started_at bigint,
    finished_at bigint,
    CONSTRAINT admin_bulk_job_items_attempts_check CHECK ((attempts >= 0)),
    CONSTRAINT admin_bulk_job_items_lease_generation_check CHECK ((lease_generation >= 0)),
    CONSTRAINT admin_bulk_job_items_expected_version_check CHECK ((expected_version > 0)),
    CONSTRAINT admin_bulk_job_items_ordinal_check CHECK ((ordinal >= 0)),
    CONSTRAINT admin_bulk_job_items_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'running'::text, 'succeeded'::text, 'failed'::text, 'canceled'::text])))
);

CREATE TABLE public.admin_bulk_jobs (
    id text NOT NULL,
    kind text NOT NULL,
    status text NOT NULL,
    actor_id text NOT NULL,
    session_id text,
    reason text NOT NULL,
    idempotency_key text NOT NULL,
    request_hash text NOT NULL,
    parameters jsonb NOT NULL,
    total_items integer NOT NULL,
    completed_items integer DEFAULT 0 NOT NULL,
    failed_items integer DEFAULT 0 NOT NULL,
    lease_owner text,
    lease_expires_at bigint,
    lease_generation bigint DEFAULT 0 NOT NULL,
    parent_job_id text,
    created_at bigint NOT NULL,
    started_at bigint,
    finished_at bigint,
    CONSTRAINT admin_bulk_jobs_completed_items_check CHECK ((completed_items >= 0)),
    CONSTRAINT admin_bulk_jobs_failed_items_check CHECK ((failed_items >= 0)),
    CONSTRAINT admin_bulk_jobs_lease_generation_check CHECK ((lease_generation >= 0)),
    CONSTRAINT admin_bulk_jobs_request_hash_check CHECK ((request_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT admin_bulk_jobs_status_check CHECK ((status = ANY (ARRAY['queued'::text, 'running'::text, 'cancel_requested'::text, 'succeeded'::text, 'partial_failed'::text, 'failed'::text, 'canceled'::text]))),
    CONSTRAINT admin_bulk_jobs_total_items_check CHECK (((total_items >= 1) AND (total_items <= 10000)))
);

CREATE TABLE public.admin_bulk_previews (
    id text NOT NULL,
    actor_id text NOT NULL,
    kind text NOT NULL,
    parameters jsonb NOT NULL,
    targets jsonb NOT NULL,
    target_count integer NOT NULL,
    request_hash text NOT NULL,
    expires_at bigint NOT NULL,
    consumed_at bigint,
    created_at bigint NOT NULL,
    CONSTRAINT admin_bulk_previews_check CHECK ((expires_at > created_at)),
    CONSTRAINT admin_bulk_previews_kind_check CHECK ((kind = ANY (ARRAY['account_set_state'::text, 'license_set_status'::text, 'activation_code_revoke'::text, 'activation_code_expire'::text, 'device_set_state'::text]))),
    CONSTRAINT admin_bulk_previews_request_hash_check CHECK ((request_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT admin_bulk_previews_target_count_check CHECK (((target_count >= 1) AND (target_count <= 10000)))
);

CREATE TABLE public.admin_enrollment_states (
    token_hash text NOT NULL,
    key_id text NOT NULL,
    nonce bytea NOT NULL,
    ciphertext bytea NOT NULL,
    created_at bigint NOT NULL
);

CREATE TABLE public.admin_enrollment_tokens (
    token_hash text NOT NULL,
    user_id text NOT NULL,
    purpose text NOT NULL,
    created_by text NOT NULL,
    reason text NOT NULL,
    expires_at bigint NOT NULL,
    consumed_at bigint,
    created_at bigint NOT NULL,
    CONSTRAINT admin_enrollment_tokens_check CHECK ((expires_at > created_at)),
    CONSTRAINT admin_enrollment_tokens_purpose_check CHECK ((purpose = ANY (ARRAY['enroll'::text, 'reset'::text]))),
    CONSTRAINT admin_enrollment_tokens_token_hash_check CHECK ((token_hash ~ '^[0-9a-f]{64}$'::text))
);

CREATE TABLE public.admin_login_buckets (
    bucket_key text NOT NULL,
    window_started_at bigint NOT NULL,
    attempts integer NOT NULL,
    blocked_until bigint,
    CONSTRAINT admin_login_buckets_attempts_check CHECK ((attempts >= 0))
);

CREATE TABLE public.admin_operations (
    operation_id text NOT NULL,
    command text NOT NULL,
    request_hash text NOT NULL,
    actor text NOT NULL,
    reason text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    response_document jsonb
);

CREATE TABLE public.admin_password_credentials (
    user_id text NOT NULL,
    password_hash text NOT NULL,
    key_id text NOT NULL,
    changed_at bigint NOT NULL,
    credential_epoch bigint DEFAULT 1 NOT NULL,
    CONSTRAINT admin_password_credentials_epoch_check CHECK ((credential_epoch > 0))
);

CREATE TABLE public.admin_recovery_codes (
    user_id text NOT NULL,
    code_hash text NOT NULL,
    consumed_at bigint,
    created_at bigint NOT NULL,
    CONSTRAINT admin_recovery_codes_code_hash_check CHECK ((code_hash ~ '^[0-9a-f]{64}$'::text))
);

CREATE TABLE public.admin_role_bindings (
    user_id text NOT NULL,
    role text NOT NULL,
    granted_by text NOT NULL,
    reason text NOT NULL,
    created_at bigint NOT NULL,
    CONSTRAINT admin_role_bindings_role_check CHECK ((role = ANY (ARRAY['platform_owner'::text, 'licensing_admin'::text, 'security_admin'::text, 'billing_admin'::text, 'support_operator'::text, 'auditor'::text])))
);

CREATE TABLE public.admin_secret_deliveries (
    id text NOT NULL,
    actor_id text NOT NULL,
    session_id text NOT NULL,
    purpose text NOT NULL,
    key_id text NOT NULL,
    nonce bytea NOT NULL,
    ciphertext bytea NOT NULL,
    claim_token_hash text NOT NULL,
    expires_at bigint NOT NULL,
    claimed_at bigint,
    acknowledged_at bigint,
    created_at bigint NOT NULL,
    CONSTRAINT admin_secret_deliveries_check CHECK ((expires_at > created_at)),
    CONSTRAINT admin_secret_deliveries_claim_token_hash_check CHECK ((claim_token_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT admin_secret_deliveries_purpose_check CHECK ((purpose = ANY (ARRAY['activation_code_batch'::text, 'team_invitation'::text, 'admin_enrollment'::text])))
);

CREATE TABLE public.admin_sessions (
    id text NOT NULL,
    user_id text NOT NULL,
    token_hash text NOT NULL,
    csrf_hash text NOT NULL,
    source_ip text,
    user_agent_hash text,
    auth_time bigint NOT NULL,
    elevated_until bigint NOT NULL,
    last_seen_at bigint NOT NULL,
    expires_at bigint NOT NULL,
    revoked_at bigint,
    created_at bigint NOT NULL,
    credential_epoch bigint DEFAULT 1 NOT NULL,
    CONSTRAINT admin_sessions_check CHECK ((expires_at > created_at)),
    CONSTRAINT admin_sessions_epoch_check CHECK ((credential_epoch > 0)),
    CONSTRAINT admin_sessions_csrf_hash_check CHECK ((csrf_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT admin_sessions_token_hash_check CHECK ((token_hash ~ '^[0-9a-f]{64}$'::text))
);

CREATE TABLE public.admin_totp_credentials (
    user_id text NOT NULL,
    key_id text NOT NULL,
    nonce bytea NOT NULL,
    ciphertext bytea NOT NULL,
    last_used_step bigint,
    confirmed_at bigint NOT NULL
);

CREATE TABLE public.admin_users (
    id text NOT NULL,
    username text NOT NULL,
    display_name text NOT NULL,
    status text NOT NULL,
    row_version bigint DEFAULT 1 NOT NULL,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    CONSTRAINT admin_users_display_name_check CHECK (((char_length(display_name) >= 1) AND (char_length(display_name) <= 128))),
    CONSTRAINT admin_users_row_version_check CHECK ((row_version > 0)),
    CONSTRAINT admin_users_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'active'::text, 'disabled'::text]))),
    CONSTRAINT admin_users_username_check CHECK ((username ~ '^[a-z0-9][a-z0-9._-]{2,63}$'::text))
);

CREATE TABLE public.audit_archive_manifests (
    id text NOT NULL,
    period_start bigint NOT NULL,
    period_end bigint NOT NULL,
    object_id text NOT NULL,
    row_count bigint NOT NULL,
    sha256 text NOT NULL,
    verified_at bigint NOT NULL,
    created_at bigint NOT NULL,
    CONSTRAINT audit_archive_manifests_row_count_check CHECK ((row_count >= 0)),
    CONSTRAINT audit_archive_manifests_sha256_check CHECK ((sha256 ~ '^[0-9a-f]{64}$'::text))
);

CREATE TABLE public.audit_events (
    id text NOT NULL,
    event_type text NOT NULL,
    outcome text NOT NULL,
    occurred_at bigint NOT NULL,
    account_id text,
    license_id text,
    device_id text,
    reason_code text,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    document jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    actor_type text,
    actor_id text,
    admin_session_id text,
    request_id text,
    source_ip text,
    user_agent_hash text,
    target_type text,
    target_id text,
    operation_id text,
    job_id text
);

CREATE TABLE public.authorization_codes (
    code_hash text NOT NULL,
    account_id text NOT NULL,
    license_id text,
    activation_code_hash text,
    expires_at bigint NOT NULL,
    consumed boolean DEFAULT false NOT NULL,
    document jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.billing_invoices (
    id text NOT NULL,
    account_id text NOT NULL,
    license_id text NOT NULL,
    offer_id text NOT NULL,
    plan text NOT NULL,
    plan_revision integer NOT NULL,
    seats integer NOT NULL,
    duration_days integer NOT NULL,
    currency text NOT NULL,
    amount_due numeric(20,8) NOT NULL,
    payment_reference text NOT NULL,
    status text NOT NULL,
    due_at bigint NOT NULL,
    paid_at bigint,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    row_version bigint DEFAULT 1 NOT NULL,
    CONSTRAINT billing_invoices_amount_due_check CHECK ((amount_due >= (0)::numeric)),
    CONSTRAINT billing_invoices_duration_days_check CHECK (((duration_days >= 1) AND (duration_days <= 3660))),
    CONSTRAINT billing_invoices_plan_check CHECK ((plan = ANY (ARRAY['pro'::text, 'team'::text]))),
    CONSTRAINT billing_invoices_plan_revision_check CHECK ((plan_revision > 0)),
    CONSTRAINT billing_invoices_row_version_check CHECK ((row_version > 0)),
    CONSTRAINT billing_invoices_seats_check CHECK ((seats >= 0)),
    CONSTRAINT billing_invoices_status_check CHECK ((status = ANY (ARRAY['open'::text, 'paid'::text, 'overdue'::text, 'void'::text, 'refunded'::text])))
);

CREATE TABLE public.commercial_offers (
    id text NOT NULL,
    plan text NOT NULL,
    plan_revision integer NOT NULL,
    duration_days integer NOT NULL,
    currency text NOT NULL,
    base_amount numeric(20,8) NOT NULL,
    seat_amount numeric(20,8),
    name_en text NOT NULL,
    name_zh text NOT NULL,
    active boolean DEFAULT true NOT NULL,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    row_version bigint DEFAULT 1 NOT NULL,
    CONSTRAINT commercial_offers_base_amount_check CHECK ((base_amount >= (0)::numeric)),
    CONSTRAINT commercial_offers_currency_check CHECK ((currency ~ '^[A-Z][A-Z0-9]{2,11}$'::text)),
    CONSTRAINT commercial_offers_duration_days_check CHECK (((duration_days >= 1) AND (duration_days <= 3660))),
    CONSTRAINT commercial_offers_plan_check CHECK ((plan = ANY (ARRAY['pro'::text, 'team'::text]))),
    CONSTRAINT commercial_offers_plan_revision_check CHECK ((plan_revision > 0)),
    CONSTRAINT commercial_offers_row_version_check CHECK ((row_version > 0)),
    CONSTRAINT commercial_offers_seat_amount_check CHECK (((seat_amount IS NULL) OR (seat_amount >= (0)::numeric)))
);

CREATE TABLE public.customer_payment_operations (
    account_id text NOT NULL,
    operation_id text NOT NULL,
    request_hash text NOT NULL,
    claim_id text,
    response jsonb,
    submitted_at bigint NOT NULL,
    CONSTRAINT customer_payment_operations_completion_check CHECK ((((claim_id IS NULL) AND (response IS NULL)) OR ((claim_id IS NOT NULL) AND (response IS NOT NULL) AND (jsonb_typeof(response) = 'object'::text) AND ((response ->> 'id'::text) = claim_id) AND ((response ->> 'accountId'::text) = account_id) AND ((response ->> 'submittedAt'::text) = (submitted_at)::text)))),
    CONSTRAINT customer_payment_operations_operation_id_check CHECK ((operation_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'::text)),
    CONSTRAINT customer_payment_operations_request_hash_check CHECK ((request_hash ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT customer_payment_operations_submitted_at_check CHECK ((submitted_at > 0))
);

CREATE TABLE public.device_challenges (
    challenge_id text NOT NULL,
    device_id text NOT NULL,
    expires_at bigint NOT NULL,
    consumed boolean DEFAULT false NOT NULL,
    document jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.device_member_bindings (
    device_id text NOT NULL,
    member_id text NOT NULL,
    bound_at bigint NOT NULL
);

CREATE TABLE public.devices (
    device_id text NOT NULL,
    account_id text NOT NULL,
    license_id text NOT NULL,
    state text NOT NULL,
    document jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_version bigint DEFAULT 1 NOT NULL,
    CONSTRAINT devices_row_version_check CHECK ((row_version > 0)),
    CONSTRAINT devices_state_check CHECK ((state = ANY (ARRAY['pending_activation'::text, 'active'::text, 'removed'::text, 'revoked'::text, 'suspicious'::text])))
);

CREATE TABLE public.licenses (
    id text NOT NULL,
    account_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    plan text NOT NULL,
    plan_revision integer NOT NULL,
    status text NOT NULL,
    expires_at bigint,
    license_epoch bigint NOT NULL,
    purchased_seats integer NOT NULL,
    row_version bigint NOT NULL,
    CONSTRAINT licenses_canonical_id_check CHECK ((id ~ '^[A-Za-z0-9_.:-]{1,128}$'::text)),
    CONSTRAINT licenses_epoch_check CHECK ((license_epoch > 0)),
    CONSTRAINT licenses_plan_check CHECK ((plan = ANY (ARRAY['free'::text, 'pro'::text, 'team'::text]))),
    CONSTRAINT licenses_plan_revision_check CHECK ((plan_revision > 0)),
    CONSTRAINT licenses_row_version_check CHECK ((row_version > 0)),
    CONSTRAINT licenses_seats_check CHECK ((((plan = 'team'::text) AND ((purchased_seats >= 3) AND (purchased_seats <= 10000))) OR ((plan <> 'team'::text) AND (purchased_seats = 0)))),
    CONSTRAINT licenses_status_check CHECK ((status = ANY (ARRAY['active'::text, 'past_due'::text, 'canceled'::text])))
);

CREATE TABLE public.manual_payment_claims (
    id text NOT NULL,
    invoice_id text NOT NULL,
    account_id text NOT NULL,
    payment_method_id text NOT NULL,
    external_transaction_id text NOT NULL,
    paid_amount numeric(20,8) NOT NULL,
    paid_asset text NOT NULL,
    paid_at bigint NOT NULL,
    payer_name text,
    note text,
    status text NOT NULL,
    submitted_by text NOT NULL,
    reviewed_by text,
    review_reason text,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    row_version bigint DEFAULT 1 NOT NULL,
    submitted_at bigint NOT NULL,
    CONSTRAINT manual_payment_claims_paid_amount_check CHECK ((paid_amount >= (0)::numeric)),
    CONSTRAINT manual_payment_claims_row_version_check CHECK ((row_version > 0)),
    CONSTRAINT manual_payment_claims_status_check CHECK ((status = ANY (ARRAY['submitted'::text, 'under_review'::text, 'needs_information'::text, 'verified'::text, 'rejected'::text, 'withdrawn'::text])))
);

CREATE TABLE public.manual_payment_methods (
    id text NOT NULL,
    name_en text NOT NULL,
    name_zh text NOT NULL,
    instructions_en text NOT NULL,
    instructions_zh text NOT NULL,
    settlement_asset text NOT NULL,
    destination_hint text NOT NULL,
    active boolean DEFAULT true NOT NULL,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    row_version bigint DEFAULT 1 NOT NULL,
    CONSTRAINT manual_payment_methods_row_version_check CHECK ((row_version > 0)),
    CONSTRAINT manual_payment_methods_settlement_asset_check CHECK ((settlement_asset ~ '^[A-Z][A-Z0-9._-]{1,15}$'::text))
);

CREATE TABLE public.member_device_enrollments (
    id text NOT NULL,
    account_id text NOT NULL,
    member_id text NOT NULL,
    token_hash text NOT NULL,
    created_by_device_id text NOT NULL,
    expires_at bigint NOT NULL,
    consumed_at bigint,
    revoked_at bigint,
    created_at bigint NOT NULL,
    CONSTRAINT member_device_enrollments_check CHECK ((expires_at > created_at)),
    CONSTRAINT member_device_enrollments_check1 CHECK ((NOT ((consumed_at IS NOT NULL) AND (revoked_at IS NOT NULL))))
);

CREATE TABLE public.payment_evidence_attachments (
    id text NOT NULL,
    claim_id text NOT NULL,
    object_id text NOT NULL,
    original_name text NOT NULL,
    media_type text NOT NULL,
    byte_length bigint NOT NULL,
    sha256 text NOT NULL,
    scan_status text NOT NULL,
    created_at bigint NOT NULL,
    scanned_at bigint,
    CONSTRAINT payment_evidence_attachments_byte_length_check CHECK (((byte_length >= 1) AND (byte_length <= 8388608))),
    CONSTRAINT payment_evidence_attachments_media_type_check CHECK ((media_type = ANY (ARRAY['image/png'::text, 'image/jpeg'::text, 'application/pdf'::text]))),
    CONSTRAINT payment_evidence_attachments_scan_status_check CHECK ((scan_status = ANY (ARRAY['quarantined'::text, 'clean'::text, 'rejected'::text, 'failed'::text]))),
    CONSTRAINT payment_evidence_attachments_sha256_check CHECK ((sha256 ~ '^[0-9a-f]{64}$'::text))
);

CREATE TABLE public.rate_limit_buckets (
    scope text NOT NULL,
    bucket_key text NOT NULL,
    window_started_at bigint NOT NULL,
    request_count bigint NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT rate_limit_buckets_request_count_check CHECK ((request_count > 0))
);

CREATE TABLE public.refresh_sessions (
    token_hash text NOT NULL,
    family_id text NOT NULL,
    active boolean NOT NULL,
    expires_at bigint NOT NULL,
    document jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    device_id text NOT NULL,
    proof_state text NOT NULL,
    CONSTRAINT refresh_sessions_proof_state_check CHECK ((proof_state = ANY (ARRAY['unproven'::text, 'device_proven'::text])))
);

CREATE TABLE public.service_time_authority (
    singleton smallint NOT NULL,
    high_water_unix bigint NOT NULL,
    last_database_unix bigint NOT NULL,
    status text NOT NULL,
    anomaly_count bigint DEFAULT 0 NOT NULL,
    anomaly_detected_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT service_time_authority_anomaly_count_check CHECK ((anomaly_count >= 0)),
    CONSTRAINT service_time_authority_high_water_unix_check CHECK ((high_water_unix >= 0)),
    CONSTRAINT service_time_authority_last_database_unix_check CHECK ((last_database_unix >= 0)),
    CONSTRAINT service_time_authority_singleton_check CHECK ((singleton = 1)),
    CONSTRAINT service_time_authority_status_check CHECK ((status = ANY (ARRAY['healthy'::text, 'rollback_held'::text, 'forward_jump'::text])))
);

CREATE TABLE public.stored_object_chunks (
    object_id text NOT NULL,
    chunk_index integer NOT NULL,
    ciphertext bytea NOT NULL,
    CONSTRAINT stored_object_chunks_chunk_index_check CHECK ((chunk_index >= 0))
);

CREATE TABLE public.stored_objects (
    id text NOT NULL,
    namespace text NOT NULL,
    backend text NOT NULL,
    locator text NOT NULL,
    media_type text NOT NULL,
    original_name text,
    byte_length bigint NOT NULL,
    sha256 text NOT NULL,
    key_id text NOT NULL,
    wrapped_key_nonce bytea NOT NULL,
    wrapped_key bytea NOT NULL,
    content_nonce bytea NOT NULL,
    status text NOT NULL,
    staging_target_status text,
    created_by text NOT NULL,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    CONSTRAINT stored_objects_backend_check CHECK ((backend = ANY (ARRAY['filesystem'::text, 'database'::text, 's3'::text]))),
    CONSTRAINT stored_objects_byte_length_check CHECK ((byte_length >= 0)),
    CONSTRAINT stored_objects_sha256_check CHECK ((sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT stored_objects_status_check CHECK ((status = ANY (ARRAY['staging'::text, 'quarantined'::text, 'ready'::text, 'rejected'::text, 'deleting'::text]))),
    CONSTRAINT stored_objects_staging_target_check CHECK (((status = 'staging'::text AND backend <> 'database'::text AND staging_target_status = ANY (ARRAY['quarantined'::text, 'ready'::text, 'rejected'::text])) OR (status <> 'staging'::text AND staging_target_status IS NULL)))
);

CREATE TABLE public.team_invitations (
    id text NOT NULL,
    account_id text NOT NULL,
    member_id text NOT NULL,
    token_hash text NOT NULL,
    invited_by_member_id text,
    expires_at bigint NOT NULL,
    accepted_at bigint,
    revoked_at bigint,
    created_at bigint NOT NULL,
    invited_by_admin_user_id text,
    CONSTRAINT team_invitations_check CHECK ((expires_at > created_at)),
    CONSTRAINT team_invitations_check1 CHECK ((NOT ((accepted_at IS NOT NULL) AND (revoked_at IS NOT NULL)))),
    CONSTRAINT team_invitations_one_inviter CHECK (((((invited_by_member_id IS NOT NULL))::integer + ((invited_by_admin_user_id IS NOT NULL))::integer) = 1))
);

CREATE TABLE public.workspace_alert_incidents (
    id text NOT NULL,
    account_id text NOT NULL,
    rule_id text NOT NULL,
    event_kind text NOT NULL,
    severity text NOT NULL,
    dedupe_key text NOT NULL,
    status text NOT NULL,
    summary text NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    row_version bigint DEFAULT 1 NOT NULL,
    occurred_at bigint NOT NULL,
    acknowledged_at bigint,
    acknowledged_by_device_id text,
    resolved_at bigint,
    resolved_by_device_id text,
    CONSTRAINT workspace_alert_incidents_check CHECK ((((status = 'open'::text) AND (acknowledged_at IS NULL) AND (acknowledged_by_device_id IS NULL) AND (resolved_at IS NULL) AND (resolved_by_device_id IS NULL)) OR ((status = 'acknowledged'::text) AND (acknowledged_at IS NOT NULL) AND (acknowledged_by_device_id IS NOT NULL) AND (resolved_at IS NULL) AND (resolved_by_device_id IS NULL)) OR ((status = 'resolved'::text) AND (acknowledged_at IS NOT NULL) AND (acknowledged_by_device_id IS NOT NULL) AND (resolved_at IS NOT NULL) AND (resolved_by_device_id IS NOT NULL)))),
    CONSTRAINT workspace_alert_incidents_dedupe_key_check CHECK ((length(dedupe_key) = 64)),
    CONSTRAINT workspace_alert_incidents_event_kind_check CHECK ((event_kind = ANY (ARRAY['sync_conflict'::text, 'quota_warning'::text, 'configuration_created'::text, 'configuration_revised'::text, 'configuration_published'::text, 'configuration_deleted'::text, 'configuration_restored'::text]))),
    CONSTRAINT workspace_alert_incidents_id_check CHECK (((length(id) >= 1) AND (length(id) <= 128))),
    CONSTRAINT workspace_alert_incidents_row_version_check CHECK ((row_version > 0)),
    CONSTRAINT workspace_alert_incidents_severity_check CHECK ((severity = ANY (ARRAY['info'::text, 'warning'::text, 'critical'::text]))),
    CONSTRAINT workspace_alert_incidents_status_check CHECK ((status = ANY (ARRAY['open'::text, 'acknowledged'::text, 'resolved'::text]))),
    CONSTRAINT workspace_alert_incidents_summary_check CHECK (((octet_length(summary) >= 1) AND (octet_length(summary) <= 512)))
);

CREATE TABLE public.workspace_alert_rules (
    id text NOT NULL,
    account_id text NOT NULL,
    name text NOT NULL,
    event_kind text NOT NULL,
    severity text NOT NULL,
    enabled boolean NOT NULL,
    row_version bigint DEFAULT 1 NOT NULL,
    deleted_at bigint,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    CONSTRAINT workspace_alert_rules_event_kind_check CHECK ((event_kind = ANY (ARRAY['sync_conflict'::text, 'quota_warning'::text, 'configuration_created'::text, 'configuration_revised'::text, 'configuration_published'::text, 'configuration_deleted'::text, 'configuration_restored'::text]))),
    CONSTRAINT workspace_alert_rules_id_check CHECK (((length(id) >= 1) AND (length(id) <= 128))),
    CONSTRAINT workspace_alert_rules_name_check CHECK (((octet_length(name) >= 1) AND (octet_length(name) <= 160))),
    CONSTRAINT workspace_alert_rules_row_version_check CHECK ((row_version > 0)),
    CONSTRAINT workspace_alert_rules_severity_check CHECK ((severity = ANY (ARRAY['info'::text, 'warning'::text, 'critical'::text])))
);

CREATE TABLE public.workspace_changes (
    cursor bigint NOT NULL,
    account_id text NOT NULL,
    device_id text NOT NULL,
    operation_id text NOT NULL,
    change_kind text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    row_version bigint NOT NULL,
    occurred_at bigint NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT workspace_changes_change_kind_check CHECK ((change_kind = ANY (ARRAY['configuration_created'::text, 'configuration_revised'::text, 'configuration_published'::text, 'configuration_deleted'::text, 'configuration_restored'::text, 'configuration_purged'::text, 'sync_conflict'::text, 'alert_rule_created'::text, 'alert_rule_updated'::text, 'alert_rule_deleted'::text, 'alert_incident_opened'::text, 'alert_incident_updated'::text, 'alert_incident_acknowledged'::text, 'alert_incident_resolved'::text]))),
    CONSTRAINT workspace_changes_operation_id_check CHECK (((length(operation_id) >= 1) AND (length(operation_id) <= 160))),
    CONSTRAINT workspace_changes_resource_id_check CHECK (((length(resource_id) >= 1) AND (length(resource_id) <= 128))),
    CONSTRAINT workspace_changes_resource_type_check CHECK (((length(resource_type) >= 1) AND (length(resource_type) <= 64))),
    CONSTRAINT workspace_changes_row_version_check CHECK ((row_version >= 0))
);

CREATE SEQUENCE public.workspace_changes_cursor_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.workspace_changes_cursor_seq OWNED BY public.workspace_changes.cursor;

CREATE TABLE public.workspace_device_checkpoints (
    account_id text NOT NULL,
    device_id text NOT NULL,
    cursor bigint NOT NULL,
    row_version bigint DEFAULT 1 NOT NULL,
    updated_at bigint NOT NULL,
    CONSTRAINT workspace_device_checkpoints_cursor_check CHECK ((cursor >= 0)),
    CONSTRAINT workspace_device_checkpoints_row_version_check CHECK ((row_version > 0))
);

CREATE TABLE public.workspace_document_revisions (
    account_id text NOT NULL,
    document_id text NOT NULL,
    revision bigint NOT NULL,
    name text NOT NULL,
    program_kind text NOT NULL,
    key_id text NOT NULL,
    wrapped_key_nonce bytea NOT NULL,
    wrapped_data_key bytea NOT NULL,
    content_nonce bytea NOT NULL,
    ciphertext bytea NOT NULL,
    payload_sha256 bytea NOT NULL,
    content_sha256 bytea NOT NULL,
    plaintext_bytes bigint NOT NULL,
    created_by_device_id text NOT NULL,
    created_at bigint NOT NULL,
    CONSTRAINT workspace_document_revisions_ciphertext_check CHECK (((octet_length(ciphertext) >= 20) AND (octet_length(ciphertext) <= 4198420))),
    CONSTRAINT workspace_document_revisions_content_nonce_check CHECK ((octet_length(content_nonce) = 24)),
    CONSTRAINT workspace_document_revisions_content_sha256_check CHECK ((octet_length(content_sha256) = 32)),
    CONSTRAINT workspace_document_revisions_key_id_check CHECK (((length(key_id) >= 1) AND (length(key_id) <= 128))),
    CONSTRAINT workspace_document_revisions_name_check CHECK (((octet_length(name) >= 1) AND (octet_length(name) <= 160))),
    CONSTRAINT workspace_document_revisions_payload_sha256_check CHECK ((octet_length(payload_sha256) = 32)),
    CONSTRAINT workspace_document_revisions_plaintext_bytes_check CHECK (((plaintext_bytes >= 4) AND (plaintext_bytes <= 4198404))),
    CONSTRAINT workspace_document_revisions_program_kind_check CHECK ((program_kind = ANY (ARRAY['generic'::text, 'singBox'::text, 'xray'::text, 'mihomo'::text]))),
    CONSTRAINT workspace_document_revisions_revision_check CHECK ((revision > 0)),
    CONSTRAINT workspace_document_revisions_wrapped_data_key_check CHECK ((octet_length(wrapped_data_key) = 48)),
    CONSTRAINT workspace_document_revisions_wrapped_key_nonce_check CHECK ((octet_length(wrapped_key_nonce) = 24))
);

CREATE TABLE public.workspace_documents (
    id text NOT NULL,
    account_id text NOT NULL,
    row_version bigint DEFAULT 1 NOT NULL,
    last_revision bigint DEFAULT 0 NOT NULL,
    draft_revision bigint,
    published_revision bigint,
    deleted_at bigint,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    CONSTRAINT workspace_documents_check CHECK (((draft_revision IS NULL) OR (draft_revision <= last_revision))),
    CONSTRAINT workspace_documents_check1 CHECK (((published_revision IS NULL) OR (published_revision <= last_revision))),
    CONSTRAINT workspace_documents_draft_revision_check CHECK (((draft_revision IS NULL) OR (draft_revision > 0))),
    CONSTRAINT workspace_documents_id_check CHECK (((length(id) >= 1) AND (length(id) <= 128))),
    CONSTRAINT workspace_documents_last_revision_check CHECK ((last_revision >= 0)),
    CONSTRAINT workspace_documents_published_revision_check CHECK (((published_revision IS NULL) OR (published_revision > 0))),
    CONSTRAINT workspace_documents_row_version_check CHECK ((row_version > 0))
);

CREATE TABLE public.workspace_members (
    id text NOT NULL,
    account_id text NOT NULL,
    email text NOT NULL,
    display_name text NOT NULL,
    role text NOT NULL,
    status text NOT NULL,
    row_version bigint DEFAULT 1 NOT NULL,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    CONSTRAINT workspace_members_role_check CHECK ((role = ANY (ARRAY['owner'::text, 'admin'::text, 'billing'::text, 'operator'::text, 'viewer'::text, 'auditor'::text]))),
    CONSTRAINT workspace_members_row_version_check CHECK ((row_version > 0)),
    CONSTRAINT workspace_members_status_check CHECK ((status = ANY (ARRAY['invited'::text, 'active'::text, 'suspended'::text, 'removed'::text])))
);

CREATE TABLE public.workspace_operations (
    account_id text NOT NULL,
    operation_id text NOT NULL,
    device_id text NOT NULL,
    action text NOT NULL,
    request_sha256 bytea NOT NULL,
    outcome text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    response_row_version bigint NOT NULL,
    sync_cursor bigint,
    created_at bigint NOT NULL,
    CONSTRAINT workspace_operations_action_check CHECK (((length(action) >= 1) AND (length(action) <= 64))),
    CONSTRAINT workspace_operations_operation_id_check CHECK ((operation_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'::text)),
    CONSTRAINT workspace_operations_outcome_check CHECK ((outcome = ANY (ARRAY['succeeded'::text, 'version_conflict'::text, 'quota_exceeded'::text, 'document_limit'::text, 'alert_rule_limit'::text, 'retention_active'::text]))),
    CONSTRAINT workspace_operations_request_sha256_check CHECK ((octet_length(request_sha256) = 32)),
    CONSTRAINT workspace_operations_resource_id_check CHECK (((length(resource_id) >= 1) AND (length(resource_id) <= 128))),
    CONSTRAINT workspace_operations_resource_type_check CHECK (((length(resource_type) >= 1) AND (length(resource_type) <= 64))),
    CONSTRAINT workspace_operations_response_row_version_check CHECK ((response_row_version >= 0)),
    CONSTRAINT workspace_operations_sync_cursor_check CHECK (((sync_cursor IS NULL) OR (sync_cursor >= 0)))
);

CREATE TABLE public.workspace_storage_usage (
    account_id text NOT NULL,
    active_document_count integer DEFAULT 0 NOT NULL,
    revision_plaintext_bytes bigint DEFAULT 0 NOT NULL,
    row_version bigint DEFAULT 1 NOT NULL,
    updated_at bigint NOT NULL,
    CONSTRAINT workspace_storage_usage_active_document_count_check CHECK (((active_document_count >= 0) AND (active_document_count <= 200))),
    CONSTRAINT workspace_storage_usage_revision_plaintext_bytes_check CHECK (((revision_plaintext_bytes >= 0) AND (revision_plaintext_bytes <= '2147483648'::bigint))),
    CONSTRAINT workspace_storage_usage_row_version_check CHECK ((row_version > 0))
);

CREATE TABLE public.workspace_webhook_deliveries (
    id text NOT NULL,
    account_id text NOT NULL,
    event_id text NOT NULL,
    endpoint_id text NOT NULL,
    state text NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    next_attempt_at bigint NOT NULL,
    lease_owner text,
    lease_until bigint,
    last_http_status integer,
    last_error_category text,
    delivered_at bigint,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    CONSTRAINT workspace_webhook_deliveries_attempt_count_check CHECK (((attempt_count >= 0) AND (attempt_count <= 32))),
    CONSTRAINT workspace_webhook_deliveries_check CHECK ((updated_at >= created_at)),
    CONSTRAINT workspace_webhook_deliveries_created_at_check CHECK ((created_at > 0)),
    CONSTRAINT workspace_webhook_deliveries_id_check CHECK ((id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'::text)),
    CONSTRAINT workspace_webhook_deliveries_last_error_category_check CHECK (((last_error_category IS NULL) OR (last_error_category ~ '^[a-z][a-z0-9_]{0,63}$'::text))),
    CONSTRAINT workspace_webhook_deliveries_last_http_status_check CHECK (((last_http_status >= 100) AND (last_http_status <= 599))),
    CONSTRAINT workspace_webhook_deliveries_lease_owner_check CHECK (((lease_owner IS NULL) OR (lease_owner ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'::text))),
    CONSTRAINT workspace_webhook_deliveries_next_attempt_at_check CHECK ((next_attempt_at > 0)),
    CONSTRAINT workspace_webhook_deliveries_state_check CHECK ((state = ANY (ARRAY['pending'::text, 'in_flight'::text, 'delivered'::text, 'retry'::text, 'dead'::text]))),
    CONSTRAINT workspace_webhook_deliveries_state_fields_check CHECK ((((state = 'pending'::text) AND (attempt_count = 0) AND (lease_owner IS NULL) AND (lease_until IS NULL) AND (delivered_at IS NULL)) OR ((state = 'in_flight'::text) AND (attempt_count > 0) AND (lease_owner IS NOT NULL) AND (lease_until IS NOT NULL) AND (lease_until > updated_at) AND (delivered_at IS NULL)) OR ((state = 'retry'::text) AND (attempt_count > 0) AND (lease_owner IS NULL) AND (lease_until IS NULL) AND (delivered_at IS NULL)) OR ((state = 'delivered'::text) AND (attempt_count > 0) AND (lease_owner IS NULL) AND (lease_until IS NULL) AND (delivered_at IS NOT NULL) AND (last_http_status IS NOT NULL) AND ((last_http_status >= 200) AND (last_http_status <= 299))) OR ((state = 'dead'::text) AND (lease_owner IS NULL) AND (lease_until IS NULL) AND (delivered_at IS NULL))))
);

CREATE TABLE public.workspace_webhook_endpoints (
    id text NOT NULL,
    account_id text NOT NULL,
    name text NOT NULL,
    url text NOT NULL,
    event_types text[] NOT NULL,
    active boolean NOT NULL,
    secret_version integer NOT NULL,
    secret_key_id text NOT NULL,
    secret_nonce bytea NOT NULL,
    secret_ciphertext bytea NOT NULL,
    row_version bigint DEFAULT 1 NOT NULL,
    created_at bigint NOT NULL,
    updated_at bigint NOT NULL,
    deleted_at bigint,
    CONSTRAINT workspace_webhook_endpoints_check CHECK ((updated_at >= created_at)),
    CONSTRAINT workspace_webhook_endpoints_check1 CHECK (((deleted_at IS NULL) OR (deleted_at >= created_at))),
    CONSTRAINT workspace_webhook_endpoints_created_at_check CHECK ((created_at > 0)),
    CONSTRAINT workspace_webhook_endpoints_event_types_check CHECK ((((cardinality(event_types) >= 1) AND (cardinality(event_types) <= 32)) AND (array_position(event_types, NULL::text) IS NULL))),
    CONSTRAINT workspace_webhook_endpoints_name_check CHECK ((((char_length(name) >= 1) AND (char_length(name) <= 128)) AND (name = btrim(name)))),
    CONSTRAINT workspace_webhook_endpoints_row_version_check CHECK ((row_version > 0)),
    CONSTRAINT workspace_webhook_endpoints_secret_ciphertext_check CHECK (((octet_length(secret_ciphertext) >= 17) AND (octet_length(secret_ciphertext) <= 1024))),
    CONSTRAINT workspace_webhook_endpoints_secret_key_id_check CHECK (((char_length(secret_key_id) >= 1) AND (char_length(secret_key_id) <= 128))),
    CONSTRAINT workspace_webhook_endpoints_secret_nonce_check CHECK ((octet_length(secret_nonce) = 24)),
    CONSTRAINT workspace_webhook_endpoints_secret_version_check CHECK ((secret_version > 0)),
    CONSTRAINT workspace_webhook_endpoints_url_check CHECK ((((char_length(url) >= 1) AND (char_length(url) <= 2048)) AND ("left"(url, 8) = 'https://'::text) AND (POSITION(('?'::text) IN (url)) = 0) AND (POSITION(('#'::text) IN (url)) = 0)))
);

CREATE TABLE public.workspace_webhook_events (
    account_id text NOT NULL,
    event_id text NOT NULL,
    event_type text NOT NULL,
    payload bytea NOT NULL,
    created_at bigint NOT NULL,
    CONSTRAINT workspace_webhook_events_created_at_check CHECK ((created_at > 0)),
    CONSTRAINT workspace_webhook_events_event_id_check CHECK ((event_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'::text)),
    CONSTRAINT workspace_webhook_events_event_type_check CHECK ((((char_length(event_type) >= 1) AND (char_length(event_type) <= 64)) AND (event_type ~ '^[a-z][a-z0-9_.-]*$'::text) AND (event_type = ANY (ARRAY['alert.incident.acknowledged'::text, 'alert.incident.opened'::text, 'alert.incident.resolved'::text, 'configuration.created'::text, 'configuration.deleted'::text, 'configuration.published'::text, 'configuration.purged'::text, 'configuration.restored'::text, 'configuration.revised'::text, 'sync.conflict'::text])))),
    CONSTRAINT workspace_webhook_events_payload_check CHECK (((octet_length(payload) >= 2) AND (octet_length(payload) <= 131072)))
);

CREATE TABLE public.workspace_webhook_operations (
    account_id text NOT NULL,
    operation_id text NOT NULL,
    command text NOT NULL,
    request_hash text NOT NULL,
    endpoint_id text,
    response jsonb,
    created_at bigint NOT NULL,
    completed_at bigint,
    CONSTRAINT workspace_webhook_operations_check CHECK (((completed_at IS NULL) OR (completed_at >= created_at))),
    CONSTRAINT workspace_webhook_operations_command_check CHECK ((command = ANY (ARRAY['endpoint.create'::text, 'endpoint.update'::text, 'endpoint.rotate_secret'::text, 'endpoint.delete'::text]))),
    CONSTRAINT workspace_webhook_operations_completion_check CHECK ((((endpoint_id IS NULL) AND (response IS NULL) AND (completed_at IS NULL)) OR ((endpoint_id IS NOT NULL) AND (response IS NOT NULL) AND (jsonb_typeof(response) = 'object'::text) AND (COALESCE((response ->> 'id'::text), (response ->> 'endpointId'::text), ''::text) = endpoint_id) AND (completed_at IS NOT NULL)))),
    CONSTRAINT workspace_webhook_operations_created_at_check CHECK ((created_at > 0)),
    CONSTRAINT workspace_webhook_operations_operation_id_check CHECK ((operation_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'::text)),
    CONSTRAINT workspace_webhook_operations_request_hash_check CHECK ((request_hash ~ '^[0-9a-f]{64}$'::text))
);

ALTER TABLE ONLY public.workspace_changes ALTER COLUMN cursor SET DEFAULT nextval('public.workspace_changes_cursor_seq'::regclass);

ALTER TABLE ONLY public.accounts
    ADD CONSTRAINT accounts_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.activation_codes
    ADD CONSTRAINT activation_codes_pkey PRIMARY KEY (code_hash);

ALTER TABLE ONLY public.admin_bulk_job_items
    ADD CONSTRAINT admin_bulk_job_items_job_id_target_type_target_id_key UNIQUE (job_id, target_type, target_id);

ALTER TABLE ONLY public.admin_bulk_job_items
    ADD CONSTRAINT admin_bulk_job_items_pkey PRIMARY KEY (job_id, ordinal);

ALTER TABLE ONLY public.admin_bulk_jobs
    ADD CONSTRAINT admin_bulk_jobs_actor_id_idempotency_key_key UNIQUE (actor_id, idempotency_key);

ALTER TABLE ONLY public.admin_bulk_jobs
    ADD CONSTRAINT admin_bulk_jobs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.admin_bulk_previews
    ADD CONSTRAINT admin_bulk_previews_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.admin_enrollment_states
    ADD CONSTRAINT admin_enrollment_states_pkey PRIMARY KEY (token_hash);

ALTER TABLE ONLY public.admin_enrollment_tokens
    ADD CONSTRAINT admin_enrollment_tokens_pkey PRIMARY KEY (token_hash);

ALTER TABLE ONLY public.admin_login_buckets
    ADD CONSTRAINT admin_login_buckets_pkey PRIMARY KEY (bucket_key);

ALTER TABLE ONLY public.admin_operations
    ADD CONSTRAINT admin_operations_pkey PRIMARY KEY (operation_id);

ALTER TABLE ONLY public.admin_password_credentials
    ADD CONSTRAINT admin_password_credentials_pkey PRIMARY KEY (user_id);

ALTER TABLE ONLY public.admin_recovery_codes
    ADD CONSTRAINT admin_recovery_codes_pkey PRIMARY KEY (user_id, code_hash);

ALTER TABLE ONLY public.admin_role_bindings
    ADD CONSTRAINT admin_role_bindings_pkey PRIMARY KEY (user_id, role);

ALTER TABLE ONLY public.admin_secret_deliveries
    ADD CONSTRAINT admin_secret_deliveries_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.admin_sessions
    ADD CONSTRAINT admin_sessions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.admin_sessions
    ADD CONSTRAINT admin_sessions_token_hash_key UNIQUE (token_hash);

ALTER TABLE ONLY public.admin_totp_credentials
    ADD CONSTRAINT admin_totp_credentials_pkey PRIMARY KEY (user_id);

ALTER TABLE ONLY public.admin_users
    ADD CONSTRAINT admin_users_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.admin_users
    ADD CONSTRAINT admin_users_username_key UNIQUE (username);

ALTER TABLE ONLY public.audit_archive_manifests
    ADD CONSTRAINT audit_archive_manifests_period_start_period_end_key UNIQUE (period_start, period_end);

ALTER TABLE ONLY public.audit_archive_manifests
    ADD CONSTRAINT audit_archive_manifests_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.authorization_codes
    ADD CONSTRAINT authorization_codes_pkey PRIMARY KEY (code_hash);

ALTER TABLE ONLY public.billing_invoices
    ADD CONSTRAINT billing_invoices_payment_reference_key UNIQUE (payment_reference);

ALTER TABLE ONLY public.billing_invoices
    ADD CONSTRAINT billing_invoices_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.commercial_offers
    ADD CONSTRAINT commercial_offers_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.customer_payment_operations
    ADD CONSTRAINT customer_payment_operations_pkey PRIMARY KEY (account_id, operation_id);

ALTER TABLE ONLY public.device_challenges
    ADD CONSTRAINT device_challenges_pkey PRIMARY KEY (challenge_id);

ALTER TABLE ONLY public.device_member_bindings
    ADD CONSTRAINT device_member_bindings_pkey PRIMARY KEY (device_id);

ALTER TABLE ONLY public.devices
    ADD CONSTRAINT devices_pkey PRIMARY KEY (device_id);

ALTER TABLE ONLY public.licenses
    ADD CONSTRAINT licenses_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.manual_payment_claims
    ADD CONSTRAINT manual_payment_claims_payment_method_id_external_transactio_key UNIQUE (payment_method_id, external_transaction_id);

ALTER TABLE ONLY public.manual_payment_claims
    ADD CONSTRAINT manual_payment_claims_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.manual_payment_methods
    ADD CONSTRAINT manual_payment_methods_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.member_device_enrollments
    ADD CONSTRAINT member_device_enrollments_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.member_device_enrollments
    ADD CONSTRAINT member_device_enrollments_token_hash_key UNIQUE (token_hash);

ALTER TABLE ONLY public.payment_evidence_attachments
    ADD CONSTRAINT payment_evidence_attachments_claim_id_sha256_key UNIQUE (claim_id, sha256);

ALTER TABLE ONLY public.payment_evidence_attachments
    ADD CONSTRAINT payment_evidence_attachments_object_id_key UNIQUE (object_id);

ALTER TABLE ONLY public.payment_evidence_attachments
    ADD CONSTRAINT payment_evidence_attachments_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.rate_limit_buckets
    ADD CONSTRAINT rate_limit_buckets_pkey PRIMARY KEY (scope, bucket_key);

ALTER TABLE ONLY public.refresh_sessions
    ADD CONSTRAINT refresh_sessions_pkey PRIMARY KEY (token_hash);

ALTER TABLE ONLY public.service_time_authority
    ADD CONSTRAINT service_time_authority_pkey PRIMARY KEY (singleton);

ALTER TABLE ONLY public.stored_object_chunks
    ADD CONSTRAINT stored_object_chunks_pkey PRIMARY KEY (object_id, chunk_index);

ALTER TABLE ONLY public.stored_objects
    ADD CONSTRAINT stored_objects_backend_locator_key UNIQUE (backend, locator);

ALTER TABLE ONLY public.stored_objects
    ADD CONSTRAINT stored_objects_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.team_invitations
    ADD CONSTRAINT team_invitations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.team_invitations
    ADD CONSTRAINT team_invitations_token_hash_key UNIQUE (token_hash);

ALTER TABLE ONLY public.workspace_alert_incidents
    ADD CONSTRAINT workspace_alert_incidents_id_key UNIQUE (id);

ALTER TABLE ONLY public.workspace_alert_incidents
    ADD CONSTRAINT workspace_alert_incidents_pkey PRIMARY KEY (account_id, id);

ALTER TABLE ONLY public.workspace_alert_rules
    ADD CONSTRAINT workspace_alert_rules_id_key UNIQUE (id);

ALTER TABLE ONLY public.workspace_alert_rules
    ADD CONSTRAINT workspace_alert_rules_pkey PRIMARY KEY (account_id, id);

ALTER TABLE ONLY public.workspace_changes
    ADD CONSTRAINT workspace_changes_account_id_operation_id_change_kind_resou_key UNIQUE (account_id, operation_id, change_kind, resource_type, resource_id);

ALTER TABLE ONLY public.workspace_changes
    ADD CONSTRAINT workspace_changes_pkey PRIMARY KEY (cursor);

ALTER TABLE ONLY public.workspace_device_checkpoints
    ADD CONSTRAINT workspace_device_checkpoints_pkey PRIMARY KEY (account_id, device_id);

ALTER TABLE ONLY public.workspace_document_revisions
    ADD CONSTRAINT workspace_document_revisions_pkey PRIMARY KEY (account_id, document_id, revision);

ALTER TABLE ONLY public.workspace_documents
    ADD CONSTRAINT workspace_documents_id_key UNIQUE (id);

ALTER TABLE ONLY public.workspace_documents
    ADD CONSTRAINT workspace_documents_pkey PRIMARY KEY (account_id, id);

ALTER TABLE ONLY public.workspace_members
    ADD CONSTRAINT workspace_members_account_id_email_key UNIQUE (account_id, email);

ALTER TABLE ONLY public.workspace_members
    ADD CONSTRAINT workspace_members_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.workspace_operations
    ADD CONSTRAINT workspace_operations_pkey PRIMARY KEY (account_id, operation_id);

ALTER TABLE ONLY public.workspace_storage_usage
    ADD CONSTRAINT workspace_storage_usage_pkey PRIMARY KEY (account_id);

ALTER TABLE ONLY public.workspace_webhook_deliveries
    ADD CONSTRAINT workspace_webhook_deliveries_account_id_event_id_endpoint_i_key UNIQUE (account_id, event_id, endpoint_id);

ALTER TABLE ONLY public.workspace_webhook_deliveries
    ADD CONSTRAINT workspace_webhook_deliveries_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.workspace_webhook_endpoints
    ADD CONSTRAINT workspace_webhook_endpoints_account_id_id_key UNIQUE (account_id, id);

ALTER TABLE ONLY public.workspace_webhook_endpoints
    ADD CONSTRAINT workspace_webhook_endpoints_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.workspace_webhook_events
    ADD CONSTRAINT workspace_webhook_events_pkey PRIMARY KEY (account_id, event_id);

ALTER TABLE ONLY public.workspace_webhook_operations
    ADD CONSTRAINT workspace_webhook_operations_pkey PRIMARY KEY (account_id, operation_id);

CREATE INDEX accounts_id_lower_prefix_idx ON public.accounts USING btree (lower(id) text_pattern_ops);

CREATE INDEX activation_codes_account_id_idx ON public.activation_codes USING btree (account_id);

CREATE INDEX activation_codes_hash_account_idx ON public.activation_codes USING btree (code_hash, account_id);

CREATE INDEX activation_codes_license_id_idx ON public.activation_codes USING btree (license_id);

CREATE INDEX activation_codes_prefix_idx ON public.activation_codes USING btree (code_prefix);

CREATE INDEX activation_codes_status_expiry_idx ON public.activation_codes USING btree (status, expires_at, consumed);

CREATE INDEX admin_bulk_job_items_pending_idx ON public.admin_bulk_job_items USING btree (job_id, status, ordinal);

CREATE INDEX admin_bulk_jobs_queue_idx ON public.admin_bulk_jobs USING btree (status, created_at) WHERE (status = ANY (ARRAY['queued'::text, 'running'::text, 'cancel_requested'::text]));

CREATE INDEX admin_bulk_previews_expiry_idx ON public.admin_bulk_previews USING btree (expires_at) WHERE (consumed_at IS NULL);

CREATE INDEX admin_enrollment_tokens_expiry_idx ON public.admin_enrollment_tokens USING btree (expires_at) WHERE (consumed_at IS NULL);

CREATE INDEX admin_operations_created_at_idx ON public.admin_operations USING btree (created_at);

CREATE INDEX admin_secret_deliveries_expiry_idx ON public.admin_secret_deliveries USING btree (expires_at) WHERE (acknowledged_at IS NULL);

CREATE INDEX admin_sessions_expiry_idx ON public.admin_sessions USING btree (expires_at) WHERE (revoked_at IS NULL);

CREATE INDEX admin_sessions_user_active_idx ON public.admin_sessions USING btree (user_id, expires_at) WHERE (revoked_at IS NULL);

CREATE INDEX admin_users_status_username_idx ON public.admin_users USING btree (status, username);

CREATE INDEX audit_events_account_keyset_idx ON public.audit_events USING btree (account_id, occurred_at DESC, id DESC);

CREATE INDEX audit_events_account_time_idx ON public.audit_events USING btree (account_id, occurred_at DESC);

CREATE INDEX audit_events_actor_time_idx ON public.audit_events USING btree (actor_id, occurred_at DESC);

CREATE INDEX audit_events_device_time_idx ON public.audit_events USING btree (device_id, occurred_at DESC);

CREATE INDEX audit_events_outcome_time_idx ON public.audit_events USING btree (outcome, occurred_at DESC);

CREATE INDEX audit_events_target_time_idx ON public.audit_events USING btree (target_type, target_id, occurred_at DESC);

CREATE INDEX audit_events_type_time_idx ON public.audit_events USING btree (event_type, occurred_at DESC);

CREATE INDEX authorization_codes_account_id_idx ON public.authorization_codes USING btree (account_id);

CREATE INDEX authorization_codes_activation_code_hash_idx ON public.authorization_codes USING btree (activation_code_hash);

CREATE INDEX authorization_codes_expiry_idx ON public.authorization_codes USING btree (expires_at, consumed);

CREATE INDEX billing_invoices_account_status_idx ON public.billing_invoices USING btree (account_id, status, created_at DESC);

CREATE INDEX customer_payment_operations_claim_idx ON public.customer_payment_operations USING btree (claim_id) WHERE (claim_id IS NOT NULL);

CREATE INDEX device_challenges_expiry_idx ON public.device_challenges USING btree (expires_at, consumed);

CREATE INDEX device_challenges_subject_expiry_idx ON public.device_challenges USING btree (device_id, expires_at, consumed);

CREATE INDEX device_member_bindings_member_idx ON public.device_member_bindings USING btree (member_id);

CREATE UNIQUE INDEX devices_account_device_unique_idx ON public.devices USING btree (account_id, device_id);

CREATE INDEX devices_account_id_idx ON public.devices USING btree (account_id);

CREATE INDEX devices_id_lower_prefix_idx ON public.devices USING btree (lower(device_id) text_pattern_ops);

CREATE INDEX devices_license_active_idx ON public.devices USING btree (license_id, state);

CREATE INDEX devices_license_device_id_idx ON public.devices USING btree (license_id, device_id COLLATE "C");

CREATE INDEX licenses_account_id_idx ON public.licenses USING btree (account_id);

CREATE UNIQUE INDEX licenses_one_per_account_idx ON public.licenses USING btree (account_id);

CREATE INDEX licenses_plan_revision_idx ON public.licenses USING btree (plan, plan_revision);

CREATE UNIQUE INDEX manual_payment_claims_one_open_per_invoice_idx ON public.manual_payment_claims USING btree (invoice_id) WHERE (status = ANY (ARRAY['submitted'::text, 'under_review'::text, 'needs_information'::text]));

CREATE INDEX manual_payment_claims_review_queue_idx ON public.manual_payment_claims USING btree (status, created_at);

CREATE INDEX member_device_enrollments_member_idx ON public.member_device_enrollments USING btree (member_id, created_at DESC, id);

CREATE UNIQUE INDEX member_device_enrollments_one_open_per_member_idx ON public.member_device_enrollments USING btree (member_id) WHERE ((consumed_at IS NULL) AND (revoked_at IS NULL));

CREATE INDEX payment_evidence_claim_idx ON public.payment_evidence_attachments USING btree (claim_id, created_at);

CREATE INDEX rate_limit_buckets_window_idx ON public.rate_limit_buckets USING btree (window_started_at);

CREATE INDEX refresh_sessions_active_expiry_idx ON public.refresh_sessions USING btree (active, expires_at);

CREATE INDEX refresh_sessions_device_active_idx ON public.refresh_sessions USING btree (device_id, active);

CREATE INDEX refresh_sessions_family_id_idx ON public.refresh_sessions USING btree (family_id);

CREATE UNIQUE INDEX refresh_sessions_one_active_proven_per_device_idx ON public.refresh_sessions USING btree (device_id) WHERE (active AND (proof_state = 'device_proven'::text));

CREATE INDEX stored_objects_backend_status_idx ON public.stored_objects USING btree (backend, status, created_at);

CREATE INDEX stored_objects_namespace_time_idx ON public.stored_objects USING btree (namespace, created_at DESC);

CREATE INDEX team_invitations_account_expiry_idx ON public.team_invitations USING btree (account_id, expires_at DESC) WHERE ((accepted_at IS NULL) AND (revoked_at IS NULL));

CREATE UNIQUE INDEX team_invitations_one_open_per_member_idx ON public.team_invitations USING btree (member_id) WHERE ((accepted_at IS NULL) AND (revoked_at IS NULL));

CREATE INDEX workspace_alert_incidents_account_status_time_idx ON public.workspace_alert_incidents USING btree (account_id, status, occurred_at DESC, id DESC);

CREATE INDEX workspace_alert_incidents_account_time_idx ON public.workspace_alert_incidents USING btree (account_id, occurred_at DESC, id DESC);

CREATE UNIQUE INDEX workspace_alert_incidents_active_dedupe_idx ON public.workspace_alert_incidents USING btree (account_id, rule_id, dedupe_key) WHERE (status = ANY (ARRAY['open'::text, 'acknowledged'::text]));

CREATE INDEX workspace_alert_rules_account_active_idx ON public.workspace_alert_rules USING btree (account_id, created_at DESC, id DESC) WHERE (deleted_at IS NULL);

CREATE INDEX workspace_changes_account_cursor_idx ON public.workspace_changes USING btree (account_id, cursor);

CREATE INDEX workspace_documents_account_active_time_idx ON public.workspace_documents USING btree (account_id, updated_at DESC, id DESC) WHERE (deleted_at IS NULL);

CREATE INDEX workspace_documents_account_deleted_time_idx ON public.workspace_documents USING btree (account_id, updated_at DESC, id DESC) WHERE (deleted_at IS NOT NULL);

CREATE INDEX workspace_members_account_status_idx ON public.workspace_members USING btree (account_id, status, created_at, id);

CREATE UNIQUE INDEX workspace_members_one_owner_per_account_idx ON public.workspace_members USING btree (account_id) WHERE (role = 'owner'::text);

CREATE INDEX workspace_operations_account_time_idx ON public.workspace_operations USING btree (account_id, created_at DESC, operation_id DESC);

CREATE INDEX workspace_webhook_deliveries_claim_idx ON public.workspace_webhook_deliveries USING btree (state, next_attempt_at, created_at, id) WHERE (state = ANY (ARRAY['pending'::text, 'retry'::text]));

CREATE INDEX workspace_webhook_deliveries_expiry_idx ON public.workspace_webhook_deliveries USING btree (created_at, id) WHERE (state = ANY (ARRAY['pending'::text, 'retry'::text, 'in_flight'::text]));

CREATE INDEX workspace_webhook_deliveries_history_idx ON public.workspace_webhook_deliveries USING btree (account_id, created_at DESC, id DESC);

CREATE INDEX workspace_webhook_deliveries_lease_idx ON public.workspace_webhook_deliveries USING btree (lease_until, id) WHERE (state = 'in_flight'::text);

CREATE INDEX workspace_webhook_endpoints_cleanup_idx ON public.workspace_webhook_endpoints USING btree (deleted_at, account_id, id) WHERE (deleted_at IS NOT NULL);

CREATE INDEX workspace_webhook_events_cleanup_idx ON public.workspace_webhook_events USING btree (created_at, account_id, event_id);

CREATE INDEX workspace_webhook_operations_cleanup_idx ON public.workspace_webhook_operations USING btree (completed_at, account_id, operation_id) WHERE (completed_at IS NOT NULL);

CREATE INDEX workspace_webhook_operations_endpoint_idx ON public.workspace_webhook_operations USING btree (account_id, endpoint_id) WHERE (endpoint_id IS NOT NULL);

CREATE TRIGGER accounts_workspace_owner_after_insert AFTER INSERT ON public.accounts FOR EACH ROW EXECUTE FUNCTION public.ensure_workspace_owner_for_account();

CREATE TRIGGER device_member_bindings_limit_before_write BEFORE INSERT OR UPDATE OF member_id ON public.device_member_bindings FOR EACH ROW EXECUTE FUNCTION public.enforce_workspace_member_device_limit();

CREATE TRIGGER devices_workspace_owner_after_insert AFTER INSERT ON public.devices FOR EACH ROW EXECUTE FUNCTION public.bind_first_workspace_device_to_owner();

CREATE TRIGGER workspace_webhook_delivery_transition_trigger BEFORE UPDATE OF state ON public.workspace_webhook_deliveries FOR EACH ROW EXECUTE FUNCTION public.enforce_workspace_webhook_delivery_transition();

CREATE TRIGGER workspace_webhook_endpoint_limit_trigger BEFORE INSERT OR UPDATE OF deleted_at ON public.workspace_webhook_endpoints FOR EACH ROW EXECUTE FUNCTION public.enforce_workspace_webhook_endpoint_limit();

CREATE TRIGGER workspace_webhook_event_types_trigger BEFORE INSERT OR UPDATE OF event_types ON public.workspace_webhook_endpoints FOR EACH ROW EXECUTE FUNCTION public.validate_workspace_webhook_event_types();

ALTER TABLE ONLY public.activation_codes
    ADD CONSTRAINT activation_codes_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.activation_codes
    ADD CONSTRAINT activation_codes_license_id_fkey FOREIGN KEY (license_id) REFERENCES public.licenses(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.admin_bulk_job_items
    ADD CONSTRAINT admin_bulk_job_items_job_id_fkey FOREIGN KEY (job_id) REFERENCES public.admin_bulk_jobs(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.admin_bulk_jobs
    ADD CONSTRAINT admin_bulk_jobs_actor_id_fkey FOREIGN KEY (actor_id) REFERENCES public.admin_users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.admin_bulk_jobs
    ADD CONSTRAINT admin_bulk_jobs_parent_job_id_fkey FOREIGN KEY (parent_job_id) REFERENCES public.admin_bulk_jobs(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.admin_bulk_jobs
    ADD CONSTRAINT admin_bulk_jobs_session_id_fkey FOREIGN KEY (session_id) REFERENCES public.admin_sessions(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.admin_bulk_previews
    ADD CONSTRAINT admin_bulk_previews_actor_id_fkey FOREIGN KEY (actor_id) REFERENCES public.admin_users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.admin_enrollment_states
    ADD CONSTRAINT admin_enrollment_states_token_hash_fkey FOREIGN KEY (token_hash) REFERENCES public.admin_enrollment_tokens(token_hash) ON DELETE CASCADE;

ALTER TABLE ONLY public.admin_enrollment_tokens
    ADD CONSTRAINT admin_enrollment_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.admin_users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.admin_password_credentials
    ADD CONSTRAINT admin_password_credentials_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.admin_users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.admin_recovery_codes
    ADD CONSTRAINT admin_recovery_codes_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.admin_users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.admin_role_bindings
    ADD CONSTRAINT admin_role_bindings_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.admin_users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.admin_secret_deliveries
    ADD CONSTRAINT admin_secret_deliveries_actor_id_fkey FOREIGN KEY (actor_id) REFERENCES public.admin_users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.admin_secret_deliveries
    ADD CONSTRAINT admin_secret_deliveries_session_id_fkey FOREIGN KEY (session_id) REFERENCES public.admin_sessions(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.admin_sessions
    ADD CONSTRAINT admin_sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.admin_users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.admin_totp_credentials
    ADD CONSTRAINT admin_totp_credentials_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.admin_users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.audit_archive_manifests
    ADD CONSTRAINT audit_archive_manifests_object_id_fkey FOREIGN KEY (object_id) REFERENCES public.stored_objects(id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.billing_invoices
    ADD CONSTRAINT billing_invoices_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.billing_invoices
    ADD CONSTRAINT billing_invoices_license_id_fkey FOREIGN KEY (license_id) REFERENCES public.licenses(id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.billing_invoices
    ADD CONSTRAINT billing_invoices_offer_id_fkey FOREIGN KEY (offer_id) REFERENCES public.commercial_offers(id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.customer_payment_operations
    ADD CONSTRAINT customer_payment_operations_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.customer_payment_operations
    ADD CONSTRAINT customer_payment_operations_claim_id_fkey FOREIGN KEY (claim_id) REFERENCES public.manual_payment_claims(id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.device_member_bindings
    ADD CONSTRAINT device_member_bindings_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.devices(device_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.device_member_bindings
    ADD CONSTRAINT device_member_bindings_member_id_fkey FOREIGN KEY (member_id) REFERENCES public.workspace_members(id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.devices
    ADD CONSTRAINT devices_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.devices
    ADD CONSTRAINT devices_license_id_fkey FOREIGN KEY (license_id) REFERENCES public.licenses(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.licenses
    ADD CONSTRAINT licenses_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.manual_payment_claims
    ADD CONSTRAINT manual_payment_claims_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.manual_payment_claims
    ADD CONSTRAINT manual_payment_claims_invoice_id_fkey FOREIGN KEY (invoice_id) REFERENCES public.billing_invoices(id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.manual_payment_claims
    ADD CONSTRAINT manual_payment_claims_payment_method_id_fkey FOREIGN KEY (payment_method_id) REFERENCES public.manual_payment_methods(id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.member_device_enrollments
    ADD CONSTRAINT member_device_enrollments_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.member_device_enrollments
    ADD CONSTRAINT member_device_enrollments_created_by_device_id_fkey FOREIGN KEY (created_by_device_id) REFERENCES public.devices(device_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.member_device_enrollments
    ADD CONSTRAINT member_device_enrollments_member_id_fkey FOREIGN KEY (member_id) REFERENCES public.workspace_members(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.payment_evidence_attachments
    ADD CONSTRAINT payment_evidence_attachments_claim_id_fkey FOREIGN KEY (claim_id) REFERENCES public.manual_payment_claims(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.payment_evidence_attachments
    ADD CONSTRAINT payment_evidence_attachments_object_id_fkey FOREIGN KEY (object_id) REFERENCES public.stored_objects(id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.stored_object_chunks
    ADD CONSTRAINT stored_object_chunks_object_id_fkey FOREIGN KEY (object_id) REFERENCES public.stored_objects(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.team_invitations
    ADD CONSTRAINT team_invitations_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.team_invitations
    ADD CONSTRAINT team_invitations_invited_by_admin_user_id_fkey FOREIGN KEY (invited_by_admin_user_id) REFERENCES public.admin_users(id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.team_invitations
    ADD CONSTRAINT team_invitations_invited_by_member_id_fkey FOREIGN KEY (invited_by_member_id) REFERENCES public.workspace_members(id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.team_invitations
    ADD CONSTRAINT team_invitations_member_id_fkey FOREIGN KEY (member_id) REFERENCES public.workspace_members(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_alert_incidents
    ADD CONSTRAINT workspace_alert_incidents_account_id_acknowledged_by_devic_fkey FOREIGN KEY (account_id, acknowledged_by_device_id) REFERENCES public.devices(account_id, device_id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.workspace_alert_incidents
    ADD CONSTRAINT workspace_alert_incidents_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_alert_incidents
    ADD CONSTRAINT workspace_alert_incidents_account_id_resolved_by_device_id_fkey FOREIGN KEY (account_id, resolved_by_device_id) REFERENCES public.devices(account_id, device_id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.workspace_alert_incidents
    ADD CONSTRAINT workspace_alert_incidents_account_id_rule_id_fkey FOREIGN KEY (account_id, rule_id) REFERENCES public.workspace_alert_rules(account_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.workspace_alert_rules
    ADD CONSTRAINT workspace_alert_rules_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_changes
    ADD CONSTRAINT workspace_changes_account_id_device_id_fkey FOREIGN KEY (account_id, device_id) REFERENCES public.devices(account_id, device_id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.workspace_changes
    ADD CONSTRAINT workspace_changes_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_device_checkpoints
    ADD CONSTRAINT workspace_device_checkpoints_account_id_device_id_fkey FOREIGN KEY (account_id, device_id) REFERENCES public.devices(account_id, device_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_device_checkpoints
    ADD CONSTRAINT workspace_device_checkpoints_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_document_revisions
    ADD CONSTRAINT workspace_document_revisions_account_id_created_by_device__fkey FOREIGN KEY (account_id, created_by_device_id) REFERENCES public.devices(account_id, device_id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.workspace_document_revisions
    ADD CONSTRAINT workspace_document_revisions_account_id_document_id_fkey FOREIGN KEY (account_id, document_id) REFERENCES public.workspace_documents(account_id, id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_documents
    ADD CONSTRAINT workspace_documents_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_documents
    ADD CONSTRAINT workspace_documents_draft_revision_fk FOREIGN KEY (account_id, id, draft_revision) REFERENCES public.workspace_document_revisions(account_id, document_id, revision) DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY public.workspace_documents
    ADD CONSTRAINT workspace_documents_published_revision_fk FOREIGN KEY (account_id, id, published_revision) REFERENCES public.workspace_document_revisions(account_id, document_id, revision) DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY public.workspace_members
    ADD CONSTRAINT workspace_members_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_operations
    ADD CONSTRAINT workspace_operations_account_id_device_id_fkey FOREIGN KEY (account_id, device_id) REFERENCES public.devices(account_id, device_id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.workspace_operations
    ADD CONSTRAINT workspace_operations_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_storage_usage
    ADD CONSTRAINT workspace_storage_usage_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_webhook_deliveries
    ADD CONSTRAINT workspace_webhook_deliveries_account_id_endpoint_id_fkey FOREIGN KEY (account_id, endpoint_id) REFERENCES public.workspace_webhook_endpoints(account_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.workspace_webhook_deliveries
    ADD CONSTRAINT workspace_webhook_deliveries_account_id_event_id_fkey FOREIGN KEY (account_id, event_id) REFERENCES public.workspace_webhook_events(account_id, event_id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_webhook_deliveries
    ADD CONSTRAINT workspace_webhook_deliveries_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_webhook_endpoints
    ADD CONSTRAINT workspace_webhook_endpoints_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_webhook_events
    ADD CONSTRAINT workspace_webhook_events_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.workspace_webhook_operations
    ADD CONSTRAINT workspace_webhook_operations_account_id_endpoint_id_fkey FOREIGN KEY (account_id, endpoint_id) REFERENCES public.workspace_webhook_endpoints(account_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.workspace_webhook_operations
    ADD CONSTRAINT workspace_webhook_operations_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;

-- The trusted-time singleton is required before every long-lived runtime role starts.
INSERT INTO public.service_time_authority (
    singleton,
    high_water_unix,
    last_database_unix,
    status
)
SELECT 1, observed_unix, observed_unix, 'healthy'
FROM (
    SELECT floor(extract(epoch FROM clock_timestamp()))::BIGINT AS observed_unix
) AS observed;

-- Pre-release Team device-integrity baseline.
ALTER TABLE device_member_bindings
    ADD COLUMN account_id TEXT;

UPDATE device_member_bindings AS bindings
SET account_id = members.account_id
FROM workspace_members AS members
WHERE members.id = bindings.member_id;

ALTER TABLE device_member_bindings
    ALTER COLUMN account_id SET NOT NULL;

DELETE FROM device_member_bindings AS bindings
USING devices
WHERE devices.device_id = bindings.device_id
  AND devices.state <> 'active';

ALTER TABLE devices
    ADD CONSTRAINT devices_account_device_key UNIQUE (account_id, device_id);

ALTER TABLE workspace_members
    ADD CONSTRAINT workspace_members_account_member_key UNIQUE (account_id, id);

ALTER TABLE device_member_bindings
    ADD CONSTRAINT device_member_bindings_account_id_fkey
        FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    ADD CONSTRAINT device_member_bindings_account_device_fkey
        FOREIGN KEY (account_id, device_id)
        REFERENCES devices(account_id, device_id) ON DELETE CASCADE,
    ADD CONSTRAINT device_member_bindings_account_member_fkey
        FOREIGN KEY (account_id, member_id)
        REFERENCES workspace_members(account_id, id) ON DELETE RESTRICT;

CREATE INDEX device_member_bindings_account_member_idx
    ON device_member_bindings (account_id, member_id);

CREATE FUNCTION public.require_active_team_device_binding() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    device_state TEXT;
BEGIN
    SELECT state INTO device_state
    FROM devices
    WHERE account_id = NEW.account_id AND device_id = NEW.device_id
    FOR SHARE;
    IF device_state IS DISTINCT FROM 'active' THEN
        RAISE EXCEPTION 'workspace member bindings require an active device'
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'device_member_bindings_active_device';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER device_member_bindings_active_device_before_write
    BEFORE INSERT OR UPDATE OF account_id, device_id ON device_member_bindings
    FOR EACH ROW EXECUTE FUNCTION public.require_active_team_device_binding();

CREATE FUNCTION public.remove_inactive_team_device_binding() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.state <> 'active' THEN
        DELETE FROM device_member_bindings
        WHERE account_id = NEW.account_id AND device_id = NEW.device_id;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER devices_remove_inactive_team_binding_after_update
    AFTER UPDATE OF state ON devices
    FOR EACH ROW
    WHEN (OLD.state IS DISTINCT FROM NEW.state)
    EXECUTE FUNCTION public.remove_inactive_team_device_binding();

CREATE TABLE device_removal_operations (
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    operation_id TEXT NOT NULL,
    requester_session_hash TEXT NOT NULL,
    requester_device_id TEXT NOT NULL,
    target_device_id TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (account_id, operation_id),
    CONSTRAINT device_removal_operations_operation_id_check
        CHECK (operation_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    CONSTRAINT device_removal_operations_session_hash_check
        CHECK (requester_session_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT device_removal_operations_created_at_check
        CHECK (created_at > 0),
    CONSTRAINT device_removal_operations_requester_fkey
        FOREIGN KEY (account_id, requester_device_id)
        REFERENCES devices(account_id, device_id) ON DELETE CASCADE,
    CONSTRAINT device_removal_operations_target_fkey
        FOREIGN KEY (account_id, target_device_id)
        REFERENCES devices(account_id, device_id) ON DELETE CASCADE
);

CREATE INDEX device_removal_operations_created_idx
    ON device_removal_operations (created_at);

CREATE OR REPLACE FUNCTION public.bind_first_workspace_device_to_owner() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    owner_id TEXT;
    observed_at BIGINT;
BEGIN
    IF NEW.state <> 'active' THEN
        RETURN NEW;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.account_id, 7102026));
    SELECT id INTO owner_id
    FROM workspace_members
    WHERE account_id = NEW.account_id AND role = 'owner' AND status = 'active'
    ORDER BY created_at, id
    LIMIT 1;
    IF owner_id IS NULL THEN
        RETURN NEW;
    END IF;
    observed_at := COALESCE((NEW.document ->> 'last_seen_at')::BIGINT,
                           (NEW.document ->> 'created_at')::BIGINT, 0);
    IF observed_at <= 0 THEN
        RAISE EXCEPTION 'device domain timestamp is required'
            USING ERRCODE = 'check_violation', CONSTRAINT = 'device_domain_timestamp';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM device_member_bindings
        WHERE account_id = NEW.account_id
    ) THEN
        INSERT INTO device_member_bindings (account_id, device_id, member_id, bound_at)
        VALUES (NEW.account_id, NEW.device_id, owner_id, observed_at)
        ON CONFLICT (device_id) DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER devices_workspace_owner_after_insert ON devices;

CREATE TRIGGER devices_workspace_owner_after_insert
    AFTER INSERT OR UPDATE OF state ON devices
    FOR EACH ROW
    WHEN (NEW.state = 'active')
    EXECUTE FUNCTION public.bind_first_workspace_device_to_owner();

-- Pre-release idempotent Team operation baseline.
CREATE TABLE team_operations (
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    operation_id TEXT NOT NULL,
    requester_session_hash TEXT NOT NULL,
    requester_device_id TEXT NOT NULL,
    command TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    response_key_id TEXT NOT NULL,
    response_nonce BYTEA NOT NULL,
    response_ciphertext BYTEA NOT NULL,
    created_at BIGINT NOT NULL,
    completed_at BIGINT NOT NULL,
    PRIMARY KEY (account_id, operation_id),
    CONSTRAINT team_operations_operation_id_check
        CHECK (operation_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    CONSTRAINT team_operations_session_hash_check
        CHECK (requester_session_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT team_operations_device_id_check
        CHECK (requester_device_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    CONSTRAINT team_operations_command_check
        CHECK (command ~ '^[a-z][a-z0-9_]{0,63}$'),
    CONSTRAINT team_operations_request_hash_check
        CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT team_operations_response_key_id_check
        CHECK (response_key_id ~ '^[A-Za-z0-9._-]{1,128}$'),
    CONSTRAINT team_operations_response_nonce_check
        CHECK (octet_length(response_nonce) = 24),
    CONSTRAINT team_operations_response_ciphertext_check
        CHECK (octet_length(response_ciphertext) BETWEEN 17 AND 131088),
    CONSTRAINT team_operations_created_at_check
        CHECK (created_at > 0),
    CONSTRAINT team_operations_completed_at_check
        CHECK (completed_at >= created_at),
    CONSTRAINT team_operations_requester_fkey
        FOREIGN KEY (account_id, requester_device_id)
        REFERENCES devices(account_id, device_id) ON DELETE CASCADE
);

CREATE INDEX team_operations_cleanup_idx
    ON team_operations (completed_at, account_id, operation_id);

CREATE INDEX team_operations_response_key_idx
    ON team_operations (response_key_id);

CREATE INDEX audit_events_global_keyset_idx
    ON audit_events (occurred_at DESC, id DESC);
