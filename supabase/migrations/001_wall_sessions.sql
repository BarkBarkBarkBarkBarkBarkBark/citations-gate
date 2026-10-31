-- Apply with the database deployment account. No service-role key in Vercel.
-- The already-exposed hosaka_citations schema hosts RPCs, NOT the private table.
BEGIN;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'citations_gate_session_owner') THEN
    CREATE ROLE citations_gate_session_owner NOLOGIN;
  END IF;
  EXECUTE format('GRANT citations_gate_session_owner TO %I', current_user);
END $$;
CREATE SCHEMA IF NOT EXISTS citations_gate_private AUTHORIZATION citations_gate_session_owner;
REVOKE ALL ON SCHEMA citations_gate_private FROM PUBLIC, anon, authenticated;
GRANT USAGE, CREATE ON SCHEMA hosaka_citations TO citations_gate_session_owner;
GRANT USAGE ON SCHEMA hosaka_citations TO anon, authenticated;

CREATE TABLE IF NOT EXISTS citations_gate_private.wall_sessions (
  scope text PRIMARY KEY CHECK (length(scope) BETWEEN 1 AND 128),
  secret_hash bytea NOT NULL CHECK (octet_length(secret_hash) = 32),
  record text CHECK (octet_length(record) <= 32768),
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE citations_gate_private.wall_sessions OWNER TO citations_gate_session_owner;
ALTER TABLE citations_gate_private.wall_sessions ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON citations_gate_private.wall_sessions FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION hosaka_citations.cg_wall_session_read(p_scope text, p_secret text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE result text;
BEGIN
  IF p_secret IS NULL OR p_secret !~ '^[a-f0-9]{64}$' OR p_scope IS NULL OR length(p_scope) > 128 THEN
    RAISE EXCEPTION 'session store access denied' USING ERRCODE = '28000';
  END IF;
  SELECT s.record INTO result FROM citations_gate_private.wall_sessions s
    WHERE s.scope = p_scope AND s.secret_hash = sha256(convert_to(p_secret, 'UTF8'));
  IF NOT FOUND THEN
    RAISE EXCEPTION 'session store access denied' USING ERRCODE = '28000';
  END IF;
  RETURN result;
END $$;
ALTER FUNCTION hosaka_citations.cg_wall_session_read(text,text) OWNER TO citations_gate_session_owner;

CREATE OR REPLACE FUNCTION hosaka_citations.cg_wall_session_cas(
  p_scope text, p_secret text, p_expected text, p_next text
) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE changed integer;
BEGIN
  IF p_secret IS NULL OR p_secret !~ '^[a-f0-9]{64}$' OR p_scope IS NULL OR length(p_scope) > 128 THEN
    RAISE EXCEPTION 'session store access denied' USING ERRCODE = '28000';
  END IF;
  IF p_next IS NULL OR octet_length(p_next) > 32768 OR octet_length(p_expected) > 32768 THEN
    RAISE EXCEPTION 'invalid session record' USING ERRCODE = '22023';
  END IF;
  -- PostgreSQL atomically checks the expected version while holding the row lock.
  UPDATE citations_gate_private.wall_sessions s SET record = p_next, updated_at = now()
    WHERE s.scope = p_scope AND s.secret_hash = sha256(convert_to(p_secret, 'UTF8'))
      AND s.record IS NOT DISTINCT FROM p_expected;
  GET DIAGNOSTICS changed = ROW_COUNT;
  IF changed = 1 THEN RETURN true; END IF;
  IF NOT EXISTS (SELECT 1 FROM citations_gate_private.wall_sessions s
    WHERE s.scope = p_scope AND s.secret_hash = sha256(convert_to(p_secret, 'UTF8'))) THEN
    RAISE EXCEPTION 'session store access denied' USING ERRCODE = '28000';
  END IF;
  RETURN false;
END $$;
ALTER FUNCTION hosaka_citations.cg_wall_session_cas(text,text,text,text) OWNER TO citations_gate_session_owner;
REVOKE ALL ON FUNCTION hosaka_citations.cg_wall_session_read(text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION hosaka_citations.cg_wall_session_cas(text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION hosaka_citations.cg_wall_session_read(text,text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION hosaka_citations.cg_wall_session_cas(text,text,text,text) TO anon, authenticated;
REVOKE CREATE ON SCHEMA hosaka_citations FROM citations_gate_session_owner;
NOTIFY pgrst, 'reload schema';
COMMIT;
