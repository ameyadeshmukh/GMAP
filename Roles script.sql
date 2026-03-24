-- CREATE ROLES
CREATE ROLE app_admin;
CREATE ROLE app_user;
CREATE ROLE readonly_auditor;

-- GRANT CONNECTION
GRANT CONNECT ON DATABASE postgres TO app_admin, app_user, readonly_auditor;

-- SCHEMA ACCESS
GRANT USAGE ON SCHEMA public TO app_admin, app_user, readonly_auditor;

-- ADMIN (FULL ACCESS)
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO app_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO app_admin;

-- Future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public
GRANT ALL ON TABLES TO app_admin;

-- APP USER (LIMITED WRITE)
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO app_user;

REVOKE DELETE ON audit_events FROM app_user;
REVOKE DELETE ON compliance_ledger FROM app_user;

-- Prevent audit tampering
REVOKE UPDATE ON audit_events FROM app_user;
REVOKE UPDATE ON compliance_ledger FROM app_user;

-- READ-ONLY AUDITOR
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly_auditor;

REVOKE INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public FROM readonly_auditor;

-- FUNCTION ACCESS
GRANT EXECUTE ON FUNCTION current_tenant_id() TO app_user, readonly_auditor;

