SET app.current_tenant_id = 'TENANT_UUID';

-- ENABLE RLS ON CORE TABLES
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE job_definitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE job_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_analyses ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediations ENABLE ROW LEVEL SECURITY;
ALTER TABLE approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;

-- HELPER: CURRENT TENANT FUNCTION
CREATE OR REPLACE FUNCTION current_tenant_id()
RETURNS UUID AS $$
BEGIN
    RETURN current_setting('app.current_tenant_id')::UUID;
EXCEPTION
    WHEN others THEN
        RETURN NULL;
END;
$$ LANGUAGE plpgsql STABLE;

-- TENANTS (self-access only)
CREATE POLICY tenant_isolation ON tenants
FOR SELECT
USING (id = current_tenant_id());

-- USERS
CREATE POLICY user_tenant_isolation ON users
FOR ALL
USING (tenant_id = current_tenant_id());

-- JOB DEFINITIONS
CREATE POLICY job_def_tenant_isolation ON job_definitions
FOR ALL
USING (tenant_id = current_tenant_id());

-- JOB EXECUTIONS (via job_definitions)
CREATE POLICY job_exec_tenant_isolation ON job_executions
FOR ALL
USING (
    job_definition_id IN (
        SELECT id FROM job_definitions
        WHERE tenant_id = current_tenant_id()
    )
);

-- FINDINGS
CREATE POLICY findings_tenant_isolation ON findings
FOR ALL
USING (
    job_execution_id IN (
        SELECT je.id
        FROM job_executions je
        JOIN job_definitions jd ON je.job_definition_id = jd.id
        WHERE jd.tenant_id = current_tenant_id()
    )
);

-- EVIDENCE/AI/REMEDIATIONS/APPROVALS
CREATE POLICY evidence_tenant_isolation ON evidence
FOR ALL
USING (
    finding_id IN (
        SELECT f.id FROM findings f
        JOIN job_executions je ON f.job_execution_id = je.id
        JOIN job_definitions jd ON je.job_definition_id = jd.id
        WHERE jd.tenant_id = current_tenant_id()
    )
);

CREATE POLICY ai_analysis_tenant_isolation ON ai_analyses
FOR ALL
USING (
    finding_id IN (SELECT id FROM findings)
);

CREATE POLICY remediation_tenant_isolation ON remediations
FOR ALL
USING (
    finding_id IN (SELECT id FROM findings)
);

CREATE POLICY approvals_tenant_isolation ON approvals
FOR ALL
USING (
    finding_id IN (SELECT id FROM findings)
);

-- AUDIT EVENTS
CREATE POLICY audit_tenant_isolation ON audit_events
FOR ALL
USING (tenant_id = current_tenant_id());