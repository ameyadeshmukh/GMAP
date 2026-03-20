-- SEED REASONING POLICIES
INSERT INTO reasoning_storage_policies (id, mode, retain_raw_prompt, retain_chain_of_thought)
VALUES
(gen_random_uuid(), 'full', true, true),
(gen_random_uuid(), 'partial', true, false),
(gen_random_uuid(), 'summary_only', false, false);


-- SEED TENANTS
INSERT INTO tenants (id, name, subscription_tier, reasoning_policy_id)
SELECT gen_random_uuid(), 'Tenant A', 'enterprise', id FROM reasoning_storage_policies LIMIT 1;

INSERT INTO tenants (id, name, subscription_tier, reasoning_policy_id)
SELECT gen_random_uuid(), 'Tenant B', 'pro', id FROM reasoning_storage_policies OFFSET 1 LIMIT 1;


-- SEED USERS
INSERT INTO users (id, tenant_id, email, role)
SELECT gen_random_uuid(), t.id, 'admin@tenanta.com', 'admin'
FROM tenants t WHERE t.name = 'Tenant A';

INSERT INTO users (id, tenant_id, email, role)
SELECT gen_random_uuid(), t.id, 'analyst@tenanta.com', 'analyst'
FROM tenants t WHERE t.name = 'Tenant A';

INSERT INTO users (id, tenant_id, email, role)
SELECT gen_random_uuid(), t.id, 'admin@tenantb.com', 'admin'
FROM tenants t WHERE t.name = 'Tenant B';


-- SEED TARGETS
INSERT INTO targets (id, type, value, environment, owner)
VALUES
(gen_random_uuid(), 'ip', '192.168.1.10', 'internal', 'DevOps'),
(gen_random_uuid(), 'domain', 'example.com', 'production', 'Web Team'),
(gen_random_uuid(), 'container', 'vuln-applatest', 'staging', 'Security Team');


-- SEED JOB DEFINITIONS
INSERT INTO job_definitions (id, tenant_id, target_id, created_by, name, version_number)
SELECT
    gen_random_uuid(),
    t.id,
    (SELECT id FROM targets LIMIT 1),
    (SELECT id FROM users WHERE tenant_id = t.id LIMIT 1),
    'Weekly Vulnerability Scan',
    1
FROM tenants t;


-- SEED JOB EXECUTIONS
INSERT INTO job_executions (id, job_definition_id, execution_number, status, triggered_by)
SELECT
    gen_random_uuid(),
    jd.id,
    1,
    'completed',
    jd.created_by
FROM job_definitions jd;


-- SEED TOOLS
INSERT INTO tools (id, name, version, category)
VALUES
(gen_random_uuid(), 'Metasploit', '6.3', 'exploit'),
(gen_random_uuid(), 'Semgrep', '1.45', 'scanner'),
(gen_random_uuid(), 'LangGraph Agent', '1.0', 'ai_agent');


-- SEED EXECUTION TOOLS
INSERT INTO execution_tools (id, job_execution_id, tool_id, execution_order, status)
SELECT
    gen_random_uuid(),
    je.id,
    t.id,
    ROW_NUMBER() OVER (),
    'completed'
FROM job_executions je, tools t;


-- SEED TOOL RUNS
INSERT INTO tool_runs (id, execution_tool_id, raw_output_json, exit_code)
SELECT
    gen_random_uuid(),
    et.id,
    '{"result" "sample scan output", "vulnerabilities" 2}'jsonb,
    0
FROM execution_tools et;


-- SEED MODEL REGISTRY
INSERT INTO model_registry (id, provider, model_name, model_version)
VALUES
(gen_random_uuid(), 'OpenAI', 'gpt-oss-120b', 'v1'),
(gen_random_uuid(), 'Moonshot', 'kimi-k2-thinking', 'v1');


-- SEED FINDINGS
INSERT INTO findings (
    id, job_execution_id, tool_run_id,
    cve_id, title, severity_label, confidence_score
)
SELECT
    gen_random_uuid(),
    je.id,
    tr.id,
    'CVE-2024-12345',
    'Remote Code Execution Vulnerability',
    'critical',
    0.95
FROM job_executions je
JOIN tool_runs tr ON true
LIMIT 5;


-- SEED EVIDENCE
INSERT INTO evidence (id, finding_id, evidence_type, content_json)
SELECT
    gen_random_uuid(),
    f.id,
    'log',
    '{"log" "exploit successful"}'jsonb
FROM findings f;


-- SEED AI ANALYSES
INSERT INTO ai_analyses (
    id, finding_id, model_id,
    reasoning_mode, summary_text, confidence_score
)
SELECT
    gen_random_uuid(),
    f.id,
    (SELECT id FROM model_registry LIMIT 1),
    'summary_only',
    'This vulnerability allows remote code execution.',
    0.92
FROM findings f;


-- SEED REMEDIATIONS
INSERT INTO remediations (id, finding_id, remediation_text, priority)
SELECT
    gen_random_uuid(),
    f.id,
    'Apply latest security patch and restrict network access.',
    'critical'
FROM findings f;


-- SEED APPROVALS
INSERT INTO approvals (id, finding_id, required_role, status)
SELECT
    gen_random_uuid(),
    f.id,
    'admin',
    'pending'
FROM findings f;


-- SEED AUDIT EVENTS
INSERT INTO audit_events (
    id, tenant_id, user_id, entity_type, entity_id, action
)
SELECT
    gen_random_uuid(),
    t.id,
    u.id,
    'job_execution',
    je.id,
    'EXECUTED'
FROM tenants t
JOIN users u ON u.tenant_id = t.id
JOIN job_executions je ON true
LIMIT 10;


-- SEED COMPLIANCE LEDGER
INSERT INTO compliance_ledger (id, audit_event_id, current_hash)
SELECT
    gen_random_uuid(),
    ae.id,
    encode(digest(ae.idtext, 'sha256'), 'hex')
FROM audit_events ae;


-- SEED AGENT STEPS
INSERT INTO agent_steps (
    id, job_execution_id, model_used, node_name, input_state, output_state
)
SELECT
    gen_random_uuid(),
    je.id,
    (SELECT id FROM model_registry LIMIT 1),
    'analyze_findings',
    '{"input" "scan data"}'jsonb,
    '{"output" "analysis complete"}'jsonb
FROM job_executions je;