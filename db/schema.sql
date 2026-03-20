-- EXTENSIONS

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- DEFINE ENUM TYPES

CREATE TYPE user_role_enum AS ENUM (
    'admin',
    'analyst',
    'auditor',
    'viewer'
);

CREATE TYPE job_status_enum AS ENUM (
    'pending',
    'queued',
    'running',
    'completed',
    'failed',
    'cancelled',
    'requires_review'
);

CREATE TYPE tool_category_enum AS ENUM (
    'scanner',
    'exploit',
    'ai_agent',
    'parser'
);

CREATE TYPE severity_label_enum AS ENUM (
    'critical',
    'high',
    'medium',
    'low',
    'informational'
);

CREATE TYPE finding_status_enum AS ENUM (
    'open',
    'validated',
    'false_positive',
    'remediated'
);

CREATE TYPE reasoning_mode_enum AS ENUM (
    'full',
    'partial',
    'summary_only'
);

CREATE TYPE approval_status_enum AS ENUM (
    'pending',
    'approved',
    'rejected'
);

CREATE TYPE priority_enum AS ENUM (
    'critical',
    'high',
    'medium',
    'low'
);

CREATE TYPE evidence_type_enum AS ENUM (
    'log',
    'payload',
    'screenshot',
    'network_trace',
    'file'
);

CREATE TYPE target_type_enum AS ENUM (
    'ip',
    'domain',
    'repo',
    'container',
    'vm'
);

-- TABLES

CREATE TABLE reasoning_storage_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mode reasoning_mode_enum NOT NULL,
    retain_raw_prompt BOOLEAN NOT NULL DEFAULT false,
    retain_chain_of_thought BOOLEAN NOT NULL DEFAULT false,
    redact_sensitive_data BOOLEAN NOT NULL DEFAULT true,
    encryption_required BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    subscription_tier VARCHAR(100),
    reasoning_policy_id UUID REFERENCES reasoning_storage_policies(id),
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    role user_role_enum NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    last_login TIMESTAMP,
    UNIQUE (tenant_id, email)
);

-- TARGETS

CREATE TABLE targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type target_type_enum NOT NULL,
    value VARCHAR(512) NOT NULL,
    environment VARCHAR(255),
    owner VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT now()
);

-- JOB DEFINITIONS (VERSIONED)

CREATE TABLE job_definitions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    target_id UUID REFERENCES targets(id),
    created_by UUID REFERENCES users(id),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    parameters_json JSONB,
    version_number INTEGER NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_job_definition_version
ON job_definitions (tenant_id, name, version_number);

-- RECURRENCES

CREATE TABLE recurrences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cron_expression VARCHAR(100) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    last_run TIMESTAMP,
    next_run TIMESTAMP
);

-- JOB EXECUTIONS

CREATE TABLE job_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_definition_id UUID NOT NULL REFERENCES job_definitions(id) ON DELETE CASCADE,
    triggered_by UUID REFERENCES users(id),
    recurrence_id UUID REFERENCES recurrences(id),
    status job_status_enum NOT NULL DEFAULT 'pending',
    execution_number INTEGER NOT NULL,
    container_image_hash VARCHAR(255),
    gcp_instance_id VARCHAR(255),
    started_at TIMESTAMP,
    completed_at TIMESTAMP
);

CREATE INDEX idx_job_execution_status ON job_executions(status);
CREATE INDEX idx_job_execution_job_def ON job_executions(job_definition_id);

-- TOOLS

CREATE TABLE tools (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    version VARCHAR(100),
    category tool_category_enum NOT NULL,
    container_hash VARCHAR(255)
);

CREATE TABLE execution_tools (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_execution_id UUID NOT NULL REFERENCES job_executions(id) ON DELETE CASCADE,
    tool_id UUID NOT NULL REFERENCES tools(id),
    execution_order INTEGER NOT NULL,
    status job_status_enum NOT NULL DEFAULT 'pending',
    celery_task_id VARCHAR(255),
    started_at TIMESTAMP,
    completed_at TIMESTAMP
);

-- TOOL RUNS

CREATE TABLE tool_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_tool_id UUID NOT NULL REFERENCES execution_tools(id) ON DELETE CASCADE,
    input_parameters JSONB,
    raw_output_json JSONB,
    stdout_log TEXT,
    stderr_log TEXT,
    exit_code INTEGER,
    checksum VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT now()
);

-- MODEL REGISTRY

CREATE TABLE model_registry (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider VARCHAR(255) NOT NULL,
    model_name VARCHAR(255) NOT NULL,
    model_version VARCHAR(100),
    temperature FLOAT,
    max_tokens INTEGER,
    created_at TIMESTAMP NOT NULL DEFAULT now()
);

-- FINDINGS

CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_execution_id UUID NOT NULL REFERENCES job_executions(id) ON DELETE CASCADE,
    tool_run_id UUID REFERENCES tool_runs(id),
    cve_id VARCHAR(100),
    title VARCHAR(255),
    description TEXT,
    severity_score FLOAT,
    severity_label severity_label_enum,
    confidence_score FLOAT,
    status finding_status_enum NOT NULL DEFAULT 'open',
    discovered_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX idx_findings_severity ON findings(severity_label);
CREATE INDEX idx_findings_status ON findings(status);

-- EVIDENCE

CREATE TABLE evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    evidence_type evidence_type_enum NOT NULL,
    content_json JSONB,
    file_uri VARCHAR(512),
    checksum VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT now()
);

-- AI ANALYSES

CREATE TABLE ai_analyses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    model_id UUID REFERENCES model_registry(id),
    reasoning_mode reasoning_mode_enum NOT NULL,
    prompt_hash VARCHAR(255),
    input_context_hash VARCHAR(255),
    summary_text TEXT,
    reasoning_text TEXT,
    full_response_json JSONB,
    hallucination_flag BOOLEAN DEFAULT false,
    confidence_score FLOAT,
    created_at TIMESTAMP NOT NULL DEFAULT now()
);

-- REMEDIATIONS

CREATE TABLE remediations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    remediation_text TEXT NOT NULL,
    priority priority_enum,
    created_by_ai BOOLEAN DEFAULT true,
    approved_by UUID REFERENCES users(id),
    approved_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT now()
);

-- APPROVALS

CREATE TABLE approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    required_role user_role_enum NOT NULL,
    approved_by UUID REFERENCES users(id),
    status approval_status_enum NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP NOT NULL DEFAULT now()
);

-- AUDIT LOGS (per-job event stream written by the agent/workers)

CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL,
    level VARCHAR(8) NOT NULL DEFAULT 'INFO',
    event_type VARCHAR(32) NOT NULL,
    message TEXT NOT NULL,
    meta JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX ix_audit_logs_job_time ON audit_logs (job_id, created_at);

-- AUDIT EVENTS

CREATE TABLE audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),
    entity_type VARCHAR(255),
    entity_id UUID,
    action VARCHAR(255),
    before_hash VARCHAR(255),
    after_hash VARCHAR(255),
    ip_address VARCHAR(100),
    user_agent VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_tenant ON audit_events(tenant_id);

-- COMPLIANCE LEDGER

CREATE TABLE compliance_ledger (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_event_id UUID NOT NULL REFERENCES audit_events(id) ON DELETE CASCADE,
    previous_hash VARCHAR(255),
    current_hash VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT now()
);

-- AGENT STEPS (LangGraph tracing)

CREATE TABLE agent_steps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_execution_id UUID NOT NULL REFERENCES job_executions(id) ON DELETE CASCADE,
    model_used UUID REFERENCES model_registry(id),
    node_name VARCHAR(255),
    input_state JSONB,
    output_state JSONB,
    started_at TIMESTAMP,
    completed_at TIMESTAMP
);

-- INDEXES FOR PERFORMANCE

CREATE INDEX idx_tool_runs_exec_tool ON tool_runs(execution_tool_id);
CREATE INDEX idx_findings_job_exec ON findings(job_execution_id);
CREATE INDEX idx_ai_analysis_finding ON ai_analyses(finding_id);
CREATE INDEX idx_evidence_finding ON evidence(finding_id);

-- SEED DATA

INSERT INTO tenants (id, name, subscription_tier) VALUES
    ('00000000-0000-0000-0000-000000000001', 'default', 'free')
ON CONFLICT DO NOTHING;

INSERT INTO tools (id, name, version, category) VALUES
    ('00000000-0000-0000-0000-000000000002', 'nmap',   '7.94', 'scanner'),
    ('00000000-0000-0000-0000-000000000003', 'nuclei', '3.0',  'scanner'),
    ('00000000-0000-0000-0000-000000000004', 'httpx',  '1.3',  'scanner')
ON CONFLICT DO NOTHING;
