ALTER TABLE execution_tools
ADD COLUMN celery_task_id TEXT;

INSERT INTO tenants (id, name)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'default-tenant'
);

ALTER TABLE execution_tools
ADD COLUMN tenant_id UUID;

INSERT INTO tools (id, name, version, category)
VALUES
(gen_random_uuid(), 'Nuclei', '7.7', 'scanner'),
(gen_random_uuid(), 'Nmap', '3.3', 'scanner');

ALTER TABLE job_executions
ADD COLUMN celery_task_id VARCHAR(255),
ADD COLUMN queue_name VARCHAR(100),
ADD COLUMN retry_count INTEGER DEFAULT 0,
ADD COLUMN last_heartbeat TIMESTAMP;

CREATE TABLE job_tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_execution_id UUID REFERENCES job_executions(id) ON DELETE CASCADE,
    task_name VARCHAR(255),
    celery_task_id VARCHAR(255),
    status job_status_enum NOT NULL DEFAULT 'pending',
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    retry_count INTEGER DEFAULT 0,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT now()
);

INSERT INTO job_tasks (
    job_execution_id,
    task_name,
    celery_task_id,
    status
)
VALUES (
    '<job_execution_id>',
    'scan_pipeline',
    '<celery_task_id>',
    'queued'
);