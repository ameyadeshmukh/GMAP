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