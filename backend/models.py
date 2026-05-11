import uuid
from sqlalchemy import Column, String, Boolean, Integer, Text, ForeignKey, DateTime, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from backend.db import Base


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    subscription_tier = Column(String(100))
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(), nullable=False, server_default=func.now())


class Target(Base):
    __tablename__ = "targets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    type = Column(String(50), nullable=False)   # target_type_enum value
    value = Column(String(512), nullable=False)
    environment = Column(String(255))
    owner = Column(String(255))
    created_at = Column(DateTime(), nullable=False, server_default=func.now())


class JobDefinition(Base):
    __tablename__ = "job_definitions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    target_id = Column(UUID(as_uuid=True), ForeignKey("targets.id"))
    name = Column(String(255), nullable=False)
    version_number = Column(Integer, nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(), nullable=False, server_default=func.now())


class JobExecution(Base):
    __tablename__ = "job_executions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_definition_id = Column(UUID(as_uuid=True), ForeignKey("job_definitions.id", ondelete="CASCADE"), nullable=False)
    status = Column(String(50), nullable=False, default="pending")  # job_status_enum value
    execution_number = Column(Integer, nullable=False)
    started_at = Column(DateTime())
    completed_at = Column(DateTime())


class Tool(Base):
    __tablename__ = "tools"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    version = Column(String(100))
    category = Column(String(50), nullable=False)  # tool_category_enum value


class ExecutionTool(Base):
    __tablename__ = "execution_tools"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_execution_id = Column(UUID(as_uuid=True), ForeignKey("job_executions.id", ondelete="CASCADE"), nullable=False)
    tool_id = Column(UUID(as_uuid=True), ForeignKey("tools.id"), nullable=False)
    execution_order = Column(Integer, nullable=False)
    status = Column(String(50), nullable=False, default="pending")  # job_status_enum value
    celery_task_id = Column(String(255))
    started_at = Column(DateTime())
    completed_at = Column(DateTime())


class ToolRun(Base):
    __tablename__ = "tool_runs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    execution_tool_id = Column(UUID(as_uuid=True), ForeignKey("execution_tools.id", ondelete="CASCADE"), nullable=False)
    input_parameters = Column(JSONB)
    raw_output_json = Column(JSONB)
    stdout_log = Column(Text)
    exit_code = Column(Integer)
    created_at = Column(DateTime(), nullable=False, server_default=func.now())


class ReviewRequest(Base):
    __tablename__ = "review_requests"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_execution_id = Column(UUID(as_uuid=True), ForeignKey("job_executions.id", ondelete="CASCADE"), nullable=False, unique=True)
    vulnerabilities = Column(JSONB, nullable=False, default=list)
    msf_modules = Column(JSONB, nullable=False, default=list)
    decision = Column(String(20), nullable=True)  # approve, skip, abort
    created_at = Column(DateTime(), nullable=False, server_default=func.now())
    # exploit_suggestions = Column(JSONB, default=list)

