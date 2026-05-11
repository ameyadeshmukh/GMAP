import uuid
from sqlalchemy import Column, DateTime, String, Text, func, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB
from backend.db import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Every audit event ties to a job run
    job_id = Column(UUID(as_uuid=True), nullable=False)

    # INFO / WARN / ERROR
    level = Column(String(8), nullable=False, default="INFO")

    # What happened (e.g. JOB_CREATED, TOOL_STARTED, DECISION)
    event_type = Column(String(32), nullable=False)

    # Human-readable description
    message = Column(Text, nullable=False)

    # Structured details: tool name, args, outputs, finding IDs, etc.
    meta = Column(JSONB, nullable=False, default=dict)

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        Index("ix_audit_logs_job_time", "job_id", "created_at"),
    )
