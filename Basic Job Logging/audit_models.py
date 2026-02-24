import uuid
from sqlalchemy import Column, DateTime, String, Text, func, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB
from db import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Every audit event ties to a job run
    job_id = Column(UUID(as_uuid=True), nullable=False)

    # column for if there is info/ a warning or possible error
    level = Column(String(8), nullable=False, default="INFO")

    # event that occurs 
    event_type = Column(String(32), nullable=False)

    # Text that can be read regarding the event
    message = Column(Text, nullable=False)

    # Details like (tool name, args, step, outputs, error fields, and so on 
    meta = Column(JSONB, nullable=False, default=dict)

    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        Index("ix_audit_logs_job_time", "job_id", "created_at"),
    )