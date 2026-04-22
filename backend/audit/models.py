import uuid
from sqlalchemy import Column, DateTime, String, Text, func, Index, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from db import Base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy import Enum as SqlEnum


class AuditLog(Base):
    __tablename__ = "audit_events"  

    id = Column(UUID, primary_key=True, nullable=False)
    tenant_id = Column(UUID, nullable=False)
    user_id = Column(UUID, nullable=False)
    entity_type = Column(String(32), nullable=False)
    entity_id = Column(UUID, nullable=False)
    action = Column(String, nullable=False)
    before_hash = Column(String, nullable=False)
    after_hash = Column(String, nullable=False)
    ip_address = Column(String, nullable=False)
    user_agent = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

