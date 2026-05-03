import pytest
from backend.db import get_db
from backend.celery_app import celery_app as celery
from backend.db import SessionLocal


@pytest.fixture
def db():
    session = SessionLocal()

    try:
        yield session
        session.rollback() 
    finally:
        session.close()

@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from backend.api import app
    return TestClient(app)

@pytest.fixture
def celery_app():
    celery.conf.task_always_eager = True
    return celery

@pytest.fixture(scope="session", autouse=True)
def celery_eager():
    celery.conf.task_always_eager = True
    celery.conf.task_eager_propagates = True





