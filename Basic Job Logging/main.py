from fastapi import FastAPI
from db import Base, engine
from audit_api import router as audit_router

# For MVP. Later replace with migrations.
Base.metadata.create_all(bind=engine)

app = FastAPI(title="GMAP Audit Logging Foundation")
app.include_router(audit_router)

@app.get("/health")
def health():
    return {"ok": True}