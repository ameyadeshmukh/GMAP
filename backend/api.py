from fastapi import FastAPI
from pydantic import BaseModel
from ingestion import ingest_target


class TargetRequest(BaseModel):
    target_url: str


app = FastAPI(title="GMAP API")


@app.get("/")
def read_root():
    return {"message": "GMAP API is running!"}


@app.post("/targets")
async def submit_target(req: TargetRequest):
    return ingest_target(target_url=req.target_url)
