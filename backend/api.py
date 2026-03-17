from fastapi import FastAPI
from tasks import run_nmap, run_nuclei, parse_results
from ingestion import ingest_target
from pydantic import BaseModel

# FastAPI JSON model class for target URL
class TargetRequest(BaseModel):
    target_url: str

app = FastAPI()

repo = "https://github.com/example/repo"

@app.get("/")
def read_root():
    return {"message": "GMAP API is running!"}

# Submit a target URL, ingest/validate it, store it, and queue initial scan tasks (nmap & nuclei)
@app.post("/targets")
async def submit_target(req: TargetRequest):
    return ingest_target(target_url=req.target_url)

@app.get("/queue")
async def root():
    task = run_nmap.delay(repo)
    task_dict = task.get()
    return {
            "message": "hello world",
            "task_id": task.id,
            "task_dict" : task_dict["tool"]
            }

# @app.get("/task")
# async def create_task():
#     task = process.delay(4, 78)
#     return {
#         "message": "task queued",
#         "task_id": task.id,
#         "task_status": task.status
#     }

