from fastapi import FastAPI
from GMAP.backend.tasks import run_nmap, run_nuclei, parse_results

app = FastAPI()

repo = "https://github.com/example/repo"


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

