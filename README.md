# GMAP
Autonomous agentic system integrating cybersecurity tools to automate vulnerability assessment


## Instructions

- Create a python virtual environment with command 'python -m venv venv' and install dependencies with 'pip install -r requirements.txt'

- Run 'docker compose up -d' to run the redis and redis-commander containers.

- Run the celery app with this command 'celery -A tasks worker -l info -P threads --concurrency=8'

- Run the Fastapi app with 'uvicorn api:app --reload'