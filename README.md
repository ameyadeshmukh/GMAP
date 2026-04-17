# GMAP
Autonomous agentic system integrating cybersecurity tools to automate vulnerability assessment


## Instructions

- Create a python virtual environment with command 'python -m venv venv' and install dependencies with 'pip install -r requirements.txt'

- Run 'docker compose up -d' to run the redis and redis-commander containers.

- Run the streamlit frontend using streamlit run app.py

- Run the celery app with this command 'celery -A celery_app worker --loglevel=info' in '/backend' folder

- Run the Fastapi app with 'uvicorn api:app --reload' in '/backend' folder

- Celery tasks are viewable at localhost:8081 & FastAPI viewable at http://127.0.0.1:8000/
