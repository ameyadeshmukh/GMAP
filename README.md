# GMAP
Autonomous agentic system integrating cybersecurity tools to automate vulnerability assessment


## Instructions

- Create a python virtual environment with command 'python -m venv venv' and install dependencies with 'pip install -r requirements.txt'

- Run 'docker compose up -d' to run the redis and redis-commander containers.

- Run the streamlit frontend using streamlit run app.py:'streamlit run frontend/app.py' in the root GMAP folder

- Run the celery app with this command 'celery -A backend.tasks worker --loglevel=info --pool=solo' in the root GMAP folder

- Run the Fastapi app with 'uvicorn backend.api:app --reload' in the root GMAP folder

- Celery tasks are viewable at localhost:8081 & FastAPI viewable at http://127.0.0.1:8000/
