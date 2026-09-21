.PHONY: install train api dash test lint clean

install:
	pip install -r requirements.txt -r requirements-dev.txt

train:
	python scripts/train_all.py

seed:
	python scripts/seed_demo.py

api:
	uvicorn aegis.api.main:app --reload --host 0.0.0.0 --port 8000

dash:
	streamlit run aegis/dashboard/app.py --server.port 8501

test:
	pytest -q

lint:
	ruff check aegis/

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	rm -f aegis_events.db