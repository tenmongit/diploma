.PHONY: up down build logs migrate seed shell

up:
	docker compose up -d --build

down:
	docker compose down

build:
	docker compose build --no-cache

logs:
	docker compose logs -f

logs-api:
	docker compose logs -f api

logs-worker:
	docker compose logs -f worker

migrate:
	docker compose exec api alembic upgrade head

makemigrations:
	docker compose exec api alembic revision --autogenerate -m "$(msg)"

seed:
	docker compose exec api python -m app.db.seed

shell:
	docker compose exec api python

restart:
	docker compose restart api worker

clean:
	docker compose down -v --remove-orphans

env:
	cp .env.example .env
