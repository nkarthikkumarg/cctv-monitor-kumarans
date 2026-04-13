FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements-central.txt /app/requirements-central.txt
RUN pip install --no-cache-dir -r /app/requirements-central.txt

COPY central_app.py /app/central_app.py

CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-8080} central_app:app"]
