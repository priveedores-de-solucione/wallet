FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .

RUN python -m venv /venv \
    && /venv/bin/pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 10000

CMD ["/venv/bin/uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000"]