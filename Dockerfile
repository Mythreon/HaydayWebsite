FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["gunicorn", "--log-level", "debug", "--access-logfile", "-", "--error-logfile", "-", "-b", "0.0.0.0:8080", "app:app"]



