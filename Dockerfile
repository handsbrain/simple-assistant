FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY core ./core
COPY email_worker.py .
COPY signature.txt .

# unbuffered logs
ENV PYTHONUNBUFFERED=1
ENV HEALTH_PORT=8080

CMD ["python", "-u", "email_worker.py"]

