FROM python:3.11-slim

WORKDIR /app

# Install Docker CLI for orchestration
RUN apt-get update && apt-get install -y docker.io

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy orchestrator code
COPY . .

CMD ["python", "orchestrator.py"]
