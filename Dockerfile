FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y git nano libpcap-dev tcpdump && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r final_requirements.txt

# Expose FastAPI port
EXPOSE 9018

# Run both fetch_pcap.py and FastAPI
CMD ["sh", "-c", "python fetch_pcap.py & python remove_file.py & uvicorn app:app --host 0.0.0.0 --port 9018"]

