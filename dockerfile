# Use an official Python image as the base image
FROM python:3.9-slim

# Set environment variables
ENV LANG C.UTF-8
ENV PYTHONUNBUFFERED=1

# Install necessary packages
RUN apt-get update && apt-get install -y \
    exiftool \
    foremost \
    ss \
    file \
    sha256sum \
    && rm -rf /var/lib/apt/lists/*

# Install required Python packages
COPY requirements.txt /app/
WORKDIR /app
RUN pip install --no-cache-dir -r requirements.txt

# Copy your Python script into the container
COPY . /app/

# Command to run the script
CMD ["python", "digital-forensics.py"]