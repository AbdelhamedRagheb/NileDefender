# Use official Python runtime as a parent image
FROM python:3.13-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    wget \
    unzip \
    golang \
    && rm -rf /var/lib/apt/lists/*

# Install httpx
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Add Go bin to PATH
ENV PATH="/root/go/bin:${PATH}"

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Run server.py when the container launches
CMD ["python", "server.py"]
