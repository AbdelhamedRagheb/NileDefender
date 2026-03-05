# Use official Python runtime as a parent image
FROM python:3.13-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies + Firefox for Selenium #git
RUN apt-get update && apt-get install -y \
    # wget \
    # unzip \
    # golang \
    firefox-esr \                             
    && rm -rf /var/lib/apt/lists/*

# Install geckodriver for Selenium #git
RUN GECKO_VERSION=$(wget -qO- https://api.github.com/repos/mozilla/geckodriver/releases/latest | grep -oP '"tag_name": "\K[^"]+') && \
    wget -q "https://github.com/mozilla/geckodriver/releases/download/${GECKO_VERSION}/geckodriver-${GECKO_VERSION}-linux64.tar.gz" -O /tmp/geckodriver.tar.gz && \
    tar -xzf /tmp/geckodriver.tar.gz -C /usr/local/bin/ && \
    chmod +x /usr/local/bin/geckodriver && \
    rm /tmp/geckodriver.tar.gz

# Install httpx
# RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Add Go bin to PATH
# ENV PATH="/root/go/bin:${PATH}"

# Install Python dependencies first (cached unless requirements.txt changes)
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . /app

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Run server.py when the container launches
CMD ["python", "server.py"]
