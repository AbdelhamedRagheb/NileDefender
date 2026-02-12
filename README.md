# NileDefender

## Descripton 
NileDefender is a self-hosted security tool engineered for penetration testers and development teams. It provides a flexible framework for conducting comprehensive web application security tests through a unified web interface.



# Pages Design 
https://excalidraw.com/#json=oSrZnZ1vgoIohU6cgz77o,zaioTUhpKSf5YYQ9UVrsIA

# System Arch
https://excalidraw.com/#json=opjfKkRATAPZveyIDOy9I,2x7sTI-w_oYqYZ4ZfMcQCg

# UI/UX 
https://www.figma.com/proto/21LhpLXwu5zOjNxVuqNzdk/NileDefender?node-id=5-17&p=f&t=vNMH06Q9MfXQpfEZ-1&scaling=min-zoom&content-scaling=fixed&page-id=0%3A1&starting-point-node-id=5%3A17

## Quick Start with Docker (Recommended)

To run NileDefender easily using Docker, follow these steps:

1.  **Prerequisites:** Ensure you have Docker and Docker Compose installed on your machine.
2.  **Run the application:**
    ```bash
    docker-compose up -d
    ```
3.  **Access the interface:** Open your browser and navigate to [http://localhost:5000](http://localhost:5000).

To stop the application, run:
```bash
docker-compose down
```

## Manual Installation

If you prefer to run it manually without Docker:

1.  **Create a virtual environment:**
    ```bash
    python3 -m venv my-venv
    source my-venv/bin/activate
    ```
2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
3.  **Run the server:**
    ```bash
    python server.py
    ```
4.  **Access the interface:** Open your browser and navigate to [http://localhost:5000](http://localhost:5000).
