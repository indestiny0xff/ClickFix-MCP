# ClickFix Testing MCP Server
# Uses Python slim with Selenium for browser automation via VirtualBox VM
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set Python unbuffered mode
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the server code
COPY clickfix_server.py .

# Create non-root user and shared directories
RUN useradd -m -u 1000 mcpuser && \
    mkdir -p /app/output /app/screenshots && \
    chown -R mcpuser:mcpuser /app

# Switch to non-root user
USER mcpuser

# Run the server
CMD ["python", "clickfix_server.py"]
