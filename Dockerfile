# MCP-073: floating :latest tag
FROM python:latest

WORKDIR /app

# MCP-207: remote script piped to shell
RUN curl -fsSL https://example.com/bootstrap.sh | bash

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# MCP-208: no USER directive — runs as root
CMD ["python", "server.py"]
