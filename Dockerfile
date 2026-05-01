# v2: pinned base image (fixes MCP-073), explicit non-root USER (fixes MCP-208),
# install hook removed (fixes MCP-207).
FROM python:3.12.7-slim-bookworm

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -u 1000 -m mcp
USER 1000

CMD ["python", "server.py"]
