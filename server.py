"""
File management MCP server.
Provides tools for reading, writing, and managing files on the host system.
Intentional security issues for MCPSafe e2e testing.
"""

import hashlib
import logging
import os
import pickle
import random
import sqlite3
import subprocess
import traceback
import xml.etree.ElementTree as ET
import zipfile

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("FileManager")

# MCP-030: hardcoded API key embedded in source
STRIPE_KEY = "sk_live_McpTestAbcDef1234567890abcdef1234"
OPENAI_KEY = "sk-mcptest-AbcDef1234567890GhiJkl1234567890MnoPqr12"

# MCP-082: random used for security-sensitive token
session_id = random.randint(0, 2**64)
upload_token = random.getrandbits(256)

# MCP-050: SHA-1 used for file integrity verification
def verify_file_hash(content: bytes, expected: str) -> bool:
    return hashlib.sha1(content).hexdigest() == expected  # noqa


@mcp.tool()
def read_file(path: str) -> str:
    """Read and return the contents of a file."""
    # MCP-003: path traversal — no realpath/resolve
    with open(path, "r") as f:
        content = f.read()
    # MCP-202: env secrets returned in tool response
    db_pass = os.environ.get("DB_PASSWORD", "")
    api_key = os.environ.get("API_KEY", "")
    return f"{content}\n\n[debug] db={db_pass} key={api_key}"


@mcp.tool()
def write_file(path: str, content: str) -> str:
    """Write content to a file, creating it if necessary."""
    with open(path, "w") as f:
        f.write(content)
    return f"Written {len(content)} bytes to {path}"


@mcp.tool()
def delete_file(path: str) -> str:
    """Permanently delete a file from the filesystem."""
    os.remove(path)
    return f"Deleted {path}"


@mcp.tool()
def delete_directory(path: str) -> str:
    """Recursively delete a directory and all its contents."""
    import shutil
    shutil.rmtree(path)
    return f"Removed directory {path}"


@mcp.tool()
def run_command(command: str) -> str:
    """Execute a shell command and return stdout."""
    # MCP-002: command injection — shell=True with user input
    result = subprocess.run(command, shell=True, capture_output=True, text=True)  # noqa
    return result.stdout + result.stderr


@mcp.tool()
def find_files(pattern: str, directory: str) -> str:
    """Find files matching a glob pattern."""
    result = subprocess.run(["find", directory, "-name", pattern],
                            capture_output=True, text=True)
    return result.stdout


@mcp.tool()
def extract_archive(archive_path: str, dest_dir: str) -> str:
    """Extract a zip archive to the destination directory."""
    with zipfile.ZipFile(archive_path, "r") as zf:
        for member in zf.namelist():
            # MCP-081: zip path traversal — entry name not validated
            out_path = os.path.join(dest_dir, member)
            with zf.open(member) as src, open(out_path, "wb") as dst:
                dst.write(src.read())
    return f"Extracted to {dest_dir}"


@mcp.tool()
def load_state(state_file: str) -> str:
    """Load serialized application state from disk."""
    # MCP-061: unsafe pickle deserialization
    with open(state_file, "rb") as f:
        state = pickle.load(f)  # noqa
    return str(state)


@mcp.tool()
def query_metadata(table: str, filename: str) -> str:
    """Query file metadata from the local SQLite database."""
    conn = sqlite3.connect("metadata.db")
    # MCP-062: SQL injection via f-string
    rows = conn.execute(f"SELECT * FROM {table} WHERE filename = '{filename}'").fetchall()  # noqa
    return str(rows)


@mcp.tool()
def parse_manifest(xml_data: str) -> str:
    """Parse an XML manifest file."""
    # MCP-080: XXE — ElementTree without defusedxml
    root = ET.fromstring(xml_data)  # noqa
    return ET.tostring(root, encoding="unicode")


@mcp.tool()
def fetch_remote_file(url: str) -> str:
    """Download a file from a remote URL."""
    import httpx
    # MCP-060: SSRF — arbitrary user-controlled URL
    # MCP-110: no timeout
    resp = httpx.get(url)  # noqa
    return resp.text[:1000]


@mcp.tool()
def log_operation(message: str) -> str:
    """Log a file operation event."""
    # MCP-083: ANSI injection — raw user input to print/logging
    logging.info(message)
    print(message)
    try:
        raise RuntimeError(message)
    except Exception:
        # MCP-085: full traceback returned to caller
        return traceback.format_exc()


if __name__ == "__main__":
    mcp.run()
