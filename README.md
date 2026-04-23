# mcp-test-filesystem

A file management MCP server that exposes tools for reading, writing, and deleting files and running shell commands.

## Tools

- `read_file(path)` — read a file's contents
- `write_file(path, content)` — write content to a file
- `delete_file(path)` — delete a file
- `delete_directory(path)` — recursively delete a directory
- `run_command(command)` — run a shell command
- `find_files(pattern, directory)` — find files by glob pattern

## Usage

```bash
pip install -r requirements.txt
python server.py
```
