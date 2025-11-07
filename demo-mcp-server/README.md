# Demo MCP Servers

Intentionally vulnerable demo MCP servers that demonstrate various security issues MCP Checkpoint can detect.

**All demo servers and scans run entirely locally on your machine - no data is sent externally.**

## 1) Setup

Navigate to the demo-mcp-server directory and install dependencies:

```bash
cd demo-mcp-server
pip install fastmcp
```

## 2) Run the servers

```bash
python demo_server.py
```

This starts two servers:
- **ShopMCPServer**: `http://127.0.0.1:3000/mcp` (contains security vulnerabilities)
- **PaymentsServer**: `http://127.0.0.1:3001/mcp` (clean server for cross-server tool shadowing detection)

Custom ports: `python demo_server.py 3000 3001`

Press Ctrl+C to stop both servers.

## 3) Scan with MCP Checkpoint

```bash
# Install if needed
pip install mcp-checkpoint

# Run scan (from repository root folder)
mcp-checkpoint scan --config ./demo-mcp-server/demo_config.json
```
