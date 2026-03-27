# 🧪 Demo MCP Servers

Intentionally vulnerable demo MCP servers that showcase the security issues MCP Armor can detect.

**All demo servers and scans run entirely locally on your machine - no data is sent externally.**

### 1️⃣  Setup

Navigate to the demo-mcp-server directory and install dependencies:

```bash
cd demo-mcp-server
pip install fastmcp
```

### 2️⃣  Run the servers

```bash
python demo_server.py
```

This starts two servers:
- **ShopMCPServer**: `http://127.0.0.1:3000/mcp` (intentionally vulnerable)
- **PaymentsServer**: `http://127.0.0.1:3001/mcp` (clean; used for cross-server tool shadowing detection)

To use custom ports: 
```bash
python demo_server.py 3000 3001
```

Press `Ctrl+C` to stop both servers.

### 3️⃣  Scan with MCP Armor

```bash
# Install if needed
pip install mcp-armor

# Run scan with baseline (from repository root)
mcp-armor scan --config ./demo-mcp-server/demo_config.json --baseline ./demo-mcp-server/demo_baseline.json

# Run scan without baseline checks (from repository root)
mcp-armor scan --config ./demo-mcp-server/demo_config.json
```