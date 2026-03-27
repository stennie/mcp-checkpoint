<p align="center" style="margin-bottom: 0; line-height: 0;">
<img src="https://github.com/aira-security/mcp-armor/blob/main/mcp-armor.png" width="350"> 
</p>
<h3 align="center" margin-top: -20px; margin-bottom: 70px;>
   MCP Armor
</h3>

<br>

## 🚀 Overview

MCP Armor is a comprehensive security scanner for Model Context Protocol (MCP). Automatically discovers, analyzes, and secures MCP servers integrated with all major Agentic IDEs, Agents and Clients.

<br>

![MCP Armor](https://github.com/aira-security/mcp-armor/blob/main/mcp-armor.gif?raw=true&v=3)


## 💡 Features

- **🔍 Auto-Discovery**: Finds known MCP configurations for popular Agentic IDEs like Cursor, Windsurf, VS Code, Claude Desktop, and more
- **🔧 Tool, Resource & Prompt Inventory**: Connects to MCP servers and catalogs available tools, resources, and prompt templates
- **🛡️ Security Analysis**: Specialized security checks including Prompt Injection, Rug Pull Attack, Cross-server Tool Shadowing, Tool Poisoning, Tool Name Ambiguity, [and more..](#beginner-security-checks)
- **🧭 Baseline Drift Detection**: Captures approved MCP components and detects rug pulls attacks
- **📊 Comprehensive Reporting**: Generates JSON and Markdown reports with actionable findings
- **📜 Audit Trail**: Timestamped baselines and reports for full traceability of changes and findings


## 🧰 Installation

```bash
pip install mcp-armor
```

## 🏃 Quick Start

```bash
# Scan all configurations with security analysis (auto-detects baseline.json if present)
mcp-armor scan

# Inspect configurations and generate baseline (defaults to baseline.json)
mcp-armor inspect

# Use custom configuration file
mcp-armor scan --config /path/to/config.json

# Scan multiple configuration files
 mcp-armor scan \
   --config /path/to/cursor.mcp.json \
   --config /path/to/vscode.mcp.json

# Use custom baseline file path
mcp-armor inspect --baseline /path/to/my-baseline.json
mcp-armor scan --baseline /path/to/my-baseline.json

# Generate markdown report
mcp-armor scan --report-type md

# Save to custom file
mcp-armor scan --output my-report.json
mcp-armor scan --report-type md --output my-report.md
```

#### ⚙️ Command Options

| Option                    | Description                                                         |
|---------------------------|---------------------------------------------------------------------|
| `--config`                | Custom configuration file path (can be used multiple times)         |
| `--baseline`              | Baseline file for drift detection (scan) or creation (inspect)      |
| `--report-type {json,md}` | Output format (default: json)                                       |
| `--output`                | Custom output file path                                             |
| `--verbose`               | Detailed terminal output                                            |
| `--show-logs`             | Display debug logs in terminal                                      |


## 🔰 Security Checks

### 🛡️ Standard Checks

- **Prompt Injection**  
- **Indirect Prompt Injection**
- **Cross-Server Tool Shadowing**
- **Tool Poisoning**
  - **Prompt Injection in Tool Description, Name and Args**
  - **Command Injection in Tool Description, Name and Args**
- **Tool Name Ambiguity**
- **Command Injection**
- **Excessive Tool Permissions**
- **Hardcoded Secrets**

### 🧭 Baseline Checks

Detects deviations from approved MCP components (requires a baseline generated via `inspect` mode):

- **Rug Pull Attack**
  - **Tool Modified**
  - **Resource Modified**
  - **Resource Template Modified**
  - **Prompt Modified**

### 📃 Logging

Logs are automatically saved to `logs/mcp_armor.log`:

```bash
# Default: logs saved to file only
mcp-armor scan

# Show logs in terminal too
mcp-armor scan --show-logs
```


### 🧪 Demo

Test MCP Armor using our intentionally vulnerable MCP servers. For details, see the [demo guide](demo-mcp-server/README.md).


### ⚡ Want More?

This open-source version covers static MCP configuration scanning. For teams that need deeper protection, [Aira Security](https://airasecurity.ai) offers a full enterprise platform with:

| Capability | Open Source | Aira Platform |
|---|:---:|:---:|
| MCP config scanning | ✅ | ✅ |
| Prompt & command injection detection | ✅ | ✅ |
| Tool poisoning & shadowing checks | ✅ | ✅ |
| Hardcoded secrets detection | ✅ | ✅ |
| **Runtime enforcement & blocking** | ❌ | ✅ |
| **Agent behavior policy enforcement** (toxic flow analysis) | ❌ | ✅ |
| **Skills scanner** (agentic workflow & capability analysis) | ❌ | ✅ |
| **Custom security policies** | ❌ | ✅ |
| **Aira dashboard** (centralized visibility & alerting) | ❌ | ✅ |
| **Complete Agentic Security** (beyond MCP — Agents, Workflows, and Skills) | ❌ | ✅ |


🚀 [See Aira in Action](https://calendly.com/mohan-/aira-security) to experience the full platform.


### 🌟 Community

 [Join our Slack](https://join.slack.com/t/airasecurityc-jwt3316/shared_invite/zt-3iar5tm3k-R5js~WfnDIHRNtSgd7D0Bg) - a space for developers and security engineers building together to secure AI agents.

### ❓ FAQs

**Q: Is my source code ever shared, or does everything run locally?**

MCP Armor runs entirely locally. Inspect and scan modes analyze your MCP configurations, detect MCP servers integrated with your agents, and evaluate them directly on your machine. Prompt injection checks use our open-source model `Aira-security/FT-Llama-Prompt-Guard-2`, downloaded from Hugging Face to your local environment, ensuring your data and code is never shared externally.


### ⚖️ License

Distributed under the Apache 2.0 License. See [LICENSE](https://github.com/aira-security/mcp-armor/blob/main/LICENSE) for more information.