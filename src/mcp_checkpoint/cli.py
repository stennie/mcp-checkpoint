import asyncio
import argparse
import json
import sys
import logging
import os
import shutil
import textwrap
from pathlib import Path
from datetime import datetime

from rich.console import Console
from rich.text import Text

from .scanner import MCPConfigScanner, ScanResult
from .run_checks import SecurityCheckRunner, SecurityReport
from .security_utils import calculate_risk_level, sort_issues_by_severity


class SuppressStderr:

    def __enter__(self):
        self.original_stderr = sys.stderr
        sys.stderr = open(os.devnull, 'w')
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        sys.stderr.close()
        sys.stderr = self.original_stderr


SEVERITY_EMOJI = {
    'CRITICAL': '🚫',
    'HIGH': '🔴', 
    'MEDIUM': '🟠',
    'LOW': '🟡',
}

RISK_EMOJI = {**SEVERITY_EMOJI, 'NONE': '✅'}


def get_level_emoji(level, mapping):
    level_upper = level.upper() if isinstance(level, str) else level
    return mapping.get(level_upper, '❓')


def print_separator(char='═', length=50):
    print(char * length)


def truncate_lines(text: str, max_lines: int = 2) -> str:
    if not text:
        return ""
    lines = str(text).splitlines()
    if len(lines) <= max_lines:
        return "\n".join(lines)
    return "\n".join(lines[:max_lines]) + "…"


def wrap_text_with_indent(text: str, indent: str = "       ", max_lines: int = None) -> str:
    if not text:
        return ""
    
    try:
        terminal_width = shutil.get_terminal_size().columns
    except (OSError, AttributeError):
        terminal_width = 80
    
    indent_len = len(indent)
    available_width = terminal_width - indent_len
    
    if available_width < 20:
        available_width = 20
    
    wrapped_lines = textwrap.wrap(
        text, 
        width=available_width, 
        break_long_words=False, 
        break_on_hyphens=False
    )
    
    if max_lines and len(wrapped_lines) > max_lines:
        wrapped_lines = wrapped_lines[:max_lines]
        if len(wrapped_lines) == max_lines:
            last_line = wrapped_lines[-1]
            if len(last_line) + 3 <= available_width:
                wrapped_lines[-1] = last_line + "…"
            else:
                max_chars = available_width - 3
                wrapped_lines[-1] = last_line[:max_chars] + "…"
    
    return "\n".join([indent + line for line in wrapped_lines])


def print_banner():
    console = Console()

    banner = """
███    ███  ██████ ██████       ██████ ██   ██ ███████  ██████ ██   ██ ██████   ██████  ██ ███    ██ ████████ 
████  ████ ██      ██   ██     ██      ██   ██ ██      ██      ██  ██  ██   ██ ██    ██ ██ ████   ██    ██    
██ ████ ██ ██      ██████      ██      ███████ █████   ██      █████   ██████  ██    ██ ██ ██ ██  ██    ██    
██  ██  ██ ██      ██          ██      ██   ██ ██      ██      ██  ██  ██      ██    ██ ██ ██  ██ ██    ██    
██      ██  ██████ ██           ██████ ██   ██ ███████  ██████ ██   ██ ██       ██████  ██ ██   ████    ██ 
"""

    console.print(banner, style="turquoise2")

    banner_text = Text("                                                                            ｂｙ  Ａｉｒａ  Ｓｅｃｕｒｉｔｙ",
                       style="bold magenta")
    console.print(banner_text)
    console.print()


def print_boxed_section(title, content_func):
    print_separator('═', 60)
    print(f"{title}")
    print_separator('─', 60)
    content_func()
    print()


def setup_logging(show_logs: bool = False):
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    log_file = log_dir / "mcp_checkpoint.log"

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.handlers.clear()
    root_logger.addHandler(file_handler)

    if show_logs:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)

    return str(log_file)


def format_scan_results_as_markdown(results) -> str:
    md = []

    md.append("# MCP Checkpoint Scan Report")
    md.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    md.append("")

    md.append("## Summary")
    md.append(f"- **Servers found**: {len(results.servers)}")
    md.append(f"- **Tools found**: {len(results.tools)}")
    md.append(f"- **Resources found**: {len(results.resources)}")
    md.append(f"- **Config files**: {len(results.config_files)}")
    md.append(f"- **Errors**: {len(results.errors)}")
    md.append(f"- **Status**: {len(results.status)}")
    md.append("")

    if results.servers:
        md.append("## Discovered Servers")
        for server in results.servers:
            status = "DISABLED" if server.disabled else "ENABLED"
            md.append(f"### {server.name} ({server.type.value}) - {status}")
            if server.source_file:
                md.append(f"- **Source**: `{server.source_file}`")
            if server.endpoint:
                md.append(f"- **Endpoint**: `{server.endpoint}`")
            if server.command:
                md.append(f"- **Command**: `{server.command} {' '.join(server.args)}`")
            if server.tools:
                md.append(f"- **Tools**: {', '.join(server.tools)}")
            if server.resources:
                md.append(f"- **Resources**: {', '.join(server.resources)}")
            md.append("")

    if results.tools:
        md.append("## Discovered Tools")
        for tool in results.tools:
            md.append(f"### {tool.name}")
            md.append(f"- **Server**: {tool.server_name}")
            md.append(f"- **Description**: {tool.description}")
            if tool.input_schema:
                md.append(f"- **Schema**:")
                md.append("```json")
                md.append(json.dumps(tool.input_schema, indent=2))
                md.append("```")
            md.append("")

    if results.resources:
        md.append("## Discovered Resources")
        for resource in results.resources:
            md.append(f"### {resource.name}")
            md.append(f"- **URI**: `{resource.uri}`")
            md.append(f"- **Server**: {resource.server_name}")
            md.append(f"- **Description**: {resource.description}")
            md.append(f"- **MIME Type**: {resource.mime_type}")
            md.append("")

    if hasattr(results, 'security_report') and results.security_report:
        security_report = results.security_report
        md.append("## Security Report")
        md.append(f"- **Risk Level**: {security_report.risk_level.value}")
        md.append(f"- **Total Issues**: {security_report.total_issues}")
        md.append("")

        md.append("### Issues by Severity")
        for severity, count in security_report.issues_by_severity.items():
            if count > 0:
                md.append(f"- **{severity.value}**: {count}")
        md.append("")

        if security_report.issues_by_type:
            md.append("### Issues by Type")
            for issue_type, count in security_report.issues_by_type.items():
                md.append(f"- **{issue_type}**: {count}")
            md.append("")

        if security_report.all_issues:
            md.append("### Security Issues")
            for issue in security_report.all_issues:
                md.append(f"#### {issue.issue_type} ({issue.severity.value})")
                md.append(f"- **Description**: {issue.description}")
                if issue.entity_type:
                    md.append(f"- **Entity Type**: {issue.entity_type}")
                if issue.affected_server:
                    md.append(f"- **Server**: {issue.affected_server}")
                if issue.config_file:
                    md.append(f"- **Config File**: `{issue.config_file}`")
                if issue.entity_type == "tool" and issue.affected_tool:
                    md.append(f"- **Tool**: {issue.affected_tool}")
                elif issue.entity_type == "resource" and issue.affected_resource:
                    md.append(f"- **Resource**: {issue.affected_resource}")
                    if issue.affected_resource_uri:
                        md.append(f"- **Resource URI**: {issue.affected_resource_uri}")
                md.append(f"- **Recommendation**: {issue.recommendation}")
                if issue.affected_entities:
                    md.append(f"- **Affected Entities**:")
                    md.append("```json")
                    md.append(json.dumps(issue.affected_entities, indent=2))
                    md.append("```")

                md.append("")

    if results.errors:
        md.append("## Errors")
        for error in results.errors:
            md.append(f"- {error}")
        md.append("")

    if results.status:
        md.append("## Status")
        for status_msg in results.status:
            md.append(f"- {status_msg}")
        md.append("")

    return "\n".join(md)


def format_inspect_results_as_markdown(results) -> str:
    md = []

    md.append("# MCP Configuration Inspection Report")
    md.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    md.append("")

    md.append("## Summary")
    md.append(f"- **Servers found**: {len(results.servers)}")
    md.append(f"- **Tools found**: {len(results.tools)}")
    md.append(f"- **Resources found**: {len(results.resources)}")
    md.append(f"- **Config files**: {len(results.config_files)}")
    md.append(f"- **Errors**: {len(results.errors)}")
    md.append(f"- **Status**: {len(results.status)}")
    md.append("")

    if results.config_files:
        md.append("## Configuration Files")
        for config_file in results.config_files:
            md.append(f"- `{config_file}`")
        md.append("")

    if results.servers:
        md.append("## Discovered Servers")
        for server in results.servers:
            status = "DISABLED" if server.disabled else "ENABLED"
            md.append(f"### {server.name} ({server.type.value}) - {status}")
            if server.source_file:
                md.append(f"- **Source**: `{server.source_file}`")
            if server.endpoint:
                md.append(f"- **Endpoint**: `{server.endpoint}`")
            if server.command:
                md.append(f"- **Command**: `{server.command} {' '.join(server.args)}`")
            if server.tools:
                md.append(f"- **Tools**: {', '.join(server.tools)}")
            if server.resources:
                md.append(f"- **Resources**: {', '.join(server.resources)}")
            md.append("")

    if results.tools:
        md.append("## Discovered Tools")
        for tool in results.tools:
            md.append(f"### {tool.name}")
            md.append(f"- **Server**: {tool.server_name}")
            md.append(f"- **Description**: {tool.description}")
            if tool.input_schema:
                md.append(f"- **Schema**:")
                md.append("```json")
                md.append(json.dumps(tool.input_schema, indent=2))
                md.append("```")
            md.append("")
    if results.resources:
        md.append("## Discovered Resources")
        for resource in results.resources:
            md.append(f"### {resource.name}")
            md.append(f"- **URI**: `{resource.uri}`")
            md.append(f"- **Server**: {resource.server_name}")
            md.append(f"- **Description**: {resource.description}")
            md.append(f"- **MIME Type**: {resource.mime_type}")
            md.append("")

    if results.errors:
        md.append("## Errors")
        for error in results.errors:
            md.append(f"- {error}")
        md.append("")

    if results.status:
        md.append("## Status")
        for status_msg in results.status:
            md.append(f"- {status_msg}")
        md.append("")

    return "\n".join(md)


def determine_output_file(args, command_type: str):
    if args.output:
        return args.output
    else:
        return f"{command_type}_results.{args.report_type}"


def save_report_to_file(content, filepath, report_type, suppress_print=False):
    output_path = Path(filepath)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w') as f:
        f.write(content)

    if not suppress_print:
        print(f"Report saved to {output_path}")


async def scan_command(args):
    scanner = MCPConfigScanner()

    custom_paths = []
    if args.config:
        custom_paths.extend(args.config)

    print('\n🏃 Running MCP Checkpoint in scan mode...\n')
    missing_paths = []
    if not custom_paths:
        print("  📄 No config provided — searching known locations…")
    else:
        for p in custom_paths:
            exists = Path(p).exists()
            status_text = " (✅ found)" if exists else " (❌ not found)"
            print(f"  📄 Using config: {p}{status_text}")
            if not exists:
                missing_paths.append(p)
        if missing_paths:
            custom_paths = [p for p in custom_paths if Path(p).exists()]
            if not custom_paths:
                print(
                    "\n  No valid config files found. Please provide at least one valid config file path with --config.")
                sys.exit(1)

    try:
        with SuppressStderr():
            config_files = await scanner.discover_config_files(custom_paths)
            print("     🧩 Parsing configuration…")
            is_user_provided = bool(custom_paths)

            servers = []
            parse_errors = []
            for cfg in config_files:
                try:
                    parsed = await scanner.parse_single_config(cfg, is_user_provided)
                    servers.extend(parsed)
                except Exception as e:
                    parse_errors.append(f"Failed to parse config: {cfg} ({e})")

            if is_user_provided and len(servers) == 0:
                print("\n  ❌ Failed to parse provided config or no MCP servers found in it.")
                for p in config_files:
                    print(f"     ↳ {p}")
                if parse_errors:
                    for err in parse_errors:
                        print(f"     ❌ {err}")
                print("\n  Ensure the file is valid JSON/YAML and follows expected schema (servers/mcpServers).")
                sys.exit(1)

            server_names = [s.name for s in servers]
            if server_names:
                shown = ", ".join(server_names[:5])
                more = f" (+{len(server_names) - 5} more)" if len(server_names) > 5 else ""
                print(f"\n  🔲 Servers found ({len(server_names)}): {shown}{more}")

            failed = []
            seen_oauth = set()
            connected = set()

            def progress_cb(event, data):
                if event == 'failed':
                    name = data.get('server')
                    err = data.get('error', 'error')
                    failed.append((name, err))
                    clean_err = err.replace(f"Failed to connect to server: {name}", "").strip()
                    if not clean_err or clean_err == err:
                        clean_err = err
                    print(f"     ❌ Connection failed: {name} ({clean_err})")
                elif event == 'oauth_wait':
                    name = data.get('server')
                    if name and name not in seen_oauth:
                        seen_oauth.add(name)
                        print(f"        ⏳ Waiting for OAuth: {name}")
                elif event == 'oauth_approved':
                    name = data.get('server')
                    if name and getattr(args, 'verbose', False):
                        print(f"        🆗 Access approved: {name}")
                elif event == 'connected':
                    name = data.get('server')
                    if name:
                        connected.add(name)
                        tools_n = data.get('tools', 0)
                        res_n = data.get('resources', 0)
                        print(f"        🔗 Connected: {name} (tools {tools_n}, resources {res_n})")

            security_scanner = SecurityCheckRunner()
            config_only_result = ScanResult(servers=servers, tools=[], resources=[], config_files=config_files,
                                            errors=[], status=[])
            config_task = asyncio.create_task(security_scanner.run_configuration_checks(config_only_result))
            print("     🔌 Connecting to servers…")
            discovery_task = asyncio.create_task(scanner.discover_tools_and_resources(servers, progress=progress_cb))

            config_issues, (tools, resources) = await asyncio.gather(config_task, discovery_task)

            errors = []
            status = []

            if missing_paths:
                for p in missing_paths:
                    errors.append(f"Config not found: {p}")
                if is_user_provided:
                    total_provided = len(args.config) if args.config else 0
                    missing_count = len(missing_paths)
                    status.append(
                        f"Some provided configs ({missing_count}/{total_provided}) not found. Results exclude those files.")

            if parse_errors:
                errors.extend(parse_errors)
                if is_user_provided:
                    total_cfgs = len(config_files)
                    failed_cfgs = len(parse_errors)
                    status.append(
                        f"Some provided configs ({failed_cfgs}/{total_cfgs}) failed to parse. Results exclude those files.")

            for server_name, error_msg in failed:
                clean_error = error_msg.replace(f"Failed to connect to server: {server_name}", "").strip()
                if not clean_error or clean_error == error_msg:
                    clean_error = error_msg
                errors.append(f"Connection failed to server '{server_name}': {clean_error}")

            enabled_servers = [s for s in servers if not s.disabled]
            total_servers = len(enabled_servers)
            connected_count = len(connected)
            failed_count = len(failed)

            if connected_count == 0 and failed_count > 0:
                status.append("No servers connected. Only configuration checks were run.")
            elif failed_count > 0:
                status.append(
                    f"Some servers ({failed_count}/{total_servers}) failed to connect. Security scan is incomplete for failed servers.")
            elif total_servers == 0:
                status.append("No MCP servers found in configuration. Only configuration checks were run.")
            else:
                status.append("All servers connected. Full security scan completed.")

            if len(connected) == 0:
                print("\n  ⚠️  No servers connected. Running configuration checks only.")
                print("     ‼️  Check your server configurations and network connectivity.")

            print("\n  ✅ Configuration scan complete\n")

            if len(connected) == 0:
                results = ScanResult(servers=servers, tools=[], resources=[], config_files=config_files, errors=errors,
                                     status=status)
                security_report = SecurityReport()
                security_report.all_issues = sort_issues_by_severity(config_issues)
                security_report.total_issues = len(config_issues)
                for issue in config_issues:
                    security_report.issues_by_severity[issue.severity] += 1
                    issue_type = issue.issue_type.split(':')[0]
                    if issue_type not in security_report.issues_by_type:
                        security_report.issues_by_type[issue_type] = 0
                    security_report.issues_by_type[issue_type] += 1
                security_report.risk_level = calculate_risk_level(config_issues)
                results.security_report = security_report
            else:
                print("  🛡️  Running security checks…\n")
                security_report = await security_scanner.perform_security_scan(
                    ScanResult(servers=servers, tools=tools, resources=resources, config_files=config_files,
                               errors=errors, status=status)
                )
                results = ScanResult(servers=servers, tools=tools, resources=resources, config_files=config_files,
                                     errors=errors, status=status)
                results.security_report = security_report

            output_file = determine_output_file(args, "scan")
            if args.report_type == "json":
                output_data = {
                    "servers": [
                        {
                            "name": server.name,
                            "type": server.type.value,
                            "endpoint": server.endpoint,
                            "command": server.command,
                            "args": server.args,
                            "headers": server.headers,
                            "env": server.env,
                            "disabled": server.disabled,
                            "tools": [tool.name for tool in results.tools if tool.server_name == server.name],
                            "resources": [resource.name for resource in results.resources if
                                          resource.server_name == server.name],
                            "source_file": server.source_file
                        }
                        for server in results.servers
                    ],
                    "tools": [
                        {
                            "name": tool.name,
                            "description": tool.description,
                            "input_schema": tool.input_schema,
                            "server_name": tool.server_name,
                            "server_endpoint": tool.server_endpoint
                        }
                        for tool in results.tools
                    ],
                    "resources": [
                        {
                            "uri": resource.uri,
                            "name": resource.name,
                            "description": resource.description,
                            "mime_type": resource.mime_type,
                            "server_name": resource.server_name,
                            "server_endpoint": resource.server_endpoint
                        }
                        for resource in results.resources
                    ],
                    "config_files": results.config_files,
                    "errors": results.errors,
                    "status": results.status,
                    "security_report": {
                        "risk_level": results.security_report.risk_level.value if results.security_report else "NONE",
                        "total_issues": results.security_report.total_issues if results.security_report else 0,
                        "issues_by_severity": {k.value: v for k, v in (
                            results.security_report.issues_by_severity.items() if results.security_report else [])},
                        "issues_by_type": results.security_report.issues_by_type if results.security_report else {},
                        "all_issues": [
                            {k: v for k, v in {
                                "issue_type": issue.issue_type,
                                "severity": issue.severity.value,
                                "description": issue.description,
                                "recommendation": issue.recommendation,
                                "entity_type": issue.entity_type,
                                "affected_server": issue.affected_server,
                                "config_file": issue.config_file,
                                "affected_tool": issue.affected_tool,
                                "affected_resource": issue.affected_resource,
                                "affected_resource_uri": issue.affected_resource_uri,
                                "affected_entities": issue.affected_entities
                            }.items() if v is not None}
                            for issue in (results.security_report.all_issues if results.security_report else [])
                        ]
                    }
                }
                save_report_to_file(json.dumps(output_data, indent=2), output_file, "json", suppress_print=True)
            else:
                markdown_content = format_scan_results_as_markdown(results)
                save_report_to_file(markdown_content, output_file, "markdown", suppress_print=True)

            summary = scanner.get_scan_summary(results)
            print_separator('═', 60)
            print("📊 SUMMARY")
            print_separator('═', 60)
            print(f"🔲 Servers found:        {summary['total_servers']}")
            try:
                connected_count = len(connected)
                print(f"🔗 Connected servers:    {connected_count}/{summary['total_servers']}")
            except Exception:
                pass
            print(f"🔧 Tools found:          {summary['total_tools']}")
            print(f"📁 Resources found:      {summary['total_resources']}")
            print(f"📄 Config files:         {summary['config_files']}")
            if summary['errors'] > 0:
                print(f"❌ Errors:               {summary['errors']}")
            if results.status:
                print(f"💎 Status:")
                for msg in results.status:
                    print(f"   {msg}")
            print()
            print_separator('═', 60)
            risk = results.security_report.risk_level.value if results.security_report else "NONE"
            total_issues = results.security_report.total_issues if results.security_report else 0
            
            if total_issues == 0:
                icon = '✅'
            else:
                icon = get_level_emoji(risk, RISK_EMOJI)
            
            print(f"{icon} SECURITY REPORT")
            print_separator('═', 60)
            print(f"🔺 Total Issues:         {total_issues}")

            if results.security_report and total_issues > 0:
                print(f"\n📊 Issues by Severity:")
                severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
                for sev_name in severity_order:
                    for sev, count in results.security_report.issues_by_severity.items():
                        sev_str = sev.value if hasattr(sev, 'value') else str(sev)
                        if sev_str.upper() == sev_name and count > 0:
                            emoji = get_level_emoji(sev_str, SEVERITY_EMOJI)
                            print(f"   {emoji} {sev_str.upper()}: {count}")

                issues = results.security_report.all_issues
                if issues:
                    if len(issues) > 10:
                        print(f"\n🪲  Sample Issues ({len(issues)} total):")
                        print(f"   ... (showing first 10, see {output_file} for complete report)")
                    else:
                        print(f"\n🪲  Issues ({len(issues)} total):")
                    for i, issue in enumerate(issues[:10], 1):
                        sev_str = issue.severity.value if hasattr(issue.severity, 'value') else str(issue.severity)
                        emoji = get_level_emoji(sev_str, SEVERITY_EMOJI)
                        print(f"\n   [{i}] {emoji} {issue.issue_type} ({sev_str.upper()})")
                        print(wrap_text_with_indent(issue.description or '', indent="       ", max_lines=2))
                        if getattr(args, 'verbose', False):
                            if issue.affected_server:
                                print(f"       🔲 Server: {issue.affected_server}")
                            if issue.entity_type == 'tool' and issue.affected_tool:
                                print(f"       🔧 Tool: {issue.affected_tool}")
                            elif issue.entity_type == 'resource' and issue.affected_resource:
                                print(f"       📁 Resource: {issue.affected_resource}")
                        if issue.recommendation:
                            rec_text = issue.recommendation or ''
                            if rec_text:
                                first_line_indent = "       💡 Recommendation: "
                                subsequent_indent = "       "
                                
                                try:
                                    terminal_width = shutil.get_terminal_size().columns
                                except (OSError, AttributeError):
                                    terminal_width = 80
                                
                                available_width = terminal_width - len(first_line_indent)
                                if available_width < 20:
                                    available_width = 20
                                
                                wrapped_lines = textwrap.wrap(rec_text, width=available_width, break_long_words=False, break_on_hyphens=False)
                                
                                if len(wrapped_lines) > 2:
                                    wrapped_lines = wrapped_lines[:2]
                                    last_line = wrapped_lines[-1]
                                    if len(last_line) + 3 <= available_width:
                                        wrapped_lines[-1] = last_line + "…"
                                    else:
                                        wrapped_lines[-1] = last_line[:available_width-3] + "…"
                                
                                if wrapped_lines:
                                    print(first_line_indent + wrapped_lines[0])
                                    for line in wrapped_lines[1:]:
                                        print(subsequent_indent + line)

            print(f"\n💾 Report saved to {output_file}")
    except Exception as e:
        print(f"Scan failed: {e}", file=sys.stderr)
        sys.exit(1)


async def inspect_command(args):
    scanner = MCPConfigScanner()
    
    custom_paths = []
    if args.config:
        custom_paths.extend(args.config)
    
    print('\n🏃 Running MCP Checkpoint in inspect mode...\n')
    missing_paths = []
    if not custom_paths:
        print("  📄 No config provided — searching known locations…")
    else:
        for p in custom_paths:
            exists = Path(p).exists()
            status_text = " (✅ found)" if exists else " (❌ not found)"
            print(f"  📄 Using config: {p}{status_text}")
            if not exists:
                missing_paths.append(p)
        if missing_paths:
            custom_paths = [p for p in custom_paths if Path(p).exists()]
            if not custom_paths:
                print(
                    "\n  No valid config files found. Please provide at least one valid config file path with --config.")
                sys.exit(1)

    try:
        with SuppressStderr():
            config_files = await scanner.discover_config_files(custom_paths)
            print("     🧩 Parsing configuration…")
            is_user_provided = bool(custom_paths)

            servers = []
            parse_errors = []
            for cfg in config_files:
                try:
                    parsed = await scanner.parse_single_config(cfg, is_user_provided)
                    servers.extend(parsed)
                except Exception as e:
                    parse_errors.append(f"Failed to parse config: {cfg} ({e})")

            if is_user_provided and len(servers) == 0:
                print("\n  ❌ Failed to parse provided config or no MCP servers found in it.")
                for p in config_files:
                    print(f"     ↳ {p}")
                if parse_errors:
                    for err in parse_errors:
                        print(f"     ❌ {err}")
                print("\n  Ensure the file is valid JSON/YAML and follows expected schema (servers/mcpServers).")
                sys.exit(1)

            server_names = [s.name for s in servers]
            if server_names:
                shown = ", ".join(server_names[:5])
                more = f" (+{len(server_names) - 5} more)" if len(server_names) > 5 else ""
                print(f"\n  🔲 Servers found ({len(server_names)}): {shown}{more}")

            connected = set()
            failed = []
            seen_connecting = set()
            seen_oauth = set()

            def progress_cb(event, data):
                if event == 'failed':
                    name = data.get('server')
                    err = data.get('error', 'error')
                    failed.append((name, err))
                    clean_err = err.replace(f"Failed to connect to server: {name}", "").strip()
                    if not clean_err or clean_err == err:
                        clean_err = err
                    print(f"     ❌ Connection failed: {name} ({clean_err})")
                elif event == 'oauth_wait':
                    name = data.get('server')
                    if name and name not in seen_oauth:
                        seen_oauth.add(name)
                        print(f"        ⏳ Waiting for OAuth: {name}")
                elif event == 'oauth_approved':
                    name = data.get('server')
                    if name and getattr(args, 'verbose', False):
                        print(f"        🆗 Access approved: {name}")
                elif event == 'connected':
                    name = data.get('server')
                    if name:
                        connected.add(name)
                        tools_n = data.get('tools', 0)
                        res_n = data.get('resources', 0)
                        print(f"        🔗 Connected: {name} (tools {tools_n}, resources {res_n})")

            print("     🔌 Connecting to servers…")

            tools, resources = await scanner.discover_tools_and_resources(servers, progress=progress_cb)

            errors = []
            status = []

            if missing_paths:
                for p in missing_paths:
                    errors.append(f"Config not found: {p}")
                if is_user_provided:
                    total_provided = len(args.config) if args.config else 0
                    missing_count = len(missing_paths)
                    status.append(
                        f"Some provided configs ({missing_count}/{total_provided}) not found. Results exclude those files.")

            if parse_errors:
                errors.extend(parse_errors)
                if is_user_provided:
                    total_cfgs = len(config_files)
                    failed_cfgs = len(parse_errors)
                    status.append(
                        f"Some provided configs ({failed_cfgs}/{total_cfgs}) failed to parse. Results exclude those files.")

            for server_name, error_msg in failed:
                clean_error = error_msg.replace(f"Failed to connect to server: {server_name}", "").strip()
                if not clean_error or clean_error == error_msg:
                    clean_error = error_msg
                errors.append(f"Connection failed to server '{server_name}': {clean_error}")

            enabled_servers = [s for s in servers if not s.disabled]
            total_servers = len(enabled_servers)
            connected_count = len(connected)
            failed_count = len(failed)

            if connected_count == 0 and (failed_count > 0 or total_servers > 0):
                status.append("No servers connected. Cannot proceed with inspection.")
                print("\n  ⚠️  No servers could be connected. Cannot proceed with inspection.")
                print("      ‼️  Check your server configurations and network connectivity.\n")
                results = ScanResult(servers=servers, tools=[], resources=[], config_files=config_files, errors=errors,
                                     status=status)
            elif total_servers == 0:
                status.append("No servers connected. Cannot proceed with inspection.")
                print("\n  ⚠️  No servers could be connected. Cannot proceed with inspection.")
                print("      ‼️  Check your server configurations and network connectivity.\n")
                results = ScanResult(servers=servers, tools=[], resources=[], config_files=config_files, errors=errors,
                                     status=status)
            elif failed_count > 0:
                status.append(
                    f"Some servers ({failed_count}/{total_servers}) failed to connect. Inspection results are incomplete for failed servers.")
                print("\n  🔍 Discovering tools/resources…\n")
                results = ScanResult(servers=servers, tools=tools, resources=resources, config_files=config_files,
                                     errors=errors, status=status)
            else:
                status.append("All servers connected. Inspection complete.")
                print("\n  🔍 Discovering tools/resources…\n")
                results = ScanResult(servers=servers, tools=tools, resources=resources, config_files=config_files,
                                     errors=errors, status=status)

        output_file = determine_output_file(args, "inspect")

        if args.report_type == "json":
            output_data = {
                "servers": [
                    {
                        "name": server.name,
                        "type": server.type.value,
                        "endpoint": server.endpoint,
                        "command": server.command,
                        "args": server.args,
                        "headers": server.headers,
                        "env": server.env,
                        "disabled": server.disabled,
                        "tools": [tool.name for tool in results.tools if tool.server_name == server.name],
                        "resources": [resource.name for resource in results.resources if
                                      resource.server_name == server.name],
                        "source_file": server.source_file
                    }
                    for server in results.servers
                ],
                "tools": [
                    {
                        "name": tool.name,
                        "description": tool.description,
                        "input_schema": tool.input_schema,
                        "server_name": tool.server_name,
                        "server_endpoint": tool.server_endpoint
                    }
                    for tool in results.tools
                ],
                "resources": [
                    {
                        "uri": resource.uri,
                        "name": resource.name,
                        "description": resource.description,
                        "mime_type": resource.mime_type,
                        "server_name": resource.server_name,
                        "server_endpoint": resource.server_endpoint
                    }
                    for resource in results.resources
                ],
                "config_files": results.config_files,
                "errors": results.errors,
                "status": results.status
            }

            save_report_to_file(json.dumps(output_data, indent=2), output_file, "json", suppress_print=True)

        else:
            markdown_content = format_inspect_results_as_markdown(results)
            save_report_to_file(markdown_content, output_file, "markdown", suppress_print=True)

        summary = scanner.get_scan_summary(results)
        print_separator('═', 60)
        print("📊 SUMMARY")
        print_separator('═', 60)
        print(f"🔲 Servers found:        {summary['total_servers']}")
        try:
            connected_count = len(connected)
            print(f"🔗 Connected servers:    {connected_count}/{summary['total_servers']}")
        except Exception:
            pass
        print(f"🔧 Tools found:          {summary['total_tools']}")
        print(f"📁 Resources found:      {summary['total_resources']}")
        print(f"📄 Config files:         {summary['config_files']}")
        if summary['errors'] > 0:
            print(f"❌ Errors:               {summary['errors']}")
        if results.status:
            print(f"💎 Status:")
            for msg in results.status:
                print(f"   {msg}")
            print()
        print_separator('═', 60)
        print(f"📒 INSPECTION REPORT")
        print_separator('═', 60)
        print(f"📄 Configuration Files ({len(results.config_files)}):")
        for config_file in results.config_files:
            print(f"   • {config_file}")
        
        if results.servers:
            print(f"\n🔲  Servers ({len(results.servers)}):")
            for server in results.servers:
                status = "DISABLED" if server.disabled else "ENABLED"
                status_icon = "⛔" if server.disabled else "✅"
                print(f"   {status_icon} {server.name} ({server.type.value}) - {status}")
                if server.source_file:
                    print(f"      📍 Source: {server.source_file}")
                if server.endpoint:
                    print(f"      🔗 Endpoint: {server.endpoint}")
                if server.command:
                    print(f"      ⚙️  Host Command: {server.command}")
                if server.tools:
                    print(f"      🔧 Host Tools: {', '.join(server.tools)}")
                if server.resources:
                    print(f"      📁 Host Resources: {', '.join(server.resources)}")
                print()
        
        if results.tools:
            print(f"🔧 Tools ({len(results.tools)}):")
            for tool in results.tools:
                print(f"   • {tool.name}")
                print(f"     🔲 Server: {tool.server_name}")
                preview = truncate_lines(tool.description or "", 2).strip()
                if preview:
                    print(f"     📝 Description: {preview}\n")

        if results.resources:
            print(f"\n📁 Resources ({len(results.resources)}):")
            for resource in results.resources:
                print(f"   • {resource.name}")
                print(f"     🔲 Server: {resource.server_name}")
                print(f"     🔗 URI: {resource.uri}")
                if resource.description:
                    rprev = truncate_lines(resource.description, 2).strip()
                    print(f"     📝 Description: {rprev}")
                print(f"     📄 MIME Type: {resource.mime_type}\n")

        print(f"💾 Report saved to {output_file}")

        if any("No servers connected" in status_msg for status_msg in results.status):
            sys.exit(1)
        
    except Exception as e:
        print(f"Inspection failed: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    print_banner()

    parser = argparse.ArgumentParser(

        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
          mcp-checkpoint scan                            # Scan all known locations with security analysis
          mcp-checkpoint scan --config ./config.json     # Scan specific config with security analysis
          mcp-checkpoint scan --config ./config1.json --config ./config2.json        # Scan multiple configs in one run
          mcp-checkpoint scan --output results.json      # Save results to file
          mcp-checkpoint scan --verbose                  # Detailed output
          mcp-checkpoint inspect                         # Discovery only (no security analysis)
          mcp-checkpoint scan --show-logs                # Display debug logs in terminal
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    scan_parser = subparsers.add_parser('scan', help='Scan MCP configurations')
    scan_parser.add_argument('--config', action='append', help='Custom config file path')
    scan_parser.add_argument('--report-type', choices=['json', 'md'], default='json',
                             help='Output format: json or markdown (default: json)')
    scan_parser.add_argument('--output', '-o', help='Output file path (optional)')
    scan_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    scan_parser.add_argument('--show-logs', action='store_true',
                             help='Display debug logs in terminal (logs always saved to file)')
    scan_parser.set_defaults(func=scan_command)
    
    inspect_parser = subparsers.add_parser('inspect', help='Inspect MCP configurations')
    inspect_parser.add_argument('--config', action='append', help='Custom config file path')
    inspect_parser.add_argument('--report-type', choices=['json', 'md'], default='json',
                                help='Output format: json or markdown (default: json)')
    inspect_parser.add_argument('--output', '-o', help='Output file path (optional)')
    inspect_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    inspect_parser.add_argument('--show-logs', action='store_true',
                                help='Display debug logs in terminal (logs always saved to file)')
    inspect_parser.set_defaults(func=inspect_command)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if hasattr(args, 'show_logs') and args.show_logs:
        setup_logging(show_logs=True)
    else:
        setup_logging(show_logs=False)

    asyncio.run(args.func(args))


if __name__ == '__main__':
    main()
