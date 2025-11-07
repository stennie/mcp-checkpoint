import asyncio
import json
import re
from typing import Dict, List, Set, Tuple

from ..scanner import ScanResult, ToolInfo
from ..security_utils import SecurityIssue, Severity, create_security_issue, extract_tool_content


def _normalize(name: str) -> str:
    return (name or "").strip().lower()


def _build_patterns_with_names(name_set: Set[str], exclude: Set[str]) -> List[Tuple[re.Pattern, str]]:
    patterns = []
    for name in name_set:
        norm = _normalize(name)
        if norm not in exclude and len(name.strip()) >= 3:
            escaped = re.escape(name)
            patterns.append((re.compile(rf"\b{escaped}\b", re.IGNORECASE), name))
    return patterns


def _scan_single_tool(
        tool: ToolInfo,
        tool_patterns: List[Tuple[re.Pattern, str]],
        server_patterns: List[Tuple[re.Pattern, str]],
        tool_to_servers: Dict[str, Set[str]],
) -> Tuple[Set[str], Set[str]]:
    content = extract_tool_content(tool)
    ref_tools = set()
    ref_servers = set()

    for pattern, orig_tool_name in tool_patterns:
        referenced_servers = tool_to_servers.get(orig_tool_name, set())

        if not referenced_servers:
            continue

        if orig_tool_name == tool.name:
            tool_data = {
                "description": tool.description,
                "input_schema": tool.input_schema,
                "server_name": tool.server_name,
                "server_endpoint": tool.server_endpoint
            }
            content_without_name = json.dumps(tool_data, indent=2)
            if not pattern.search(content_without_name):
                continue
        elif not pattern.search(content):
            continue

        if orig_tool_name != tool.name and tool.server_name and tool.server_name not in referenced_servers:
            ref_tools.add(orig_tool_name)
        elif orig_tool_name == tool.name and len(referenced_servers) > 1:
            mentioned_cross_servers = set()
            for srv in referenced_servers:
                if srv and srv != tool.server_name:
                    if re.search(rf"\b{re.escape(srv)}\b", content, re.IGNORECASE):
                        mentioned_cross_servers.add(srv)
            if mentioned_cross_servers:
                ref_tools.add(orig_tool_name)

    for pattern, orig_server_name in server_patterns:
        if pattern.search(content) and orig_server_name != tool.server_name:
            ref_servers.add(orig_server_name)

    return ref_tools, ref_servers


async def scan_for_cross_server_tool_shadowing(scan_result: ScanResult) -> List[SecurityIssue]:
    if not scan_result.tools:
        return []

    tool_names: Dict[str, str] = {}
    tool_to_servers: Dict[str, Set[str]] = {}
    server_names: Set[str] = set()

    for tool in scan_result.tools:
        tool_names[_normalize(tool.name)] = tool.name
        if tool.name and tool.server_name:
            if tool.name not in tool_to_servers:
                tool_to_servers[tool.name] = set()
            tool_to_servers[tool.name].add(tool.server_name)
        if tool.server_name:
            server_names.add(tool.server_name)

    for server in scan_result.servers:
        if server.name:
            server_names.add(server.name)

    issues: List[SecurityIssue] = []
    loop = asyncio.get_event_loop()

    for tool in scan_result.tools:
        exclude_servers = {_normalize(tool.server_name)} if tool.server_name else set()

        tool_patterns = _build_patterns_with_names(
            set(tool_names.values()), set()
        )
        server_patterns = _build_patterns_with_names(server_names, exclude_servers)

        ref_tools, ref_servers = await loop.run_in_executor(
            None, _scan_single_tool, tool, tool_patterns, server_patterns, tool_to_servers
        )

        if ref_tools or ref_servers:
            severity = Severity.HIGH if ref_tools else Severity.MEDIUM
            tool_list = sorted(ref_tools)
            server_list = sorted(ref_servers)

            parts = []
            if tool_list:
                parts.append(f"tools {tool_list}")
            if server_list:
                parts.append(f"servers {server_list}")

            contexts_str = ", ".join(parts)
            count_parts = []
            if ref_tools:
                count_parts.append(f"{len(ref_tools)} cross tool name reference{'s' if len(ref_tools) != 1 else ''}")
            if ref_servers:
                count_parts.append(
                    f"{len(ref_servers)} cross server name reference{'s' if len(ref_servers) != 1 else ''}")

            description = (
                f"Tool '{tool.name}' (server: {tool.server_name}) references cross boundary contexts: "
                f"{contexts_str}. "
                f"This may bypass trust boundaries and cause agent misselection. "
                f"Found {', '.join(count_parts)}."
            )

            server_obj = next(
                (s for s in scan_result.servers if s.name == tool.server_name), None
            )
            config_file = server_obj.source_file if server_obj else None

            issues.append(
                create_security_issue(
                    issue_type="Cross-Server Tool Shadowing",
                    severity=severity,
                    description=description,
                    recommendation="Connect only trusted MCP servers. Enforce strict tool namespace isolation by assigning a unique namespace or prefix to each tool based on its originating MCP server, and implement guardrails to detect and block suspicious cross-server references or manipulation.",
                    entity_type="tool",
                    affected_tool=tool.name,
                    affected_server=tool.server_name,
                    config_file=config_file,
                )
            )

    return issues
