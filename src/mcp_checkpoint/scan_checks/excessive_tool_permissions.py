import asyncio
import json
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

from ..scanner import ScanResult
from ..security_utils import SecurityIssue, Severity, create_security_issue

RISKY_COMMAND_SUBSTRINGS: Tuple[str, ...] = (
    "bash",
    "python",
    "python3",
    "sh",
    "zsh",
    "powershell",
    "cmd",
    "busybox",
    "ash",
)

RISKY_ARG_FLAGS: Set[str] = {
    "--allow-terminal",
    "--allow-filesystem",
    "--unsafe",
    "--privileged",
    "--root",
}

CRITICAL_PERMISSIONS: Set[str] = {
    "*",
    "all",
    "admin",
    "superuser",
    "terminal:*",
    "terminal:exec",
}

CRITICAL_FILESYSTEM_PERMISSIONS: Set[str] = {
    "filesystem:*",
    "filesystem:write",
    "filesystem:delete",
}

_CRITICAL_PERMS_ALL_LOWER: Set[str] = {
    p.lower() for p in (CRITICAL_PERMISSIONS | CRITICAL_FILESYSTEM_PERMISSIONS)
}


def _load_config_file(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        try:
            return json.loads(content)
        except Exception:
            return yaml.safe_load(content)
    except Exception:
        return None


def _normalize_list_of_str(values: Any) -> List[str]:
    if isinstance(values, list):
        result: List[str] = []
        for v in values:
            try:
                result.append(str(v))
            except Exception:
                continue
        return result
    return []


def _check_server_entry(server_name: str, details: Dict[str, Any]) -> Dict[str, Any]:
    risky_permissions: List[str] = []
    risky_flags: List[str] = []
    risky_command: Optional[str] = None

    disabled = bool(isinstance(details, dict) and details.get("enabled") is False)

    command = str(details.get("command", "")) if isinstance(details, dict) else ""
    args = _normalize_list_of_str(details.get("args", [])) if isinstance(details, dict) else []
    permissions_list = []
    if isinstance(details, dict):
        permissions_list.extend(_normalize_list_of_str(details.get("permissions", [])))
        permissions_list.extend(_normalize_list_of_str(details.get("additional_permissions", [])))
    permissions = permissions_list

    cmd_lower = command.lower()
    if any(tok in cmd_lower for tok in RISKY_COMMAND_SUBSTRINGS if cmd_lower):
        risky_command = command

    lowered_args = [a.lower() for a in args]
    for flag in RISKY_ARG_FLAGS:
        if any(a.startswith(flag) for a in lowered_args):
            risky_flags.append(flag)

    for p in permissions:
        pl = p.lower()
        if pl in _CRITICAL_PERMS_ALL_LOWER:
            risky_permissions.append(p)

    return {
        "skip": False,
        "disabled": disabled,
        "server": server_name,
        "risky_permissions": risky_permissions,
        "risky_flags": risky_flags,
        "risky_command": risky_command,
    }


async def scan_for_excessive_tool_permissions(scan_result: ScanResult) -> List[SecurityIssue]:
    issues: List[SecurityIssue] = []
    if not scan_result.config_files:
        return issues

    unique_files: List[str] = []
    seen: Set[str] = set()
    for path in scan_result.config_files:
        if path and path not in seen:
            seen.add(path)
            unique_files.append(path)

    loop = asyncio.get_event_loop()
    tasks = [loop.run_in_executor(None, _load_config_file, path) for path in unique_files]
    parsed_list = await asyncio.gather(*tasks, return_exceptions=False)

    server_to_tools: Dict[str, List[str]] = {}
    for t in scan_result.tools or []:
        if getattr(t, "server_name", None):
            server_to_tools.setdefault(t.server_name, []).append(t.name)

    for cfg, cfg_path in zip(parsed_list, unique_files):
        if not isinstance(cfg, dict):
            continue

        server_maps: List[Dict[str, Any]] = []
        for key in ("mcpServers", "servers"):
            obj = cfg.get(key)
            if isinstance(obj, dict):
                server_maps.append(obj)

        if not server_maps:
            continue

        for servers_obj in server_maps:
            tasks = []
            names: List[str] = []
            for server_name, details in servers_obj.items():
                if not isinstance(details, dict):
                    continue
                names.append(str(server_name))
                tasks.append(asyncio.to_thread(_check_server_entry, str(server_name), details))

            if not tasks:
                continue

            results = await asyncio.gather(*tasks, return_exceptions=False)

            for server_name, result in zip(names, results):
                if result.get("skip"):
                    continue

                if result.get("disabled"):
                    indicators: List[str] = []
                    if result.get("risky_permissions"):
                        indicators.append("risky_permissions")
                    if result.get("risky_flags"):
                        indicators.append("risky_command_flags")
                    if result.get("risky_command"):
                        indicators.append("risky_command")

                    desc = (
                        f"Server '{server_name}' is disabled but excessive host permissions detected for tools running on it."
                    )
                    if indicators:
                        desc = f"{desc} Indicators: {', '.join(indicators)}."

                    entities: Dict[str, Any] = {
                        "disabled": True,
                        "risky_tools": server_to_tools.get(server_name, []),
                    }
                    if result.get("risky_permissions"):
                        entities["risky_permissions"] = result.get("risky_permissions")
                    if result.get("risky_flags"):
                        entities["risky_command_flags"] = result.get("risky_flags")
                    if result.get("risky_command"):
                        entities["risky_command"] = result.get("risky_command")

                    issues.append(
                        create_security_issue(
                            issue_type="Excessive Tool Permissions",
                            severity=Severity.LOW,
                            description=desc,
                            recommendation=(
                                "Restrict MCP server privileges on the host. Remove wildcard or admin user permissions, and terminal or file-system flags. "
                                "Keep only the least privileges required."
                            ),
                            entity_type="configuration",
                            affected_server=server_name,
                            config_file=cfg_path,
                            affected_entities=entities,
                        )
                    )
                    continue

                risky_permissions = result.get("risky_permissions", [])
                risky_flags = result.get("risky_flags", [])
                risky_command = result.get("risky_command")

                if not risky_permissions and not risky_flags and not risky_command:
                    continue

                severity = Severity.CRITICAL

                indicators: List[str] = []
                if risky_permissions:
                    indicators.append("risky_permissions")
                if risky_flags:
                    indicators.append("risky_command_flags")
                if risky_command:
                    indicators.append("risky_command")

                desc = (
                    f"Excessive host permissions detected for tools on server '{server_name}'. "
                    f"Indicators: {', '.join(indicators)}."
                )

                recommendation = (
                    "Restrict MCP server privileges on the host. Remove wildcard/admin user permissions and terminal/file-system flags; "
                    "keep only least privileges required."
                )

                matched_entities: Dict[str, Any] = {
                    "risky_tools": server_to_tools.get(server_name, []),
                }
                if risky_permissions:
                    matched_entities["risky_permissions"] = risky_permissions
                if risky_flags:
                    matched_entities["risky_command_flags"] = risky_flags
                if risky_command:
                    matched_entities["risky_command"] = risky_command

                issues.append(
                    create_security_issue(
                        issue_type="Excessive Tool Permissions",
                        severity=severity,
                        description=desc,
                        recommendation=recommendation,
                        entity_type="configuration",
                        affected_server=server_name,
                        config_file=cfg_path,
                        affected_entities=matched_entities,
                    )
                )

    return issues
