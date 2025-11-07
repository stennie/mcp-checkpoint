import asyncio
import json
import logging
import re
from typing import List, Optional, Set

from ..scanner import ScanResult
from ..security_utils import (
    SecurityIssue,
    Severity,
    create_security_issue,
    extract_tool_content,
    extract_resource_content,
)

logger = logging.getLogger(__name__)

critical_patterns: List[str] = [
    r"\$\(.*?\)",
    r"`.*?`",
    r"\$\{.*?\}",
    r"\b(exec|system|shell_exec|passthru|popen|proc_open)\b",
    r"\b(fork|vfork|clone)\b",
    r"[;&|]\s*\w",
    r"\b(&&|\|\|)\b",
]

context_patterns: List[str] = [
    r"\b(sh|bash|zsh|ksh|csh|tcsh|fish|powershell|pwsh|cmd\.exe|command\.com)\s+(?:-c|-e|--execute)",
    r"\b(python[0-9.]*|python3|py|perl|ruby|node|nodejs|php|java|go|rust)\s+(?:-c|-e|--eval|--execute|run)",
    r"\b(cat|curl|wget|nc|netcat|ncat|telnet|ftp|sftp|scp|ssh|rsync)\b.*[;&|>]",
    r"\b(chmod|chown|rm|mv|cp|mkdir|rmdir|touch|ln)\b.*[;&|>]",
    r"\b(sudo|su)\s+\w+",
    r"\b(kill|killall|pkill)\s+\w+",
    r"\b(mount|umount|fdisk|mkfs|dd)\s+[^\s]+",
    r"\b(systemctl|service|initctl)\s+\w+",
    r"\b(crontab|at|batch)\s+[^\s]+",
    r"\b(tee|sponge)\b.*[>|&]",
    r"\b(ping|traceroute|tracert|nslookup|dig|whois)\b.*[;&|]",
    r"\b(nmap|masscan|zmap|unicornscan)\s+[^\s]+",
    r"\b(powershell|pwsh|wsl|bash|sh)\s+(?:-c|-e)",
    r"\b(mysql|psql|sqlite|mongo|redis-cli|memcached)\b.*[;&|]",
    r"\b(docker|podman|kubectl)\s+(?:exec|run|exec)",
    r"\b(reg|regedit|regsvr32|rundll32|wscript|cscript)\s+[^\s]+",
    r"\b(taskkill|schtasks|wmic)\s+[^\s]+",
]

benign_patterns: List[str] = [
    r"(?:written|developed|coded)\s+in\s+(python|java|go|rust|perl|ruby|node)",
    r"(?:uses|utilizes)\s+(curl|wget|http)\s+(?:to|for)",
    r"(?:example|demo|sample)\s+(?:command|usage|syntax)",
    r"(?:see|refer|check)\s+(?:documentation|docs|readme|manual)",
    r"https?://[\w\-\.]+",
    r"[\w\-\.]+@[\w\-\.]+\.\w+",
]

safe_string = re.compile(r"^[\w\s\-._@:/?#\[\]]+$")

_ENTITY_BATCH_SIZE = 16


def _extract_text_content(content: str) -> str:
    try:
        data = json.loads(content)
        text_parts = []

        if isinstance(data, dict):
            for key in ['description', 'name', 'uri', 'title', 'content']:
                if key in data and data[key]:
                    text_parts.append(str(data[key]))

            if 'input_schema' in data and isinstance(data['input_schema'], dict):
                schema_str = json.dumps(data['input_schema'], indent=2)
                text_parts.append(schema_str)

            if 'output_schema' in data and isinstance(data['output_schema'], dict):
                schema_str = json.dumps(data['output_schema'], indent=2)
                text_parts.append(schema_str)

            if 'tags' in data and isinstance(data['tags'], list):
                tags_str = ' '.join(str(tag) for tag in data['tags'] if tag)
                if tags_str:
                    text_parts.append(tags_str)

        return ' '.join(text_parts)
    except (json.JSONDecodeError, TypeError):
        return content


def _scan_text_for_commands(text: str) -> Set[str]:
    if not text:
        return set()

    segments = re.split(r"[\n\r]+|\s{2,}", text)
    critical_hits: Set[str] = set()
    context_hits: Set[str] = set()
    benign_hits: Set[str] = set()

    for seg in segments:
        if not isinstance(seg, str):
            continue
        s = seg.strip()
        if not s or safe_string.match(s):
            continue

        for pat in critical_patterns:
            if re.search(pat, s, re.IGNORECASE):
                critical_hits.add(pat)

        for pat in context_patterns:
            if re.search(pat, s, re.IGNORECASE):
                context_hits.add(pat)

    text_lower = text.lower()
    for pat in benign_patterns:
        if re.search(pat, text_lower, re.IGNORECASE):
            benign_hits.add(pat)

    critical_count = len(critical_hits)
    context_count = len(context_hits)
    malicious_count = critical_count + context_count
    benign_count = len(benign_hits)

    all_hits = critical_hits | context_hits

    if critical_count >= 2:
        return all_hits

    if critical_count >= 1 and context_count >= 1:
        return all_hits

    if malicious_count >= 2 and benign_count < malicious_count:
        return all_hits

    if malicious_count >= 3:
        return all_hits

    return set()


async def _scan_single_tool(tool, servers_list) -> Optional[SecurityIssue]:
    try:
        server = next((s for s in servers_list if s.name == tool.server_name), None)
        config_file = server.source_file if server else None

        tool_content = extract_tool_content(tool)
        text_content = _extract_text_content(tool_content)
        
        loop = asyncio.get_event_loop()
        matches = await loop.run_in_executor(None, _scan_text_for_commands, text_content)

        if matches:
            examples = list(matches)[:3]
            examples_str = "; ".join([p[:50] for p in examples])

            description = (
                "Command-execution indicators detected in tool description/metadata "
                f"(found {len(matches)} patterns)."
            )

            recommendation = (
                "Integrate only trusted MCP servers; block tools exposing hidden or unsafe commands in metadata. "
                "Periodically scan for tool poisoning and rug pull risks to prevent command injection and unauthorized data exfiltration."
            )

            issue = create_security_issue(
                issue_type="Command Injection",
                severity=Severity.CRITICAL,
                description=description,
                recommendation=recommendation,
                entity_type="tool",
                affected_tool=tool.name,
                affected_server=tool.server_name,
                config_file=config_file,
                affected_entities={
                    "pattern_count": len(matches),
                    "examples": [str(p) for p in examples[:3]]
                }
            )
            logger.warning(
                f"Command injection detected in tool: {tool.name} (found {len(matches)} pattern groups)")
            return issue
        return None
    except Exception as e:
        logger.error(f"Error scanning tool {tool.name} for command injection: {e}")
        return None


async def _scan_single_resource(resource, servers_list) -> Optional[SecurityIssue]:
    try:
        server = next((s for s in servers_list if s.name == resource.server_name), None)
        config_file = server.source_file if server else None

        resource_content = extract_resource_content(resource)
        text_content = _extract_text_content(resource_content)
        
        loop = asyncio.get_event_loop()
        matches = await loop.run_in_executor(None, _scan_text_for_commands, text_content)

        if matches:
            examples = list(matches)[:3]
            examples_str = "; ".join([p[:50] for p in examples])

            description = (
                "Command-execution indicators detected in resource metadata "
                f"(found {len(matches)} risky patterns)."
            )

            recommendation = (
                "Integrate only trusted MCP servers. Block resources exposing hidden or unsafe commands in metadata. "
                "Periodically scan for resource poisoning and rug-pull risks to prevent command injection and unauthorized data exfiltration."
            )

            issue = create_security_issue(
                issue_type="Command Injection",
                severity=Severity.CRITICAL,
                description=description,
                recommendation=recommendation,
                entity_type="resource",
                affected_resource=resource.name,
                affected_resource_uri=resource.uri,
                affected_server=resource.server_name,
                config_file=config_file,
                affected_entities={
                    "pattern_count": len(matches),
                    "examples": [str(p) for p in examples[:3]]
                }
            )
            logger.warning(
                f"Command injection detected in resource: {resource.uri} (found {len(matches)} pattern groups)")
            return issue
        return None
    except Exception as e:
        logger.error(f"Error scanning resource {resource.uri} for command injection: {e}")
        return None


async def scan_for_command_injection(scan_result: ScanResult) -> List[SecurityIssue]:
    issues: List[SecurityIssue] = []

    if not scan_result.tools and not scan_result.resources:
        return issues

    logger.info(f"Scanning {len(scan_result.tools)} tools and {len(scan_result.resources)} resources for command injection")

    if scan_result.tools:
        for i in range(0, len(scan_result.tools), _ENTITY_BATCH_SIZE):
            batch = scan_result.tools[i:i + _ENTITY_BATCH_SIZE]
            tasks = [_scan_single_tool(tool, scan_result.servers) for tool in batch]
            
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in batch_results:
                if result is not None and not isinstance(result, Exception):
                    issues.append(result)
                elif isinstance(result, Exception):
                    logger.error(f"Unexpected exception in tool scan: {result}")

    if scan_result.resources:
        for i in range(0, len(scan_result.resources), _ENTITY_BATCH_SIZE):
            batch = scan_result.resources[i:i + _ENTITY_BATCH_SIZE]
            tasks = [_scan_single_resource(resource, scan_result.servers) for resource in batch]
            
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in batch_results:
                if result is not None and not isinstance(result, Exception):
                    issues.append(result)
                elif isinstance(result, Exception):
                    logger.error(f"Unexpected exception in resource scan: {result}")

    logger.info(f"Command injection scan completed: {len(issues)} issues found")
    return issues
