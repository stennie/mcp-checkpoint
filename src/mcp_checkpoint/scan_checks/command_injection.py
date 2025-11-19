import asyncio
import json
import logging
import re
from typing import List, Optional, Set, Pattern, Tuple

from ..security_utils import (
    ScanResult,
    SecurityIssue,
    Severity,
    create_security_issue,
    extract_tool_content,
    extract_resource_content,
    extract_prompt_content,
    extract_resource_template_content,
    extract_text_content,
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

_COMPILED_CRITICAL_PATTERNS: Optional[List[Pattern]] = None
_COMPILED_CONTEXT_PATTERNS: Optional[List[Pattern]] = None
_COMPILED_BENIGN_PATTERNS: Optional[List[Pattern]] = None


def _get_compiled_patterns() -> Tuple[List[Pattern], List[Pattern], List[Pattern]]:
    global _COMPILED_CRITICAL_PATTERNS, _COMPILED_CONTEXT_PATTERNS, _COMPILED_BENIGN_PATTERNS
    
    if _COMPILED_CRITICAL_PATTERNS is None:
        _COMPILED_CRITICAL_PATTERNS = []
        for pattern_str in critical_patterns:
            try:
                _COMPILED_CRITICAL_PATTERNS.append(re.compile(pattern_str, re.IGNORECASE))
            except re.error as e:
                logger.warning(f"Failed to compile critical pattern '{pattern_str}': {e}")
        
        _COMPILED_CONTEXT_PATTERNS = []
        for pattern_str in context_patterns:
            try:
                _COMPILED_CONTEXT_PATTERNS.append(re.compile(pattern_str, re.IGNORECASE))
            except re.error as e:
                logger.warning(f"Failed to compile context pattern '{pattern_str}': {e}")
        
        _COMPILED_BENIGN_PATTERNS = []
        for pattern_str in benign_patterns:
            try:
                _COMPILED_BENIGN_PATTERNS.append(re.compile(pattern_str, re.IGNORECASE))
            except re.error as e:
                logger.warning(f"Failed to compile benign pattern '{pattern_str}': {e}")
    
    return _COMPILED_CRITICAL_PATTERNS, _COMPILED_CONTEXT_PATTERNS, _COMPILED_BENIGN_PATTERNS


def _scan_text_for_commands(text: str) -> Tuple[Set[str], List[str]]:
    if not text:
        return set(), []

    compiled_critical, compiled_context, compiled_benign = _get_compiled_patterns()

    segments = re.split(r"[\n\r]+|\s{2,}", text)
    critical_hits: Set[str] = set()
    context_hits: Set[str] = set()
    benign_hits: Set[str] = set()
    matched_snippets: List[str] = []

    for seg in segments:
        if not isinstance(seg, str):
            continue
        s = seg.strip()
        if not s or safe_string.match(s):
            continue

        for i, compiled_pat in enumerate(compiled_critical):
            match = compiled_pat.search(s)
            if match:
                critical_hits.add(critical_patterns[i])
                start = max(0, match.start() - 50)
                end = min(len(s), match.end() + 50)
                context_snippet = s[start:end].strip()
                if context_snippet and context_snippet not in matched_snippets:
                    matched_snippets.append(context_snippet[:150])

        for i, compiled_pat in enumerate(compiled_context):
            match = compiled_pat.search(s)
            if match:
                context_hits.add(context_patterns[i])
                start = max(0, match.start() - 50)
                end = min(len(s), match.end() + 50)
                context_snippet = s[start:end].strip()
                if context_snippet and context_snippet not in matched_snippets:
                    matched_snippets.append(context_snippet[:150])

    text_lower = text.lower()
    for i, compiled_pat in enumerate(compiled_benign):
        if compiled_pat.search(text_lower):
            benign_hits.add(benign_patterns[i])

    critical_count = len(critical_hits)
    context_count = len(context_hits)
    malicious_count = critical_count + context_count
    benign_count = len(benign_hits)

    all_hits = critical_hits | context_hits

    if critical_count >= 2:
        return all_hits, matched_snippets[:5]

    if critical_count >= 1 and context_count >= 1:
        return all_hits, matched_snippets[:5]

    if malicious_count >= 2 and benign_count < malicious_count:
        return all_hits, matched_snippets[:5]

    if malicious_count >= 3:
        return all_hits, matched_snippets[:5]

    return set(), []


async def _scan_single_tool(tool, servers_list) -> Optional[SecurityIssue]:
    try:
        server = next((s for s in servers_list if s.name == tool.server_name), None)
        config_file = server.source_file if server else None

        tool_content = extract_tool_content(tool)
        text_content = extract_text_content(tool_content)
        
        matches, matched_content = await asyncio.to_thread(_scan_text_for_commands, text_content)

        if matches:
            issue = create_security_issue(
                issue_type="Command Injection",
                severity=Severity.CRITICAL,
                entity_type="tool",
                affected_tool=tool.name,
                affected_server=tool.server_name,
                config_file=config_file,
                affected_entities={
                    "pattern_count": len(matches),
                    "matched_content": matched_content
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
        text_content = extract_text_content(resource_content)
        
        matches, matched_content = await asyncio.to_thread(_scan_text_for_commands, text_content)

        if matches:
            issue = create_security_issue(
                issue_type="Command Injection",
                severity=Severity.CRITICAL,
                entity_type="resource",
                affected_resource=resource.name,
                affected_resource_uri=resource.uri,
                affected_server=resource.server_name,
                config_file=config_file,
                affected_entities={
                    "pattern_count": len(matches),
                    "matched_content": matched_content
                }
            )
            logger.warning(
                f"Command injection detected in resource: {resource.uri} (found {len(matches)} pattern groups)")
            return issue
        return None
    except Exception as e:
        logger.error(f"Error scanning resource {resource.uri} for command injection: {e}")
        return None


async def scan_for_tool_command_injection(scan_result: ScanResult) -> List[SecurityIssue]:
    issues: List[SecurityIssue] = []

    if not scan_result.tools:
        return issues

    logger.info(f"Scanning {len(scan_result.tools)} tools for command injection")

    for i in range(0, len(scan_result.tools), _ENTITY_BATCH_SIZE):
        batch = scan_result.tools[i:i + _ENTITY_BATCH_SIZE]
        tasks = [_scan_single_tool(tool, scan_result.servers) for tool in batch]
        
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in batch_results:
            if result is not None and not isinstance(result, Exception):
                issues.append(result)
            elif isinstance(result, Exception):
                logger.error(f"Unexpected exception in tool scan: {result}")

    logger.info(f"Tool command injection scan completed: {len(issues)} issues found")
    return issues


async def scan_for_resource_command_injection(scan_result: ScanResult) -> List[SecurityIssue]:
    issues: List[SecurityIssue] = []

    if not scan_result.resources:
        return issues

    logger.info(f"Scanning {len(scan_result.resources)} resources for command injection")

    for i in range(0, len(scan_result.resources), _ENTITY_BATCH_SIZE):
        batch = scan_result.resources[i:i + _ENTITY_BATCH_SIZE]
        tasks = [_scan_single_resource(resource, scan_result.servers) for resource in batch]
        
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in batch_results:
            if result is not None and not isinstance(result, Exception):
                issues.append(result)
            elif isinstance(result, Exception):
                logger.error(f"Unexpected exception in resource scan: {result}")

    logger.info(f"Resource command injection scan completed: {len(issues)} issues found")
    return issues


async def _scan_single_prompt(prompt, servers_list) -> Optional[SecurityIssue]:
    try:
        server = next((s for s in servers_list if s.name == prompt.server_name), None)
        config_file = server.source_file if server else None

        prompt_content = extract_prompt_content(prompt)
        text_content = extract_text_content(prompt_content)
        
        matches, matched_content = await asyncio.to_thread(_scan_text_for_commands, text_content)

        if matches:
            issue = create_security_issue(
                issue_type="Command Injection",
                severity=Severity.CRITICAL,
                entity_type="prompt",
                affected_server=prompt.server_name,
                config_file=config_file,
                affected_entities={
                    "pattern_count": len(matches),
                    "matched_content": matched_content
                }
            )
            logger.warning(
                f"Command injection detected in prompt: {prompt.name} (found {len(matches)} pattern groups)")
            return issue
        return None
    except Exception as e:
        logger.error(f"Error scanning prompt {prompt.name} for command injection: {e}")
        return None


async def _scan_single_resource_template(template, servers_list) -> Optional[SecurityIssue]:
    try:
        server = next((s for s in servers_list if s.name == template.server_name), None)
        config_file = server.source_file if server else None

        template_content = extract_resource_template_content(template)
        text_content = extract_text_content(template_content)
        
        matches, matched_content = await asyncio.to_thread(_scan_text_for_commands, text_content)

        if matches:
            issue = create_security_issue(
                issue_type="Command Injection",
                severity=Severity.CRITICAL,
                entity_type="resource_template",
                affected_server=template.server_name,
                config_file=config_file,
                affected_entities={
                    "resource_template": template.name,
                    "uri_template": template.uri_template,
                    "pattern_count": len(matches),
                    "matched_content": matched_content
                }
            )
            logger.warning(
                f"Command injection detected in resource template: {template.uri_template} (found {len(matches)} pattern groups)")
            return issue
        return None
    except Exception as e:
        logger.error(f"Error scanning resource template {template.uri_template} for command injection: {e}")
        return None


async def scan_for_prompt_command_injection(scan_result: ScanResult) -> List[SecurityIssue]:
    issues: List[SecurityIssue] = []

    if not scan_result.prompts:
        return issues

    logger.info(f"Scanning {len(scan_result.prompts)} prompts for command injection")

    for i in range(0, len(scan_result.prompts), _ENTITY_BATCH_SIZE):
        batch = scan_result.prompts[i:i + _ENTITY_BATCH_SIZE]
        tasks = [_scan_single_prompt(prompt, scan_result.servers) for prompt in batch]
        
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in batch_results:
            if result is not None and not isinstance(result, Exception):
                issues.append(result)
            elif isinstance(result, Exception):
                logger.error(f"Unexpected exception in prompt scan: {result}")

    logger.info(f"Prompt command injection scan completed: {len(issues)} issues found")
    return issues


async def scan_for_resource_template_command_injection(scan_result: ScanResult) -> List[SecurityIssue]:
    issues: List[SecurityIssue] = []

    if not scan_result.resource_templates:
        return issues

    logger.info(f"Scanning {len(scan_result.resource_templates)} resource templates for command injection")

    for i in range(0, len(scan_result.resource_templates), _ENTITY_BATCH_SIZE):
        batch = scan_result.resource_templates[i:i + _ENTITY_BATCH_SIZE]
        tasks = [_scan_single_resource_template(template, scan_result.servers) for template in batch]
        
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in batch_results:
            if result is not None and not isinstance(result, Exception):
                issues.append(result)
            elif isinstance(result, Exception):
                logger.error(f"Unexpected exception in resource template scan: {result}")

    logger.info(f"Resource template command injection scan completed: {len(issues)} issues found")
    return issues