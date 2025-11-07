import re
import json
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

from .scanner import MCPServerInfo, ToolInfo, ResourceInfo, ScanResult

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityIssue:
    issue_type: str
    severity: Severity
    description: str
    recommendation: str

    entity_type: Optional[str] = None
    affected_server: Optional[str] = None
    config_file: Optional[str] = None
    affected_tool: Optional[str] = None
    affected_resource: Optional[str] = None
    affected_resource_uri: Optional[str] = None
    affected_entities: Optional[Dict[str, Any]] = None


def create_security_issue(
        issue_type: str,
        severity: Severity,
        description: str,
        recommendation: str,
        entity_type: Optional[str] = None,
        affected_server: Optional[str] = None,
        config_file: Optional[str] = None,
        affected_tool: Optional[str] = None,
        affected_resource: Optional[str] = None,
        affected_resource_uri: Optional[str] = None,
        affected_entities: Optional[Dict[str, Any]] = None
) -> SecurityIssue:
    return SecurityIssue(
        issue_type=issue_type,
        severity=severity,
        description=description,
        recommendation=recommendation,
        entity_type=entity_type,
        affected_server=affected_server,
        config_file=config_file,
        affected_tool=affected_tool,
        affected_resource=affected_resource,
        affected_resource_uri=affected_resource_uri,
        affected_entities=affected_entities
    )


def extract_server_content(server: MCPServerInfo) -> str:
    config_data = {
        "name": server.name,
        "type": server.type.value,
        "endpoint": server.endpoint,
        "command": server.command,
        "args": server.args,
        "headers": server.headers,
        "env": server.env,
        "tools": server.tools,
        "resources": server.resources,
        "additional_permissions": server.additional_permissions
    }
    return json.dumps(config_data, indent=2)


def extract_tool_content(tool: ToolInfo) -> str:
    tool_data = {
        "name": tool.name,
        "title": getattr(tool, 'title', None),
        "description": tool.description,
        "input_schema": tool.input_schema,
        "output_schema": getattr(tool, 'output_schema', None),
        "tags": getattr(tool, 'tags', None) or [],
        "server_name": tool.server_name,
        "server_endpoint": tool.server_endpoint
    }
    return json.dumps(tool_data, indent=2)


def extract_resource_content(resource: ResourceInfo) -> str:
    resource_data = {
        "uri": resource.uri,
        "name": resource.name,
        "title": getattr(resource, 'title', None),
        "description": resource.description,
        "mime_type": resource.mime_type,
        "tags": getattr(resource, 'tags', None) or [],
        "server_name": resource.server_name,
        "server_endpoint": resource.server_endpoint
    }
    return json.dumps(resource_data, indent=2)


def match_patterns(text: str, patterns: List[str]) -> List[str]:
    matches = []
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            matches.append(pattern)
    return matches


def find_pattern_matches(text: str, pattern_categories: Dict[str, List[str]]) -> Dict[str, List[str]]:
    matches = {}
    for category, patterns in pattern_categories.items():
        category_matches = match_patterns(text, patterns)
        if category_matches:
            matches[category] = category_matches
    return matches


def sort_issues_by_severity(issues: List[SecurityIssue]) -> List[SecurityIssue]:
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3
    }
    
    return sorted(
        issues,
        key=lambda issue: (
            severity_order.get(issue.severity, 99),
            issue.issue_type or "",
            issue.affected_server or ""
        )
    )


def calculate_risk_level(issues: List[SecurityIssue]) -> RiskLevel:
    if not issues:
        return RiskLevel.NONE

    severity_order = {
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4
    }

    highest_severity = max(issues, key=lambda issue: severity_order[issue.severity]).severity

    severity_to_risk = {
        Severity.CRITICAL: RiskLevel.CRITICAL,
        Severity.HIGH: RiskLevel.HIGH,
        Severity.MEDIUM: RiskLevel.MEDIUM,
        Severity.LOW: RiskLevel.LOW
    }

    return severity_to_risk[highest_severity]
