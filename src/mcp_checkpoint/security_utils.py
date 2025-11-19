import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


MAX_CONFIG_FILE_SIZE = 10 * 1024 * 1024  # 10MB for config files
MAX_BASELINE_FILE_SIZE = 50 * 1024 * 1024  # 50MB for baseline files


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


class TransportType(Enum):
    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"


@dataclass
class MCPServerInfo:
    name: str
    type: TransportType
    endpoint: Optional[str] = None
    command: Optional[str] = None
    args: List[str] = None
    headers: Dict[str, str] = None
    env: Dict[str, str] = None
    disabled: bool = False
    tools: List[str] = None
    resources: List[str] = None
    additional_permissions: List[str] = None
    source_file: Optional[str] = None
    
    def __post_init__(self):
        if self.args is None:
            self.args = []
        if self.headers is None:
            self.headers = {}
        if self.env is None:
            self.env = {}
        if self.tools is None:
            self.tools = []
        if self.resources is None:
            self.resources = []


@dataclass
class ResourceInfo:
    uri: str
    name: str
    description: str
    mime_type: str
    server_name: str
    server_endpoint: str
    config_file: str = ""
    title: Optional[str] = None
    tags: List[str] = field(default_factory=list)


@dataclass
class ToolInfo:
    name: str
    
    description: str = ""
    input_schema: Dict[str, Any] = field(default_factory=dict)
    server_name: str = ""
    server_endpoint: str = ""
    config_file: str = ""
    title: Optional[str] = None
    output_schema: Optional[Dict[str, Any]] = None
    tags: List[str] = field(default_factory=list)


@dataclass
class PromptInfo:
    name: str
    description: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    server_name: str = ""
    server_endpoint: str = ""
    config_file: str = ""
    title: Optional[str] = None
    tags: List[str] = field(default_factory=list)


@dataclass
class ResourceTemplateInfo:
    uri_template: str
    name: str
    description: str
    mime_type: str
    server_name: str = ""
    server_endpoint: str = ""
    config_file: str = ""
    title: Optional[str] = None
    tags: List[str] = field(default_factory=list)


@dataclass
class ScanResult:
    servers: List[MCPServerInfo]
    tools: List[ToolInfo]
    resources: List[ResourceInfo]
    prompts: List[PromptInfo]
    resource_templates: List[ResourceTemplateInfo]
    config_files: List[str]
    errors: List[str] = field(default_factory=list)
    status: List[str] = field(default_factory=list)


@dataclass
class SecurityIssue:
    issue_type: str
    severity: Severity
    description: Optional[str] = None
    recommendation: Optional[str] = None

    entity_type: Optional[str] = None
    affected_server: Optional[str] = None
    config_file: Optional[str] = None
    affected_tool: Optional[str] = None
    affected_resource: Optional[str] = None
    affected_resource_uri: Optional[str] = None
    affected_entities: Optional[Dict[str, Any]] = None


@dataclass
class AffectedEntity:
    entity_type: str
    entity_name: str
    server_name: str
    config_file: Optional[str] = None
    
    affected_tool: Optional[str] = None
    affected_resource: Optional[str] = None
    affected_resource_uri: Optional[str] = None
    affected_prompt: Optional[str] = None
    affected_resource_template: Optional[str] = None
    affected_resource_template_uri: Optional[str] = None
    
    changed_fields: Optional[List[str]] = None
    additional_info: Optional[Dict[str, Any]] = None


@dataclass
class GroupedIssue:
    issue_type: str
    severity: Severity
    description: str
    remediation: str
    entities_affected: List[AffectedEntity] = field(default_factory=list)
    total_entities: int = 0


def create_security_issue(
        issue_type: str,
        severity: Severity,
        description: Optional[str] = None,
        recommendation: Optional[str] = None,
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


def extract_prompt_content(prompt: PromptInfo) -> str:
    prompt_data = {
        "name": prompt.name,
        "title": getattr(prompt, 'title', None),
        "description": prompt.description,
        "arguments": prompt.arguments,
        "tags": getattr(prompt, 'tags', None) or [],
        "server_name": prompt.server_name,
        "server_endpoint": prompt.server_endpoint
    }
    return json.dumps(prompt_data, indent=2)


def extract_resource_template_content(template: ResourceTemplateInfo) -> str:
    template_data = {
        "uri_template": template.uri_template,
        "name": template.name,
        "title": getattr(template, 'title', None),
        "description": template.description,
        "mime_type": template.mime_type,
        "tags": getattr(template, 'tags', None) or [],
        "server_name": template.server_name,
        "server_endpoint": template.server_endpoint
    }
    return json.dumps(template_data, indent=2)


def extract_text_content(content: str) -> str:
    try:
        data = json.loads(content)
        text_parts = []

        if isinstance(data, dict):
            for key in ['description', 'name', 'uri', 'uri_template', 'title', 'content']:
                if key in data and data[key]:
                    text_parts.append(str(data[key]))

            if 'input_schema' in data and isinstance(data['input_schema'], dict):
                schema_str = json.dumps(data['input_schema'], indent=2)
                text_parts.append(schema_str)

            if 'output_schema' in data and isinstance(data['output_schema'], dict):
                schema_str = json.dumps(data['output_schema'], indent=2)
                text_parts.append(schema_str)

            if 'arguments' in data and isinstance(data['arguments'], dict):
                arguments_str = json.dumps(data['arguments'], indent=2)
                text_parts.append(arguments_str)

            if 'tags' in data and isinstance(data['tags'], list):
                tags_str = ' '.join(str(tag) for tag in data['tags'] if tag)
                if tags_str:
                    text_parts.append(tags_str)

        return ' '.join(text_parts)
    except (json.JSONDecodeError, TypeError):
        return content


def _severity_order(severity: Severity) -> int:
    order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
    }
    return order.get(severity, 99)


def sort_issues_by_severity(issues: List[SecurityIssue]) -> List[SecurityIssue]:
    return sorted(
        issues,
        key=lambda issue: (
            _severity_order(issue.severity),
            issue.issue_type or "",
            issue.affected_server or ""
        )
    )


def get_generic_description(issue_type: str) -> str:
    descriptions = {
        "Prompt Injection": "MCP components with hidden instructions may alter agent behavior and trigger unintended or malicious actions.",
        "Command Injection": "Hidden command execution patterns found in MCP component metadata, indicating potential command injection vectors.",
        "Hardcoded Secret": "Potential hardcoded secrets detected in MCP configuration file(s).",
        "Tool Name Ambiguity": "Tool names are very similar, which may cause agent misselection and unintended behavior.",
        "Cross-Server Tool Shadowing": "Tools reference other tools across server boundaries, potentially bypassing trust controls and causing agent misselection.",
        "Excessive Tool Permissions": "Excessive host permissions detected for MCP tools on the affected server.",
        "Rug Pull: MCP Component Modified": "The MCP component has changed since baseline approval. This change could enable data exfiltration or cause the agent to perform malicious actions.",
    }
    return descriptions.get(issue_type, f"{issue_type} detected.")


def get_generic_recommendation(issue_type: str) -> str:
    recommendations = {
        "Prompt Injection": (
            "Inspect affected MCP components and remove hidden instructions or block the component "
            "to prevent unauthorized actions and manipulation of the agent’s context."
        ),
        "Command Injection": (
            "Integrate only trusted MCP servers; block components that embed hidden or unsafe commands in metadata. "
            "Regularly scan for poisoning and rug-pull activity to prevent unauthorized execution or data exfiltration."
        ),
        "Hardcoded Secret": (
            "Remove hardcoded secrets and use environment variables or a secrets manager."
        ),
        "Tool Name Ambiguity": (
            "Isolate agents for conflicting MCP servers, or add guardrails to agent decision logic for safe tool selection."
        ),
        "Cross-Server Tool Shadowing": (
            "Connect only to trusted MCP servers. Enforce strict namespace isolation by assigning each tool a unique prefix "
            "based on its originating server. Implement guardrails to detect and block suspicious cross-server references or manipulation."
        ),
        "Excessive Tool Permissions": (
            "Enforce least privilege by restricting MCP server privileges on the host. Remove wildcard or admin-level permissions and disable terminal or file-system access flags. "
        ),
        "Rug Pull: MCP Component Modified": (
            "Review the modification. If suspicious, revert to the last safe MCP server version or block it. If expected, rerun inspect to update the baseline."
        ),
    }
    return recommendations.get(issue_type, f"Review and address {issue_type} issues.")


def _extract_entity_name(issue: SecurityIssue) -> str:
    if issue.affected_entities:
        if "prompt" in issue.affected_entities:
            return issue.affected_entities["prompt"]
        elif "resource_template" in issue.affected_entities:
            return issue.affected_entities["resource_template"]
    
    if issue.affected_tool:
        return issue.affected_tool
    elif issue.affected_resource:
        return issue.affected_resource
    elif issue.affected_resource_uri:
        return issue.affected_resource_uri
    elif issue.affected_server:
        return issue.affected_server
    
    logger.warning(
        f"SecurityIssue '{issue.issue_type}' has no identifiable entity. "
        f"Missing: affected_tool={issue.affected_tool}, affected_resource={issue.affected_resource}, "
        f"affected_resource_uri={issue.affected_resource_uri}, affected_server={issue.affected_server}, "
        f"affected_entities={issue.affected_entities}"
    )
    return "unknown"


def _extract_entity_from_issue(issue: SecurityIssue) -> AffectedEntity:
    entity_name = _extract_entity_name(issue)
    
    
    entity = AffectedEntity(
        entity_type=issue.entity_type or "unknown",
        entity_name=entity_name,
        server_name=issue.affected_server or "",
        config_file=issue.config_file,
        affected_tool=issue.affected_tool,
        affected_resource=issue.affected_resource,
        affected_resource_uri=issue.affected_resource_uri,
        affected_prompt=issue.affected_entities.get("prompt") if issue.affected_entities else None,
        affected_resource_template=issue.affected_entities.get("resource_template") if issue.affected_entities else None,
        affected_resource_template_uri=issue.affected_entities.get("uri_template") if issue.affected_entities else None,
        changed_fields=issue.affected_entities.get("changed_fields") if issue.affected_entities else None,
        additional_info=issue.affected_entities.copy() if issue.affected_entities else None
    )
    
    if entity.additional_info:
        entity.additional_info.pop("prompt", None)
        entity.additional_info.pop("resource_template", None)
        entity.additional_info.pop("uri_template", None)
        entity.additional_info.pop("changed_fields", None)
        if not entity.additional_info:
            entity.additional_info = None
    
    return entity


def group_issues_by_type_and_severity(issues: List[SecurityIssue]) -> List[GroupedIssue]:
    grouped_dict: Dict[Tuple[str, Severity], GroupedIssue] = {}
    
    for issue in issues:
        key = (issue.issue_type, issue.severity)
        
        if key not in grouped_dict:
            grouped_dict[key] = GroupedIssue(
                issue_type=issue.issue_type,
                severity=issue.severity,
                description=get_generic_description(issue.issue_type),
                remediation=get_generic_recommendation(issue.issue_type),
                entities_affected=[],
                total_entities=0
            )
        
        entity = _extract_entity_from_issue(issue)
        grouped_dict[key].entities_affected.append(entity)
        grouped_dict[key].total_entities += 1
    
    return sorted(
        grouped_dict.values(),
        key=lambda g: (_severity_order(g.severity), g.issue_type)
    )


def calculate_risk_level(issues: List[SecurityIssue]) -> RiskLevel:
    if not issues:
        return RiskLevel.NONE

    highest_severity = max(issues, key=lambda issue: _severity_order(issue.severity)).severity

    severity_to_risk = {
        Severity.CRITICAL: RiskLevel.CRITICAL,
        Severity.HIGH: RiskLevel.HIGH,
        Severity.MEDIUM: RiskLevel.MEDIUM,
        Severity.LOW: RiskLevel.LOW
    }

    return severity_to_risk[highest_severity]


def _check_file_size(file_path: Path, max_size: int) -> None:
    file_size = file_path.stat().st_size
    if file_size > max_size:
        raise ValueError(
            f"File '{file_path}' exceeds size limit ({max_size / (1024*1024):.1f}MB). "
            f"File size: {file_size / (1024*1024):.1f}MB"
        )


def safe_load_file(file_path: Path, max_size: int = MAX_CONFIG_FILE_SIZE) -> Dict[str, Any]:
    _check_file_size(file_path, max_size)
    
    with open(file_path, 'r', encoding='utf-8') as f:
        if str(file_path).endswith(('.yaml', '.yml')):
            import yaml
            return yaml.safe_load(f)
        else:
            return json.load(f)