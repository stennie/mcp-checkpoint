import json
import logging
import hashlib
from datetime import datetime, UTC
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from .security_utils import (
    ScanResult,
    MCPServerInfo,
    ToolInfo,
    ResourceInfo,
    PromptInfo,
    ResourceTemplateInfo,
    safe_load_file,
    MAX_BASELINE_FILE_SIZE
)

logger = logging.getLogger(__name__)

_baseline_cache: Dict[str, 'BaselineData'] = {}


@dataclass(frozen=True)
class BaselineTool:
    name: str
    server_name: str
    config_file: str
    description_hash: str
    metadata_hash: str
    args_hash: str


@dataclass(frozen=True)
class BaselineResource:
    uri: str
    name: str
    server_name: str
    config_file: str
    description_hash: str
    uri_hash: str
    mime_type_hash: str


@dataclass(frozen=True)
class BaselineServer:
    name: str
    config_file: str


@dataclass(frozen=True)
class BaselinePrompt:
    name: str
    server_name: str
    config_file: str
    description_hash: str
    arguments_hash: str
    metadata_hash: str


@dataclass(frozen=True)
class BaselineResourceTemplate:
    uri_template: str
    name: str
    server_name: str
    config_file: str
    description_hash: str
    uri_template_hash: str
    mime_type_hash: str
    metadata_hash: str


@dataclass(frozen=True)
class BaselineData:
    timestamp: str = ""
    config_files: Tuple[str, ...] = field(default_factory=tuple)
    servers: Tuple[BaselineServer, ...] = field(default_factory=tuple)
    tools: Tuple[BaselineTool, ...] = field(default_factory=tuple)
    resources: Tuple[BaselineResource, ...] = field(default_factory=tuple)
    prompts: Tuple[BaselinePrompt, ...] = field(default_factory=tuple)
    resource_templates: Tuple[BaselineResourceTemplate, ...] = field(default_factory=tuple)


def calculate_hash(data: str) -> str:
    return hashlib.sha512(data.encode('utf-8')).hexdigest()


def hash_tool_description(tool: ToolInfo) -> str:
    return calculate_hash(tool.description or "")


def hash_tool_metadata(tool: ToolInfo) -> str:
    metadata = {
        "input_schema": tool.input_schema or {},
        "output_schema": tool.output_schema or {},
        "tags": tool.tags or []
    }
    return calculate_hash(json.dumps(metadata, sort_keys=True))


def hash_tool_args(tool: ToolInfo) -> str:
    input_schema = tool.input_schema or {}
    properties = input_schema.get("properties", {})
    return calculate_hash(json.dumps(properties, sort_keys=True))


def hash_resource_description(resource: ResourceInfo) -> str:
    return calculate_hash(resource.description or "")


def hash_resource_uri(resource: ResourceInfo) -> str:
    return calculate_hash(resource.uri or "")


def hash_resource_mime_type(resource: ResourceInfo) -> str:
    return calculate_hash(resource.mime_type or "")


def hash_prompt_description(prompt: PromptInfo) -> str:
    return calculate_hash(prompt.description or "")


def hash_prompt_arguments(prompt: PromptInfo) -> str:
    return calculate_hash(json.dumps(prompt.arguments or {}, sort_keys=True))


def hash_prompt_metadata(prompt: PromptInfo) -> str:
    metadata = {
        "title": prompt.title or "",
        "tags": prompt.tags or []
    }
    return calculate_hash(json.dumps(metadata, sort_keys=True))


def hash_resource_template_description(template: ResourceTemplateInfo) -> str:
    return calculate_hash(template.description or "")


def hash_resource_template_uri_template(template: ResourceTemplateInfo) -> str:
    return calculate_hash(template.uri_template or "")


def hash_resource_template_mime_type(template: ResourceTemplateInfo) -> str:
    return calculate_hash(template.mime_type or "")


def hash_resource_template_metadata(template: ResourceTemplateInfo) -> str:
    metadata = {
        "title": template.title or "",
        "tags": template.tags or []
    }
    return calculate_hash(json.dumps(metadata, sort_keys=True))


def generate_baseline(scan_result: ScanResult) -> BaselineData:
    servers = []
    for server in scan_result.servers:
        config_file = server.source_file or ""
        servers.append(BaselineServer(
            name=server.name,
            config_file=config_file
        ))
    
    tools = []
    for tool in scan_result.tools:
        config_file = tool.config_file or ""
        tools.append(BaselineTool(
            name=tool.name,
            server_name=tool.server_name,
            config_file=config_file,
            description_hash=hash_tool_description(tool),
            metadata_hash=hash_tool_metadata(tool),
            args_hash=hash_tool_args(tool)
        ))
    
    resources = []
    for resource in scan_result.resources:
        config_file = resource.config_file or ""
        resources.append(BaselineResource(
            uri=resource.uri,
            name=resource.name,
            server_name=resource.server_name,
            config_file=config_file,
            description_hash=hash_resource_description(resource),
            uri_hash=hash_resource_uri(resource),
            mime_type_hash=hash_resource_mime_type(resource)
        ))
    
    prompts = []
    for prompt in scan_result.prompts:
        config_file = prompt.config_file or ""
        prompts.append(BaselinePrompt(
            name=prompt.name,
            server_name=prompt.server_name,
            config_file=config_file,
            description_hash=hash_prompt_description(prompt),
            arguments_hash=hash_prompt_arguments(prompt),
            metadata_hash=hash_prompt_metadata(prompt)
        ))
    
    resource_templates = []
    for template in scan_result.resource_templates:
        config_file = template.config_file or ""
        resource_templates.append(BaselineResourceTemplate(
            uri_template=template.uri_template,
            name=template.name,
            server_name=template.server_name,
            config_file=config_file,
            description_hash=hash_resource_template_description(template),
            uri_template_hash=hash_resource_template_uri_template(template),
            mime_type_hash=hash_resource_template_mime_type(template),
            metadata_hash=hash_resource_template_metadata(template)
        ))
    
    return BaselineData(
        timestamp=datetime.now(UTC).isoformat(),
        config_files=tuple(scan_result.config_files or []),
        servers=tuple(servers),
        tools=tuple(tools),
        resources=tuple(resources),
        prompts=tuple(prompts),
        resource_templates=tuple(resource_templates)
    )


def save_baseline(baseline_data: BaselineData, file_path: Path) -> None:
    baseline_dict = {
        "timestamp": baseline_data.timestamp,
        "config_files": list(baseline_data.config_files),
        "servers": [
            {
                "name": s.name,
                "config_file": s.config_file
            }
            for s in baseline_data.servers
        ],
        "tools": [
            {
                "name": t.name,
                "server_name": t.server_name,
                "config_file": t.config_file,
                "description_hash": t.description_hash,
                "metadata_hash": t.metadata_hash,
                "args_hash": t.args_hash
            }
            for t in baseline_data.tools
        ],
        "resources": [
            {
                "uri": r.uri,
                "name": r.name,
                "server_name": r.server_name,
                "config_file": r.config_file,
                "description_hash": r.description_hash,
                "uri_hash": r.uri_hash,
                "mime_type_hash": r.mime_type_hash
            }
            for r in baseline_data.resources
        ],
        "prompts": [
            {
                "name": p.name,
                "server_name": p.server_name,
                "config_file": p.config_file,
                "description_hash": p.description_hash,
                "arguments_hash": p.arguments_hash,
                "metadata_hash": p.metadata_hash
            }
            for p in baseline_data.prompts
        ],
        "resource_templates": [
            {
                "uri_template": rt.uri_template,
                "name": rt.name,
                "server_name": rt.server_name,
                "config_file": rt.config_file,
                "description_hash": rt.description_hash,
                "uri_template_hash": rt.uri_template_hash,
                "mime_type_hash": rt.mime_type_hash,
                "metadata_hash": rt.metadata_hash
            }
            for rt in baseline_data.resource_templates
        ]
    }
    
    with open(file_path, 'w') as f:
        json.dump(baseline_dict, f, indent=2)
    
    logger.info(f"Baseline saved to {file_path}")


def load_baseline(file_path: Path) -> Optional[BaselineData]:
    global _baseline_cache
    
    abs_path = str(file_path.resolve())
    
    if abs_path in _baseline_cache:
        logger.debug(f"Using cached baseline from {abs_path}")
        return _baseline_cache[abs_path]
    
    if not file_path.exists():
        return None
    
    baseline_data = _load_baseline_from_file(file_path)
    if baseline_data is None:
        return None
    
    _baseline_cache[abs_path] = baseline_data
    logger.debug(f"Cached baseline from {abs_path}")
    
    return baseline_data


def _load_baseline_from_file(file_path: Path) -> Optional[BaselineData]:
    try:
        data = safe_load_file(file_path, MAX_BASELINE_FILE_SIZE)
        
        servers = [
            BaselineServer(
                name=s["name"],
                config_file=s.get("config_file", "")
            )
            for s in data.get("servers", [])
        ]
        
        tools = [
            BaselineTool(
                name=t["name"],
                server_name=t["server_name"],
                config_file=t.get("config_file", ""),
                description_hash=t["description_hash"],
                metadata_hash=t["metadata_hash"],
                args_hash=t["args_hash"]
            )
            for t in data.get("tools", [])
        ]
        
        resources = [
            BaselineResource(
                uri=r["uri"],
                name=r["name"],
                server_name=r["server_name"],
                config_file=r.get("config_file", ""),
                description_hash=r["description_hash"],
                uri_hash=r["uri_hash"],
                mime_type_hash=r["mime_type_hash"]
            )
            for r in data.get("resources", [])
        ]
        
        prompts = [
            BaselinePrompt(
                name=p["name"],
                server_name=p["server_name"],
                config_file=p.get("config_file", ""),
                description_hash=p["description_hash"],
                arguments_hash=p["arguments_hash"],
                metadata_hash=p["metadata_hash"]
            )
            for p in data.get("prompts", [])
        ]
        
        resource_templates = [
            BaselineResourceTemplate(
                uri_template=rt["uri_template"],
                name=rt["name"],
                server_name=rt["server_name"],
                config_file=rt.get("config_file", ""),
                description_hash=rt["description_hash"],
                uri_template_hash=rt["uri_template_hash"],
                mime_type_hash=rt["mime_type_hash"],
                metadata_hash=rt["metadata_hash"]
            )
            for rt in data.get("resource_templates", [])
        ]
        
        return BaselineData(
            timestamp=data.get("timestamp", ""),
            config_files=tuple(data.get("config_files", [])),
            servers=tuple(servers),
            tools=tuple(tools),
            resources=tuple(resources),
            prompts=tuple(prompts),
            resource_templates=tuple(resource_templates)
        )
    except ValueError as e:
        logger.error(f"Baseline file size limit exceeded: {e}")
        return None
    except (KeyError, json.JSONDecodeError, TypeError) as e:
        logger.error(f"Invalid baseline file format: {e}")
        return None
    except Exception as e:
        logger.error(f"Failed to load baseline from {file_path}: {e}")
        return None

