import logging
from typing import List

from ..security_utils import (
    ScanResult,
    SecurityIssue,
    Severity,
    create_security_issue,
)
from ..baseline import (
    BaselineData,
    hash_tool_description,
    hash_tool_metadata,
    hash_tool_args,
    hash_resource_description,
    hash_resource_uri,
    hash_resource_mime_type,
    hash_prompt_description,
    hash_prompt_arguments,
    hash_prompt_metadata,
    hash_resource_template_description,
    hash_resource_template_uri_template,
    hash_resource_template_mime_type,
    hash_resource_template_metadata,
)

logger = logging.getLogger(__name__)

ISSUE_TYPE_RUG_PULL = "Rug Pull: MCP Component Modified"


async def scan_for_tool_rug_pull(scan_result: ScanResult, baseline: BaselineData) -> List[SecurityIssue]:
    issues = []
    
    if not baseline.tools:
        return issues
    
    baseline_tool_map = {
        (tool.server_name, tool.name, tool.config_file): tool
        for tool in baseline.tools
    }
    
    for tool in scan_result.tools:
        server = next((s for s in scan_result.servers if s.name == tool.server_name), None)
        config_file = server.source_file if server else ""
        
        tool_key = (tool.server_name, tool.name, config_file)
        baseline_tool = baseline_tool_map.get(tool_key)
        
        if not baseline_tool:
            continue
        
        changed_fields = []
        
        current_desc_hash = hash_tool_description(tool)
        if current_desc_hash != baseline_tool.description_hash:
            changed_fields.append("description")
        
        current_meta_hash = hash_tool_metadata(tool)
        if current_meta_hash != baseline_tool.metadata_hash:
            changed_fields.append("metadata")
        
        current_args_hash = hash_tool_args(tool)
        if current_args_hash != baseline_tool.args_hash:
            changed_fields.append("arguments")
        
        if changed_fields:
            issues.append(create_security_issue(
                issue_type=ISSUE_TYPE_RUG_PULL,
                severity=Severity.CRITICAL,
                entity_type="tool",
                affected_server=tool.server_name,
                affected_tool=tool.name,
                config_file=config_file,
                affected_entities={
                    "changed_fields": changed_fields
                }
            ))
    
    if issues:
        logger.info(f"Found {len(issues)} tool rug pull issues")
    
    return issues


async def scan_for_resource_rug_pull(scan_result: ScanResult, baseline: BaselineData) -> List[SecurityIssue]:
    issues = []
    
    if not baseline.resources:
        return issues
    
    baseline_resource_map = {
        (resource.server_name, resource.name, resource.config_file): resource
        for resource in baseline.resources
    }
    
    for resource in scan_result.resources:
        server = next((s for s in scan_result.servers if s.name == resource.server_name), None)
        config_file = server.source_file if server else ""
        
        resource_key = (resource.server_name, resource.name, config_file)
        baseline_resource = baseline_resource_map.get(resource_key)
        
        if not baseline_resource:
            continue
        
        changed_fields = []
        
        current_desc_hash = hash_resource_description(resource)
        if current_desc_hash != baseline_resource.description_hash:
            changed_fields.append("description")
        
        current_uri_hash = hash_resource_uri(resource)
        if current_uri_hash != baseline_resource.uri_hash:
            changed_fields.append("URI")
        
        current_mime_hash = hash_resource_mime_type(resource)
        if current_mime_hash != baseline_resource.mime_type_hash:
            changed_fields.append("MIME type")
        
        if changed_fields:
            issues.append(create_security_issue(
                issue_type=ISSUE_TYPE_RUG_PULL,
                severity=Severity.CRITICAL,
                entity_type="resource",
                affected_server=resource.server_name,
                affected_resource=resource.name,
                affected_resource_uri=resource.uri,
                config_file=config_file,
                affected_entities={
                    "changed_fields": changed_fields
                }
            ))
    
    if issues:
        logger.info(f"Found {len(issues)} resource rug pull issues")
    
    return issues


async def scan_for_prompt_rug_pull(scan_result: ScanResult, baseline: BaselineData) -> List[SecurityIssue]:
    issues = []
    
    if not baseline.prompts:
        return issues
    
    baseline_prompt_map = {
        (prompt.server_name, prompt.name, prompt.config_file): prompt
        for prompt in baseline.prompts
    }
    
    for prompt in scan_result.prompts:
        config_file = prompt.config_file or ""
        
        prompt_key = (prompt.server_name, prompt.name, config_file)
        baseline_prompt = baseline_prompt_map.get(prompt_key)
        
        if not baseline_prompt:
            continue
        
        changed_fields = []
        
        current_desc_hash = hash_prompt_description(prompt)
        if current_desc_hash != baseline_prompt.description_hash:
            changed_fields.append("description")
        
        current_args_hash = hash_prompt_arguments(prompt)
        if current_args_hash != baseline_prompt.arguments_hash:
            changed_fields.append("arguments")
        
        current_meta_hash = hash_prompt_metadata(prompt)
        if current_meta_hash != baseline_prompt.metadata_hash:
            changed_fields.append("metadata")
        
        if changed_fields:
            issues.append(create_security_issue(
                issue_type=ISSUE_TYPE_RUG_PULL,
                severity=Severity.CRITICAL,
                entity_type="prompt",
                affected_server=prompt.server_name,
                config_file=config_file,
                affected_entities={
                    "prompt": prompt.name,
                    "changed_fields": changed_fields
                }
            ))
    
    if issues:
        logger.info(f"Found {len(issues)} prompt rug pull issues")
    
    return issues


async def scan_for_resource_template_rug_pull(scan_result: ScanResult, baseline: BaselineData) -> List[SecurityIssue]:
    issues = []
    
    if not baseline.resource_templates:
        return issues
    
    baseline_template_map = {
        (template.server_name, template.name, template.config_file): template
        for template in baseline.resource_templates
    }
    
    for template in scan_result.resource_templates:
        config_file = template.config_file or ""
        
        template_key = (template.server_name, template.name, config_file)
        baseline_template = baseline_template_map.get(template_key)
        
        if not baseline_template:
            continue
        
        changed_fields = []
        
        current_desc_hash = hash_resource_template_description(template)
        if current_desc_hash != baseline_template.description_hash:
            changed_fields.append("description")
        
        current_uri_hash = hash_resource_template_uri_template(template)
        if current_uri_hash != baseline_template.uri_template_hash:
            changed_fields.append("URI template")
        
        current_mime_hash = hash_resource_template_mime_type(template)
        if current_mime_hash != baseline_template.mime_type_hash:
            changed_fields.append("MIME type")
        
        current_meta_hash = hash_resource_template_metadata(template)
        if current_meta_hash != baseline_template.metadata_hash:
            changed_fields.append("metadata")
        
        if changed_fields:
            issues.append(create_security_issue(
                issue_type=ISSUE_TYPE_RUG_PULL,
                severity=Severity.CRITICAL,
                entity_type="resource_template",
                affected_server=template.server_name,
                config_file=config_file,
                affected_entities={
                    "resource_template": template.name,
                    "uri_template": template.uri_template,
                    "changed_fields": changed_fields
                }
            ))
    
    if issues:
        logger.info(f"Found {len(issues)} resource template rug pull issues")
    
    return issues

