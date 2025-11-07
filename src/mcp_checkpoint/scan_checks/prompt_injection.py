import asyncio
import json
import logging
from typing import List, Optional
from transformers import pipeline

from ..scanner import ScanResult
from ..security_utils import (
    create_security_issue,
    extract_tool_content,
    extract_resource_content,
    SecurityIssue,
    Severity
)

logger = logging.getLogger(__name__)

_classifier_pipeline = None
_CONFIDENCE_THRESHOLD = 0.8
_MAX_TOKENS = 512
_STRIDE = 64
_BATCH_SIZE = 8
_ENTITY_BATCH_SIZE = 16


def _load_classifier():
    global _classifier_pipeline

    if _classifier_pipeline is not None:
        return _classifier_pipeline

    try:
        model_name = 'Aira-security/FT-Llama-Prompt-Guard-2'
        logger.info(f"Loading prompt injection classifier: {model_name}")

        _classifier_pipeline = pipeline(
            "text-classification",
            model=model_name
        )

        logger.info("Prompt injection classifier loaded successfully")
        return _classifier_pipeline

    except ImportError:
        logger.warning(
            "transformers library not available. "
            "Install with: pip install transformers torch"
        )
        return None
    except Exception as e:
        logger.error(f"Failed to load prompt injection classifier: {e}")
        return None


def _chunk_text(text: str) -> List[str]:
    if not text:
        return []
    
    pipe = _load_classifier()
    if pipe is None:
        return [text]

    try:
        tokenizer = pipe.tokenizer
        ids: List[int] = tokenizer.encode(text, add_special_tokens=True)
        if len(ids) <= _MAX_TOKENS:
            return [text]

        chunks: List[str] = []
        start = 0
        while start < len(ids):
            end = min(start + _MAX_TOKENS, len(ids))
            chunk_ids = ids[start:end]
            chunk_text = tokenizer.decode(chunk_ids, skip_special_tokens=True)
            if chunk_text.strip():
                chunks.append(chunk_text)
            if end == len(ids):
                break
            start = end - _STRIDE
            if start < 0:
                start = 0
        return chunks
    except Exception:
        return [text]


def _classify_chunks(chunks: List[str]) -> Optional[dict]:
    if not chunks:
        return None

    pipe = _load_classifier()
    if pipe is None:
        return None

    try:
        results = pipe(chunks, truncation=False, batch_size=_BATCH_SIZE)
        if not results:
            return None
        best = None
        best_score = -1.0
        malicious_result = None
        malicious_score = -1.0
        
        for res in results:
            if not res:
                continue
            label = str(res.get('label', '')).lower()
            score = float(res.get('score', 0.0))
            
            if label == 'malicious' and score > malicious_score:
                malicious_result = res
                malicious_score = score
            
            if score > best_score:
                best = res
                best_score = score
        
        return malicious_result if malicious_result is not None else best
    except Exception as e:
        logger.error(f"Error classifying chunked text: {e}")
        return None


def _classify_binary(text: str) -> (bool, float, str):
    chunks = _chunk_text(text)
    if not chunks:
        return False, 0.0, 'benign'

    classification = _classify_chunks(chunks)

    if classification is None:
        return False, 0.0, 'benign'

    raw_label = str(classification.get('label', '')).lower()
    score = float(classification.get('score', 0.0))

    if raw_label == 'malicious' and score >= _CONFIDENCE_THRESHOLD:
        return True, score, 'malicious'
    elif raw_label == 'benign':
        return False, score, 'benign'
    else:
        logger.warning(f"Unexpected label from classifier: '{raw_label}' (score: {score:.2f}). Defaulting to benign.")
        return False, score, 'benign'


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


async def _scan_single_tool(tool, servers_list) -> Optional[SecurityIssue]:
    try:
        server = next((s for s in servers_list if s.name == tool.server_name), None)
        config_file = server.source_file if server else None

        tool_content = extract_tool_content(tool)
        text_content = _extract_text_content(tool_content)
        malicious, score, norm = _classify_binary(text_content)

        if malicious:
            issue = create_security_issue(
                issue_type="Prompt Injection",
                severity=Severity.CRITICAL,
                description=(
                    f"The MCP Tool '{tool.name}' (server: {tool.server_name}) contain hidden instructions "
                    f"that can alter agent behavior to perform malicious operations."
                ),
                recommendation=(
                    "Review all tool and resource data within MCP components that include prompts. "
                    "Detect and remove hidden instructions to prevent unauthorized actions or manipulation of the agent context"
                ),
                entity_type="tool",
                affected_server=tool.server_name,
                affected_tool=tool.name,
                config_file=config_file,
                affected_entities={
                    "classification": norm,
                    "score": round(score, 2)
                }
            )
            logger.warning(
                f"Prompt injection detected in tool: {tool.name} (classification={norm}, score={score:.2f})")
            return issue
        return None
    except Exception as e:
        logger.error(f"Error scanning tool {tool.name} for prompt injection: {e}")
        return None


async def _scan_single_resource(resource, servers_list) -> Optional[SecurityIssue]:
    try:
        server = next((s for s in servers_list if s.name == resource.server_name), None)
        config_file = server.source_file if server else None

        resource_content = extract_resource_content(resource)
        text_content = _extract_text_content(resource_content)
        malicious, score, norm = _classify_binary(text_content)

        if malicious:
            issue = create_security_issue(
                issue_type="Prompt Injection",
                severity=Severity.CRITICAL,
                description=(
                    f"The MCP Resource '{resource.name}' (server: {resource.server_name}) contain hidden instructions "
                    f"that can alter agent behavior to perform malicious operations."
                ),
                recommendation=(
                    "Review all tool and resource data within MCP components that include prompts. "
                    "Detect and remove hidden instructions to prevent unauthorized actions or manipulation of agent context."
                ),
                entity_type="resource",
                affected_server=resource.server_name,
                affected_resource=resource.name,
                affected_resource_uri=resource.uri,
                config_file=config_file,
                affected_entities={
                    "classification": norm,
                    "score": round(score, 2)
                }
            )
            logger.warning(
                f"Prompt injection detected in resource: {resource.uri} (classification={norm}, score={score:.2f})")
            return issue
        return None
    except Exception as e:
        logger.error(f"Error scanning resource {resource.uri} for prompt injection: {e}")
        return None


async def scan_for_tool_prompt_injection(scan_result: ScanResult) -> List[SecurityIssue]:
    issues = []

    if not scan_result.tools:
        return issues

    if _load_classifier() is None:
        logger.warning("Prompt injection classifier not available, skipping tool scan")
        return issues

    logger.info(f"Scanning {len(scan_result.tools)} tools for prompt injection attacks")

    for i in range(0, len(scan_result.tools), _ENTITY_BATCH_SIZE):
        batch = scan_result.tools[i:i + _ENTITY_BATCH_SIZE]
        tasks = [_scan_single_tool(tool, scan_result.servers) for tool in batch]
        
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in batch_results:
            if result is not None and not isinstance(result, Exception):
                issues.append(result)
            elif isinstance(result, Exception):
                logger.error(f"Unexpected exception in tool scan: {result}")

    logger.info(f"Tool prompt injection scan completed: {len(issues)} issues found")
    return issues


async def scan_for_resource_prompt_injection(scan_result: ScanResult) -> List[SecurityIssue]:
    issues = []

    if not scan_result.resources:
        return issues

    if _load_classifier() is None:
        logger.warning("Prompt injection classifier not available, skipping resource scan")
        return issues

    logger.info(f"Scanning {len(scan_result.resources)} resources for prompt injection attacks")

    for i in range(0, len(scan_result.resources), _ENTITY_BATCH_SIZE):
        batch = scan_result.resources[i:i + _ENTITY_BATCH_SIZE]
        tasks = [_scan_single_resource(resource, scan_result.servers) for resource in batch]
        
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in batch_results:
            if result is not None and not isinstance(result, Exception):
                issues.append(result)
            elif isinstance(result, Exception):
                logger.error(f"Unexpected exception in resource scan: {result}")

    logger.info(f"Resource prompt injection scan completed: {len(issues)} issues found")
    return issues
