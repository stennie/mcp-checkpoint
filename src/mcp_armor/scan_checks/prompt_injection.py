import asyncio
import json
import logging
import sys
import threading
import time
from typing import List, Optional, Tuple
from transformers import pipeline

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

_classifier_pipeline = None
_load_lock = threading.Lock()
_CONFIDENCE_THRESHOLD = 0.8
_MAX_TOKENS = 512
_STRIDE = 64
_BATCH_SIZE = 8
_ENTITY_BATCH_SIZE = 16

MODEL_NAME = 'Aira-security/FT-Llama-Prompt-Guard-2'


def _load_classifier():
    global _classifier_pipeline

    if _classifier_pipeline is not None:
        logger.debug("Prompt injection classifier model already available locally")
        return _classifier_pipeline

    with _load_lock:
        if _classifier_pipeline is not None:
            return _classifier_pipeline

        try:
            logger.info(f"Loading prompt injection classifier: {MODEL_NAME}")

            start_time = time.perf_counter()
            _classifier_pipeline = pipeline(
                "text-classification",
                model=MODEL_NAME
            )
            end_time = time.perf_counter()
            load_duration = end_time - start_time

            if load_duration >= 2.5:
                print("     ⬇️  Downloading prompt injection model (first-time scan only)...")
                print("        ⏳ This may take a few seconds depending on your internet connection")
                sys.stdout.flush()
                print("        ✅ Model downloaded successfully")

            logger.info("Prompt injection classifier loaded successfully")
            return _classifier_pipeline

        except Exception as e:
            logger.error(f"Failed to load prompt injection classifier: {e}")
            print("        ❌ Failed to load the model. Check logs for more details.")
            print()
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


def _classify_binary(text: str) -> Tuple[bool, float, str]:
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


async def _scan_single_tool(tool, servers_list) -> Optional[SecurityIssue]:
    try:
        server = next((s for s in servers_list if s.name == tool.server_name), None)
        config_file = server.source_file if server else None

        tool_content = extract_tool_content(tool)
        text_content = extract_text_content(tool_content)
        malicious, score, norm = _classify_binary(text_content)

        if malicious:
            issue = create_security_issue(
                issue_type="Prompt Injection",
                severity=Severity.CRITICAL,
                entity_type="tool",
                affected_server=tool.server_name,
                affected_tool=tool.name,
                config_file=config_file,
                affected_entities={
                    "tool": tool.name,
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
        text_content = extract_text_content(resource_content)
        malicious, score, norm = _classify_binary(text_content)

        if malicious:
            issue = create_security_issue(
                issue_type="Prompt Injection",
                severity=Severity.CRITICAL,
                entity_type="resource",
                affected_server=resource.server_name,
                affected_resource=resource.name,
                affected_resource_uri=resource.uri,
                config_file=config_file,
                affected_entities={
                    "resource": resource.name,
                    "resource_uri": resource.uri,
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


async def _scan_single_prompt(prompt, servers_list) -> Optional[SecurityIssue]:
    try:
        server = next((s for s in servers_list if s.name == prompt.server_name), None)
        config_file = server.source_file if server else None

        prompt_content = extract_prompt_content(prompt)
        text_content = extract_text_content(prompt_content)
        malicious, score, norm = _classify_binary(text_content)

        if malicious:
            issue = create_security_issue(
                issue_type="Prompt Injection",
                severity=Severity.CRITICAL,
                entity_type="prompt",
                affected_server=prompt.server_name,
                config_file=config_file,
                affected_entities={
                    "prompt": prompt.name,
                    "classification": norm,
                    "score": round(score, 2)
                }
            )
            logger.warning(
                f"Prompt injection detected in prompt: {prompt.name} (classification={norm}, score={score:.2f})")
            return issue
        return None
    except Exception as e:
        logger.error(f"Error scanning prompt {prompt.name} for prompt injection: {e}")
        return None


async def _scan_single_resource_template(template, servers_list) -> Optional[SecurityIssue]:
    try:
        server = next((s for s in servers_list if s.name == template.server_name), None)
        config_file = server.source_file if server else None

        template_content = extract_resource_template_content(template)
        text_content = extract_text_content(template_content)
        malicious, score, norm = _classify_binary(text_content)

        if malicious:
            issue = create_security_issue(
                issue_type="Prompt Injection",
                severity=Severity.CRITICAL,
                entity_type="resource_template",
                affected_server=template.server_name,
                config_file=config_file,
                affected_entities={
                    "resource_template": template.name,
                    "uri_template": template.uri_template,
                    "classification": norm,
                    "score": round(score, 2)
                }
            )
            logger.warning(
                f"Prompt injection detected in resource template: {template.uri_template} (classification={norm}, score={score:.2f})")
            return issue
        return None
    except Exception as e:
        logger.error(f"Error scanning resource template {template.uri_template} for prompt injection: {e}")
        return None


async def scan_for_prompt_prompt_injection(scan_result: ScanResult) -> List[SecurityIssue]:
    issues = []

    if not scan_result.prompts:
        return issues

    if _load_classifier() is None:
        logger.warning("Prompt injection classifier not available, skipping prompt scan")
        return issues

    logger.info(f"Scanning {len(scan_result.prompts)} prompts for prompt injection attacks")

    for i in range(0, len(scan_result.prompts), _ENTITY_BATCH_SIZE):
        batch = scan_result.prompts[i:i + _ENTITY_BATCH_SIZE]
        tasks = [_scan_single_prompt(prompt, scan_result.servers) for prompt in batch]
        
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in batch_results:
            if result is not None and not isinstance(result, Exception):
                issues.append(result)
            elif isinstance(result, Exception):
                logger.error(f"Unexpected exception in prompt scan: {result}")

    logger.info(f"Prompt injection scan completed for prompts: {len(issues)} issues found")
    return issues


async def scan_for_resource_template_prompt_injection(scan_result: ScanResult) -> List[SecurityIssue]:
    issues = []

    if not scan_result.resource_templates:
        return issues

    if _load_classifier() is None:
        logger.warning("Prompt injection classifier not available, skipping resource template scan")
        return issues

    logger.info(f"Scanning {len(scan_result.resource_templates)} resource templates for prompt injection attacks")

    for i in range(0, len(scan_result.resource_templates), _ENTITY_BATCH_SIZE):
        batch = scan_result.resource_templates[i:i + _ENTITY_BATCH_SIZE]
        tasks = [_scan_single_resource_template(template, scan_result.servers) for template in batch]
        
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in batch_results:
            if result is not None and not isinstance(result, Exception):
                issues.append(result)
            elif isinstance(result, Exception):
                logger.error(f"Unexpected exception in resource template scan: {result}")

    logger.info(f"Resource template prompt injection scan completed: {len(issues)} issues found")
    return issues