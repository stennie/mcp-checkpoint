import asyncio
import logging
from typing import List, Dict
from dataclasses import dataclass, field

from .scanner import ScanResult
from .scan_checks.prompt_injection import (
    scan_for_tool_prompt_injection,
    scan_for_resource_prompt_injection
)
from .scan_checks.hardcoded_secrets import scan_for_hardcoded_secrets
from .scan_checks.command_injection import scan_for_command_injection
from .scan_checks.tool_name_ambiguity import scan_for_tool_name_ambiguity
from .scan_checks.cross_server_tool_shadowing import scan_for_cross_server_tool_shadowing
from .scan_checks.excessive_tool_permissions import scan_for_excessive_tool_permissions
from .security_utils import SecurityIssue, Severity, RiskLevel, calculate_risk_level, sort_issues_by_severity

logger = logging.getLogger(__name__)


@dataclass
class SecurityReport:
    total_issues: int = 0
    issues_by_severity: Dict[Severity, int] = field(default_factory=lambda: {s: 0 for s in Severity})
    issues_by_type: Dict[str, int] = field(default_factory=dict)
    all_issues: List[SecurityIssue] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.NONE
    scan_duration: float = 0.0


class SecurityCheckRunner:
    
    def __init__(self):
        self.configuration_checks = [
            scan_for_hardcoded_secrets,
            scan_for_command_injection,
            scan_for_excessive_tool_permissions,
        ]

        self.tool_checks = [
            scan_for_tool_prompt_injection,
            scan_for_tool_name_ambiguity,
            scan_for_cross_server_tool_shadowing,
        ]

        self.resource_checks = [
            scan_for_resource_prompt_injection,
        ]
        
        logger.info(
            f"Initialized security check runner with {len(self.configuration_checks)} config checks, {len(self.tool_checks)} tool checks, {len(self.resource_checks)} resource checks")

    async def perform_security_scan(self, scan_result: ScanResult) -> SecurityReport:
        logger.info("Starting security scan...")
        start_time = asyncio.get_event_loop().time()
        
        report = SecurityReport()
        all_issues = []
        
        config_issues = await self.run_configuration_checks(scan_result)
        all_issues.extend(config_issues)

        tool_issues = await self.run_tool_checks(scan_result)
        all_issues.extend(tool_issues)

        resource_issues = await self.run_resource_checks(scan_result)
        all_issues.extend(resource_issues)

        report.all_issues = sort_issues_by_severity(all_issues)
        report.total_issues = len(report.all_issues)
        
        for issue in report.all_issues:
            report.issues_by_severity[issue.severity] += 1
        
        for issue in report.all_issues:
            issue_type = issue.issue_type.split(':')[0]
            if issue_type not in report.issues_by_type:
                report.issues_by_type[issue_type] = 0
            report.issues_by_type[issue_type] += 1
        
        report.risk_level = calculate_risk_level(report.all_issues)

        end_time = asyncio.get_event_loop().time()
        report.scan_duration = end_time - start_time
        
        logger.info(
            f"Security scan completed: {report.total_issues} issues found, risk level: {report.risk_level.value}")
        return report
    
    async def run_configuration_checks(self, scan_result: ScanResult) -> List[SecurityIssue]:
        logger.info(f"Running {len(self.configuration_checks)} configuration checks...")
        check_tasks = [asyncio.create_task(check(scan_result)) for check in self.configuration_checks]
        results = await asyncio.gather(*check_tasks, return_exceptions=True)
        issues: List[SecurityIssue] = []
        for i, res in enumerate(results):
            if isinstance(res, Exception):
                logger.error(f"Configuration check {self.configuration_checks[i].__name__} failed: {res}")
                continue
            if isinstance(res, list):
                issues.extend(res)
        return issues

    async def run_tool_checks(self, scan_result: ScanResult) -> List[SecurityIssue]:
        if not scan_result.tools:
            return []
        logger.info(f"Running {len(self.tool_checks)} tool checks on {len(scan_result.tools)} tools...")
        check_tasks = [asyncio.create_task(check(scan_result)) for check in self.tool_checks]
        results = await asyncio.gather(*check_tasks, return_exceptions=True)
        issues: List[SecurityIssue] = []
        for i, res in enumerate(results):
            if isinstance(res, Exception):
                logger.error(f"Tool check {self.tool_checks[i].__name__} failed: {res}")
                continue
            if isinstance(res, list):
                issues.extend(res)
        return issues

    async def run_resource_checks(self, scan_result: ScanResult) -> List[SecurityIssue]:
        if not scan_result.resources:
            return []
        logger.info(f"Running {len(self.resource_checks)} resource checks on {len(scan_result.resources)} resources...")
        check_tasks = [asyncio.create_task(check(scan_result)) for check in self.resource_checks]
        results = await asyncio.gather(*check_tasks, return_exceptions=True)
        issues: List[SecurityIssue] = []
        for i, res in enumerate(results):
            if isinstance(res, Exception):
                logger.error(f"Resource check {self.resource_checks[i].__name__} failed: {res}")
                continue
            if isinstance(res, list):
                issues.extend(res)
        return issues
