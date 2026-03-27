import asyncio
import logging
import time
from typing import List, Dict, Callable, Optional
from dataclasses import dataclass, field

from .security_utils import ScanResult
from .scan_checks.prompt_injection import (
    scan_for_tool_prompt_injection,
    scan_for_resource_prompt_injection,
    scan_for_prompt_prompt_injection,
    scan_for_resource_template_prompt_injection
)
from .scan_checks.hardcoded_secrets import scan_for_hardcoded_secrets
from .scan_checks.command_injection import (
    scan_for_tool_command_injection,
    scan_for_resource_command_injection,
    scan_for_prompt_command_injection,
    scan_for_resource_template_command_injection
)
from .scan_checks.tool_name_ambiguity import scan_for_tool_name_ambiguity
from .scan_checks.cross_server_tool_shadowing import scan_for_cross_server_tool_shadowing
from .scan_checks.excessive_tool_permissions import scan_for_excessive_tool_permissions
from .scan_checks.baseline_deviation import (
    scan_for_tool_rug_pull,
    scan_for_resource_rug_pull,
    scan_for_prompt_rug_pull,
    scan_for_resource_template_rug_pull
)
from .security_utils import (
    SecurityIssue,
    Severity,
    RiskLevel,
    calculate_risk_level,
    sort_issues_by_severity,
    group_issues_by_type_and_severity,
    GroupedIssue
)
from .baseline import BaselineData

logger = logging.getLogger(__name__)


@dataclass
class SecurityReport:
    total_issues: int = 0
    issues_by_severity: Dict[Severity, int] = field(default_factory=lambda: {s: 0 for s in Severity})
    issues_by_type: Dict[str, int] = field(default_factory=dict)
    all_issues: List[SecurityIssue] = field(default_factory=list)
    grouped_issues: List[GroupedIssue] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.NONE
    scan_duration: float = 0.0


class SecurityCheckRunner:
    
    def __init__(self, baseline: Optional[BaselineData] = None):
        self.baseline = baseline
        
        self.configuration_checks = [
            scan_for_hardcoded_secrets,
            scan_for_excessive_tool_permissions,
        ]

        self.tool_checks = [
            scan_for_tool_prompt_injection,
            scan_for_tool_command_injection,
            scan_for_tool_name_ambiguity,
            scan_for_cross_server_tool_shadowing,
        ]
        
        if baseline:
            self.tool_checks.append(
                self._create_baseline_check_wrapper(scan_for_tool_rug_pull)
            )

        self.resource_checks = [
            scan_for_resource_prompt_injection,
            scan_for_resource_command_injection,
        ]
        
        if baseline:
            self.resource_checks.append(
                self._create_baseline_check_wrapper(scan_for_resource_rug_pull)
            )

        self.prompt_checks = [
            scan_for_prompt_prompt_injection,
            scan_for_prompt_command_injection,
        ]
        
        if baseline:
            self.prompt_checks.append(
                self._create_baseline_check_wrapper(scan_for_prompt_rug_pull)
            )

        self.resource_template_checks = [
            scan_for_resource_template_prompt_injection,
            scan_for_resource_template_command_injection,
        ]
        
        if baseline:
            self.resource_template_checks.append(
                self._create_baseline_check_wrapper(scan_for_resource_template_rug_pull)
            )
        
        baseline_info = "with baseline" if baseline else "without baseline"
        logger.info(
            f"Initialized security check runner {baseline_info}: "
            f"{len(self.configuration_checks)} config checks, "
            f"{len(self.tool_checks)} tool checks, "
            f"{len(self.resource_checks)} resource checks, "
            f"{len(self.prompt_checks)} prompt checks, "
            f"{len(self.resource_template_checks)} resource template checks"
        )
    
    def _create_baseline_check_wrapper(self, check_func: Callable) -> Callable:
        async def wrapper(scan_result: ScanResult):
            return await check_func(scan_result, self.baseline)
        return wrapper

    async def perform_security_scan(self, scan_result: ScanResult) -> SecurityReport:
        logger.info("Starting security scan...")
        start_time = time.perf_counter()
        
        report = SecurityReport()
        all_issues = []
        
        config_issues = await self.run_configuration_checks(scan_result)
        all_issues.extend(config_issues)

        tool_issues = await self.run_tool_checks(scan_result)
        all_issues.extend(tool_issues)

        resource_issues = await self.run_resource_checks(scan_result)
        all_issues.extend(resource_issues)

        prompt_issues = await self.run_prompt_checks(scan_result)
        all_issues.extend(prompt_issues)

        resource_template_issues = await self.run_resource_template_checks(scan_result)
        all_issues.extend(resource_template_issues)

        report.all_issues = sort_issues_by_severity(all_issues)
        report.total_issues = len(report.all_issues)
        
        for issue in report.all_issues:
            report.issues_by_severity[issue.severity] += 1
            issue_type = issue.issue_type.split(':')[0]
            if issue_type not in report.issues_by_type:
                report.issues_by_type[issue_type] = 0
            report.issues_by_type[issue_type] += 1
        
        report.grouped_issues = group_issues_by_type_and_severity(report.all_issues)
        report.risk_level = calculate_risk_level(report.all_issues)

        end_time = time.perf_counter()
        report.scan_duration = end_time - start_time
        
        logger.info(
            f"Security scan completed: {report.total_issues} issues found, risk level: {report.risk_level.value}")
        return report
    
    async def _run_checks(
        self,
        checks: List[Callable],
        scan_result: ScanResult,
        pre_check: Optional[Callable[[ScanResult], bool]] = None
    ) -> List[SecurityIssue]:
        if pre_check and not pre_check(scan_result):
            return []
        
        logger.info(f"Running {len(checks)} checks...")
        
        check_tasks = [asyncio.create_task(check(scan_result)) for check in checks]
        results = await asyncio.gather(*check_tasks, return_exceptions=True)
        
        issues: List[SecurityIssue] = []
        for i, res in enumerate(results):
            if isinstance(res, Exception):
                logger.error(f"Check {checks[i].__name__} failed: {res}")
                continue
            if isinstance(res, list):
                issues.extend(res)
        return issues

    async def run_configuration_checks(self, scan_result: ScanResult) -> List[SecurityIssue]:
        return await self._run_checks(
            self.configuration_checks,
            scan_result
        )

    async def run_tool_checks(self, scan_result: ScanResult) -> List[SecurityIssue]:
        return await self._run_checks(
            self.tool_checks,
            scan_result,
            pre_check=lambda s: bool(s.tools)
        )

    async def run_resource_checks(self, scan_result: ScanResult) -> List[SecurityIssue]:
        return await self._run_checks(
            self.resource_checks,
            scan_result,
            pre_check=lambda s: bool(s.resources)
        )

    async def run_prompt_checks(self, scan_result: ScanResult) -> List[SecurityIssue]:
        return await self._run_checks(
            self.prompt_checks,
            scan_result,
            pre_check=lambda s: bool(s.prompts)
        )

    async def run_resource_template_checks(self, scan_result: ScanResult) -> List[SecurityIssue]:
        return await self._run_checks(
            self.resource_template_checks,
            scan_result,
            pre_check=lambda s: bool(s.resource_templates)
        )