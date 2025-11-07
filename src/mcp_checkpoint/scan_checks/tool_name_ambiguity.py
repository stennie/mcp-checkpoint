from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import combinations
from typing import Dict, List, Tuple, Optional
from thefuzz import fuzz

from ..scanner import ScanResult
from ..security_utils import SecurityIssue, Severity, create_security_issue


def _normalize(name: Optional[str]) -> str:
    return (name or "").strip().lower()


def _hybrid_score(a: str, b: str) -> float:
    a_n, b_n = _normalize(a), _normalize(b)
    weights = {
        "token_set": 0.30,
        "partial_token_sort": 0.25,
        "token_sort": 0.20,
        "partial": 0.15,
        "simple": 0.10,
    }
    scores = {
        "token_set": fuzz.token_set_ratio(a_n, b_n),
        "partial_token_sort": fuzz.partial_token_sort_ratio(a_n, b_n),
        "token_sort": fuzz.token_sort_ratio(a_n, b_n),
        "partial": fuzz.partial_ratio(a_n, b_n),
        "simple": fuzz.ratio(a_n, b_n),
    }
    return sum(scores[k] * weights[k] for k in weights)


def _score_pairs(tool_names: List[str], threshold: int) -> List[Tuple[str, str, float]]:
    pairs = list(combinations(tool_names, 2))
    out: List[Tuple[str, str, float]] = []
    with ThreadPoolExecutor() as ex:
        futs = {ex.submit(_hybrid_score, a, b): (a, b) for a, b in pairs}
        for fut in as_completed(futs):
            a, b = futs[fut]
            score = float(fut.result() or 0.0)
            if score >= threshold:
                out.append((a, b, score))
    return out


async def scan_for_tool_name_ambiguity(scan_result: ScanResult, threshold: int = 85) -> List[SecurityIssue]:
    tool_meta: Dict[str, Tuple[Optional[str], Optional[str]]] = {}
    for t in scan_result.tools:
        srv = next((s for s in scan_result.servers if s.name == t.server_name), None)
        tool_meta[t.name] = (t.server_name, (srv.source_file if srv else None))

    names = [t.name for t in scan_result.tools if t.name]
    if len(names) < 2:
        return []

    ambiguous = _score_pairs(names, threshold)
    issues: List[SecurityIssue] = []

    for a, b, score in ambiguous:
        a_server, a_cfg = tool_meta.get(a, (None, None))
        b_server, b_cfg = tool_meta.get(b, (None, None))
        severity = Severity.HIGH if (
                    a_server is not None and b_server is not None and a_server != b_server) else Severity.MEDIUM

        description = (
            f"Tool names '{a}' (server: {a_server}) and '{b}' (server: {b_server}) "
            f"appear highly similar (score {score:.0f}), which may cause agent misselection."
        )
        recommendation = (
            "Isolate agents for conflicting MCP servers, or add guardrails to agent decision logic for safe tool selection."
        )

        issues.append(create_security_issue(
            issue_type="Tool Name Ambiguity",
            severity=severity,
            description=description,
            recommendation=recommendation,
            entity_type="tool",
            affected_tool=a,
            affected_server=a_server,
            config_file=a_cfg,
            affected_entities={
                "tools": [
                    {"name": a, "server": a_server, "config_file": a_cfg},
                    {"name": b, "server": b_server, "config_file": b_cfg},
                ],
                "score": round(score, 2),
            },
        ))

    return issues
