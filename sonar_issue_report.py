#!/usr/bin/env python3
"""Export SonarQube security/reliability issues with their code locations.

The script prefers the Multi-Quality Rule (MQR) API introduced in SonarQube
10.2.  If that API is not available, ``--mode auto`` falls back to the
traditional BUG/VULNERABILITY and BLOCKER/CRITICAL/MAJOR filters.

Examples:
    export SONAR_URL="https://sonar.example.com"
    export SONAR_TOKEN="squ_..."
    # 不设置 SONAR_PROJECT_KEY 时，默认处理当前账号可见的全部项目
    python3 sonar_issue_report.py --output sonar-issues.md

    python3 sonar_issue_report.py --format json --output sonar-issues.json
    python3 sonar_issue_report.py --format csv --output sonar-issues.csv \
        --branch develop
"""

from __future__ import annotations

import argparse
import csv
import getpass
import json
import os
import ssl
import sys
import time
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


MQR_RANK = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "BLOCKER": 4,
}

STANDARD_RANK = {
    "INFO": 0,
    "MINOR": 1,
    "MAJOR": 2,
    "CRITICAL": 3,
    "BLOCKER": 4,
}

MQR_SECURITY_LEVELS = ("MEDIUM", "HIGH", "BLOCKER")
MQR_RELIABILITY_LEVELS = ("HIGH", "BLOCKER")
STANDARD_SECURITY_LEVELS = ("MAJOR", "CRITICAL", "BLOCKER")
STANDARD_RELIABILITY_LEVELS = ("CRITICAL", "BLOCKER")
MAX_SEARCH_RESULTS = 10_000

CRITERION_LABELS = {
    "security_medium_plus": "安全性≥中危",
    "reliability_high_plus": "可靠性≥高危",
}


class SonarApiError(RuntimeError):
    """An error returned by SonarQube's Web API."""

    def __init__(
        self,
        message: str,
        status: Optional[int] = None,
        response_body: str = "",
    ) -> None:
        super().__init__(message)
        self.status = status
        self.response_body = response_body


class TooManyIssuesError(RuntimeError):
    """The API result exceeds SonarQube's searchable result window."""


class SonarClient:
    def __init__(
        self,
        base_url: str,
        token: Optional[str],
        timeout: float = 30.0,
        retries: int = 3,
        insecure: bool = False,
        verbose: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.retries = max(0, retries)
        self.verbose = verbose
        self.ssl_context = (
            ssl._create_unverified_context()  # noqa: SLF001 - explicit CLI opt-in
            if insecure
            else ssl.create_default_context()
        )

    def get_json(self, endpoint: str, params: Mapping[str, Any]) -> Dict[str, Any]:
        query: Dict[str, str] = {}
        for key, value in params.items():
            if value is None or value == "":
                continue
            query[key] = str(value)

        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        if query:
            url = f"{url}?{urlencode(query)}"

        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        last_error: Optional[Exception] = None
        for attempt in range(self.retries + 1):
            if self.verbose:
                print(f"GET {endpoint} page={query.get('p', '-')}", file=sys.stderr)

            request = Request(url, headers=headers, method="GET")
            try:
                with urlopen(  # noqa: S310 - URL is supplied by the user
                    request,
                    timeout=self.timeout,
                    context=self.ssl_context,
                ) as response:
                    raw = response.read()
                try:
                    payload = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise SonarApiError(
                        f"SonarQube 返回的不是合法 JSON: {exc}"
                    ) from exc
                if not isinstance(payload, dict):
                    raise SonarApiError("SonarQube 返回的 JSON 顶层结构不是对象")
                return payload
            except HTTPError as exc:
                body = exc.read().decode("utf-8", errors="replace")
                if exc.code in (429, 500, 502, 503, 504) and attempt < self.retries:
                    self._sleep_before_retry(attempt, exc.code)
                    last_error = exc
                    continue
                detail = _api_error_detail(body)
                if exc.code == 401:
                    message = "认证失败（401），请检查 SONAR_TOKEN 是否有效"
                elif exc.code == 403:
                    message = "权限不足（403），请求令牌需要目标项目的 Browse 权限"
                else:
                    message = f"SonarQube API 请求失败（HTTP {exc.code}）"
                if detail:
                    message = f"{message}: {detail}"
                raise SonarApiError(message, status=exc.code, response_body=body) from exc
            except URLError as exc:
                if attempt < self.retries:
                    self._sleep_before_retry(attempt, None)
                    last_error = exc
                    continue
                raise SonarApiError(f"无法连接 SonarQube: {exc.reason}") from exc
            except TimeoutError as exc:
                if attempt < self.retries:
                    self._sleep_before_retry(attempt, None)
                    last_error = exc
                    continue
                raise SonarApiError("请求 SonarQube 超时") from exc

        raise SonarApiError("请求 SonarQube 失败") from last_error

    def _sleep_before_retry(self, attempt: int, status: Optional[int]) -> None:
        # The delay is capped so transient 503s do not make the CLI wait too long.
        delay = min(8.0, 2.0**attempt)
        if self.verbose:
            suffix = f"（HTTP {status}）" if status else ""
            print(f"请求失败{suffix}，{delay:g}s 后重试", file=sys.stderr)
        time.sleep(delay)


def _api_error_detail(body: str) -> str:
    if not body:
        return ""
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return body.strip()[:500]

    if isinstance(payload, dict):
        errors = payload.get("errors")
        if isinstance(errors, list):
            messages = [
                str(item.get("msg"))
                for item in errors
                if isinstance(item, dict) and item.get("msg")
            ]
            if messages:
                return "; ".join(messages)
        for key in ("message", "error", "msg"):
            if payload.get(key):
                return str(payload[key])
    return ""


def _copy_params(params: Mapping[str, Any], **updates: Any) -> Dict[str, Any]:
    copied = dict(params)
    copied.update(updates)
    return copied


def search_all(
    client: SonarClient,
    params: Mapping[str, Any],
    page_size: int,
) -> Dict[str, Any]:
    """Read all pages for one /api/issues/search query."""

    issues_by_key: Dict[str, Dict[str, Any]] = {}
    components_by_key: Dict[str, Dict[str, Any]] = {}
    rules_by_key: Dict[str, Dict[str, Any]] = {}
    page = 1
    total: Optional[int] = None

    while True:
        response = client.get_json(
            "api/issues/search",
            _copy_params(params, p=page, ps=page_size),
        )
        paging = response.get("paging")
        if not isinstance(paging, dict):
            paging = {}

        response_total = paging.get("total", response.get("total"))
        if response_total is not None:
            try:
                total = int(response_total)
            except (TypeError, ValueError):
                total = None

        if total is not None and total > MAX_SEARCH_RESULTS:
            raise TooManyIssuesError(
                f"当前筛选条件命中 {total} 个问题，超过 SonarQube API 的 {MAX_SEARCH_RESULTS} 条检索窗口；"
                "请增加 --created-after/--created-before，或进一步缩小筛选范围。"
            )

        response_issues = response.get("issues", [])
        if not isinstance(response_issues, list):
            response_issues = []
        for issue in response_issues:
            if not isinstance(issue, dict):
                continue
            key = str(issue.get("key") or f"page-{page}-index-{len(issues_by_key)}")
            issues_by_key[key] = issue

        for component in response.get("components", []) or []:
            if isinstance(component, dict) and component.get("key"):
                components_by_key[str(component["key"])] = component

        for rule in response.get("rules", []) or []:
            if isinstance(rule, dict) and rule.get("key"):
                rules_by_key[str(rule["key"])] = rule

        count_on_page = len(response_issues)
        server_page_size = paging.get("pageSize")
        try:
            effective_page_size = int(server_page_size or page_size)
        except (TypeError, ValueError):
            effective_page_size = page_size

        if count_on_page == 0:
            break
        if total is not None and page * effective_page_size >= total:
            break
        if count_on_page < effective_page_size:
            break
        page += 1

    return {
        "issues": list(issues_by_key.values()),
        "components": list(components_by_key.values()),
        "rules": list(rules_by_key.values()),
        "total": total if total is not None else len(issues_by_key),
    }


def list_visible_projects(
    client: SonarClient,
    args: argparse.Namespace,
) -> List[Dict[str, Any]]:
    """List projects visible to the current token/user.

    The public component-search endpoint with qualifier TRK is used here
    because the project-administration endpoint requires Administer System.
    """

    projects_by_key: Dict[str, Dict[str, Any]] = {}
    page = 1
    total: Optional[int] = None

    while True:
        params: Dict[str, Any] = {
            "qualifiers": "TRK",
            "p": page,
            "ps": args.page_size,
        }
        organization = getattr(args, "organization", None)
        if organization:
            params["organization"] = organization

        response = client.get_json("api/components/search", params)
        paging = response.get("paging")
        if not isinstance(paging, dict):
            paging = {}

        response_total = paging.get("total", response.get("total"))
        if response_total is not None:
            try:
                total = int(response_total)
            except (TypeError, ValueError):
                total = None

        if total is not None and total > MAX_SEARCH_RESULTS:
            raise TooManyIssuesError(
                f"当前账号可见项目数为 {total}，超过 API 的 {MAX_SEARCH_RESULTS} 条检索窗口；"
                "请改用 --project-key 分批处理。"
            )

        components = response.get("components", [])
        if not isinstance(components, list):
            components = []
        for component in components:
            if not isinstance(component, dict):
                continue
            if component.get("qualifier") not in (None, "TRK"):
                continue
            project_key = str(component.get("key") or component.get("project") or "")
            if not project_key:
                continue
            projects_by_key[project_key] = {
                "key": project_key,
                "name": str(component.get("name") or component.get("longName") or ""),
            }

        count_on_page = len(components)
        server_page_size = paging.get("pageSize")
        try:
            effective_page_size = int(server_page_size or args.page_size)
        except (TypeError, ValueError):
            effective_page_size = args.page_size

        if count_on_page == 0:
            break
        if total is not None and page * effective_page_size >= total:
            break
        if count_on_page < effective_page_size:
            break
        page += 1

    return sorted(
        projects_by_key.values(),
        key=lambda project: (project["name"].lower(), project["key"].lower()),
    )


def _merge_query_result(
    accumulator: Dict[str, Dict[str, Any]],
    metadata: Dict[str, Dict[str, Any]],
    result: Mapping[str, Any],
    criterion: str,
) -> None:
    for issue in result.get("issues", []) or []:
        if not isinstance(issue, dict):
            continue
        key = str(issue.get("key") or "")
        if not key:
            continue
        current = accumulator.setdefault(
            key,
            {"issue": issue, "criteria": set()},
        )
        current["criteria"].add(criterion)

    for item in result.get("components", []) or []:
        if isinstance(item, dict) and item.get("key"):
            metadata["components"][str(item["key"])] = item
    for item in result.get("rules", []) or []:
        if isinstance(item, dict) and item.get("key"):
            metadata["rules"][str(item["key"])] = item


def _common_search_params(args: argparse.Namespace, component_param: str) -> Dict[str, Any]:
    params: Dict[str, Any] = {
        component_param: args.project_key,
        "s": "FILE_LINE",
        "asc": "true",
    }
    if args.unresolved_only:
        # resolved=false is supported by old and current SonarQube versions.
        params["resolved"] = "false"
    if args.branch:
        params["branch"] = args.branch
    if args.pull_request:
        params["pullRequest"] = args.pull_request
    if args.created_after:
        params["createdAfter"] = args.created_after
    if args.created_before:
        params["createdBefore"] = args.created_before
    if args.time_zone:
        params["timeZone"] = args.time_zone
    if args.new_code:
        params["inNewCodePeriod"] = "true"
    organization = getattr(args, "organization", None)
    if organization:
        params["organization"] = organization
    return params


def fetch_mqr_issues(
    client: SonarClient,
    args: argparse.Namespace,
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Dict[str, Any]]], Tuple[str, ...]]:
    """Fetch MQR issues, retrying compatible parameter variants when needed."""

    last_compatibility_error: Optional[SonarApiError] = None
    # BLOCKER/INFO became valid MQR API severity values in newer servers.  The
    # second candidate keeps SonarQube 10.2-10.7 instances usable.
    severity_candidates: Sequence[Tuple[str, ...]] = (
        MQR_SECURITY_LEVELS,
        ("MEDIUM", "HIGH"),
    )

    # `components` is the current spelling; `componentKeys` is retained for
    # older servers.  A whole two-query batch is retried with the next pair so
    # the result can never be a mixture of incompatible query styles.
    for component_param in ("components", "componentKeys"):
        for security_levels in severity_candidates:
            reliability_levels = tuple(
                level for level in security_levels if level in {"HIGH", "BLOCKER"}
            )
            if not reliability_levels:
                reliability_levels = ("HIGH",)

            accumulator: Dict[str, Dict[str, Any]] = {}
            metadata: Dict[str, Dict[str, Dict[str, Any]]] = {
                "components": {},
                "rules": {},
            }
            try:
                for quality, levels, criterion in (
                    (
                        "SECURITY",
                        security_levels,
                        "security_medium_plus",
                    ),
                    (
                        "RELIABILITY",
                        reliability_levels,
                        "reliability_high_plus",
                    ),
                ):
                    params = _common_search_params(args, component_param)
                    params.update(
                        {
                            "impactSoftwareQualities": quality,
                            "impactSeverities": ",".join(levels),
                        }
                    )
                    result = search_all(client, params, args.page_size)
                    _merge_query_result(accumulator, metadata, result, criterion)
                return accumulator, metadata, security_levels
            except SonarApiError as exc:
                if exc.status in (400, 404, 422):
                    last_compatibility_error = exc
                    continue
                raise

    if last_compatibility_error:
        raise last_compatibility_error
    raise SonarApiError("无法使用 MQR 参数查询 SonarQube 问题")


def fetch_standard_issues(
    client: SonarClient,
    args: argparse.Namespace,
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Dict[str, Any]]]]:
    """Fetch issues using the pre-MQR type/severity API."""

    last_compatibility_error: Optional[SonarApiError] = None
    for component_param in ("componentKeys", "components"):
        accumulator: Dict[str, Dict[str, Any]] = {}
        metadata: Dict[str, Dict[str, Dict[str, Any]]] = {
            "components": {},
            "rules": {},
        }
        try:
            for issue_type, levels, criterion in (
                (
                    "VULNERABILITY",
                    STANDARD_SECURITY_LEVELS,
                    "security_medium_plus",
                ),
                (
                    "BUG",
                    STANDARD_RELIABILITY_LEVELS,
                    "reliability_high_plus",
                ),
            ):
                params = _common_search_params(args, component_param)
                params.update(
                    {
                        "types": issue_type,
                        "severities": ",".join(levels),
                    }
                )
                result = search_all(client, params, args.page_size)
                _merge_query_result(accumulator, metadata, result, criterion)
            return accumulator, metadata
        except SonarApiError as exc:
            if exc.status in (400, 404, 422):
                last_compatibility_error = exc
                continue
            raise

    if last_compatibility_error:
        raise last_compatibility_error
    raise SonarApiError("无法使用传统参数查询 SonarQube 问题")


def _mqr_criteria_from_impacts(issue: Mapping[str, Any]) -> set[str]:
    criteria: set[str] = set()
    impacts = issue.get("impacts")
    if not isinstance(impacts, list):
        return criteria

    for impact in impacts:
        if not isinstance(impact, dict):
            continue
        quality = str(impact.get("softwareQuality") or "").upper()
        severity = str(impact.get("severity") or "").upper()
        if quality == "SECURITY" and MQR_RANK.get(severity, -1) >= MQR_RANK["MEDIUM"]:
            criteria.add("security_medium_plus")
        if quality == "RELIABILITY" and MQR_RANK.get(severity, -1) >= MQR_RANK["HIGH"]:
            criteria.add("reliability_high_plus")
    return criteria


def _standard_criteria_from_issue(issue: Mapping[str, Any]) -> set[str]:
    issue_type = str(issue.get("type") or "").upper()
    severity = str(issue.get("severity") or "").upper()
    rank = STANDARD_RANK.get(severity, -1)
    criteria: set[str] = set()
    if issue_type == "VULNERABILITY" and rank >= STANDARD_RANK["MAJOR"]:
        criteria.add("security_medium_plus")
    if issue_type == "BUG" and rank >= STANDARD_RANK["CRITICAL"]:
        criteria.add("reliability_high_plus")
    return criteria


def _component_path(
    issue: Mapping[str, Any],
    components: Mapping[str, Mapping[str, Any]],
    project_key: str,
) -> str:
    component_key = str(issue.get("component") or "")
    component = components.get(component_key, {})
    for field in ("path", "longName", "name"):
        value = component.get(field)
        if value:
            return str(value)

    # A file component normally looks like `<project>:<relative-path>`.
    prefix = f"{project_key}:"
    if component_key.startswith(prefix):
        return component_key[len(prefix) :]
    return component_key or "<unknown-file>"


def _location(
    text_range: Optional[Mapping[str, Any]],
    fallback_line: Any = None,
) -> Dict[str, Any]:
    text_range = text_range if isinstance(text_range, Mapping) else {}
    start_line = text_range.get("startLine", fallback_line)
    end_line = text_range.get("endLine", start_line)
    return {
        "start_line": start_line,
        "end_line": end_line,
        "start_column": text_range.get("startOffset"),
        "end_column": text_range.get("endOffset"),
    }


def _secondary_locations(
    issue: Mapping[str, Any],
    default_file: str,
) -> List[Dict[str, Any]]:
    locations: List[Dict[str, Any]] = []
    for flow in issue.get("flows", []) or []:
        if not isinstance(flow, Mapping):
            continue
        for item in flow.get("locations", []) or []:
            if not isinstance(item, Mapping):
                continue
            location = _location(item.get("textRange"))
            locations.append(
                {
                    "file": str(item.get("component") or default_file),
                    "message": item.get("msg") or item.get("message"),
                    **location,
                }
            )
    return locations


def build_report(
    accumulator: Mapping[str, Mapping[str, Any]],
    metadata: Mapping[str, Mapping[str, Mapping[str, Any]]],
    client: SonarClient,
    args: argparse.Namespace,
    mode: str,
    mqr_security_levels: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    components = metadata.get("components", {})
    rules = metadata.get("rules", {})
    report_issues: List[Dict[str, Any]] = []

    for key, entry in accumulator.items():
        issue = entry.get("issue", {})
        if not isinstance(issue, Mapping):
            continue

        query_criteria = set(entry.get("criteria", set()))
        if mode == "mqr":
            impacts = issue.get("impacts")
            actual_criteria = _mqr_criteria_from_impacts(issue)
            # The post-filter protects against servers that treat the quality
            # and severity filters as independent arrays instead of pairs.
            criteria = actual_criteria if isinstance(impacts, list) else query_criteria
        else:
            actual_criteria = _standard_criteria_from_issue(issue)
            criteria = actual_criteria or query_criteria

        if not criteria:
            continue

        component_key = str(issue.get("component") or "")
        issue_project_key = str(issue.get("project") or args.project_key or "")
        file_path = _component_path(issue, components, issue_project_key)
        primary_location = _location(
            issue.get("textRange"),
            fallback_line=issue.get("line"),
        )
        rule_key = str(issue.get("rule") or "")
        rule = rules.get(rule_key, {})
        issue_status = issue.get("issueStatus") or issue.get("status") or ""

        quality_severities: Dict[str, str] = {}
        for impact in issue.get("impacts", []) or []:
            if not isinstance(impact, Mapping):
                continue
            quality = str(impact.get("softwareQuality") or "").upper()
            severity = str(impact.get("severity") or "").upper()
            if quality and severity:
                quality_severities[quality] = severity

        report_issues.append(
            {
                "issue_key": str(issue.get("key") or key),
                "project_key": issue_project_key,
                "component_key": component_key,
                "file": file_path,
                "start_line": primary_location["start_line"],
                "end_line": primary_location["end_line"],
                "start_column": primary_location["start_column"],
                "end_column": primary_location["end_column"],
                "rule": rule_key,
                "rule_name": str(rule.get("name") or ""),
                "language": str(rule.get("langName") or rule.get("lang") or ""),
                "type": str(issue.get("type") or ""),
                "severity": str(issue.get("severity") or ""),
                "quality_severities": quality_severities,
                "matched_criteria": sorted(criteria),
                "matched_criteria_labels": [
                    CRITERION_LABELS[item]
                    for item in sorted(criteria)
                    if item in CRITERION_LABELS
                ],
                "status": str(issue_status),
                "message": str(issue.get("message") or ""),
                "effort": str(issue.get("effort") or issue.get("debt") or ""),
                "author": str(issue.get("author") or ""),
                "tags": list(issue.get("tags") or []),
                "quick_fix_available": issue.get("quickFixAvailable"),
                "secondary_locations": _secondary_locations(issue, file_path),
                "sonar_url": _issue_url(
                    client.base_url,
                    args,
                    str(issue.get("key") or key),
                    issue_project_key,
                ),
            }
        )

    report_issues.sort(
        key=lambda item: (
            str(item.get("file") or "").lower(),
            _line_sort_key(item.get("start_line")),
            str(item.get("issue_key") or ""),
        )
    )

    if mode == "mqr":
        thresholds: Dict[str, Any] = {
            "security": {
                "minimum": "MEDIUM",
                "included": list(MQR_SECURITY_LEVELS),
            },
            "reliability": {
                "minimum": "HIGH",
                "included": list(MQR_RELIABILITY_LEVELS),
            },
        }
        if mqr_security_levels is not None:
            thresholds["mqr_api_levels_used"] = list(mqr_security_levels)
    else:
        thresholds = {
            "security": {
                "minimum_mqr_equivalent": "MEDIUM",
                "type": "VULNERABILITY",
                "included_standard_severities": list(STANDARD_SECURITY_LEVELS),
            },
            "reliability": {
                "minimum_mqr_equivalent": "HIGH",
                "type": "BUG",
                "included_standard_severities": list(STANDARD_RELIABILITY_LEVELS),
            },
        }

    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sonar_url": client.base_url,
        "project_key": args.project_key,
        "branch": args.branch,
        "pull_request": args.pull_request,
        "mode": mode,
        "unresolved_only": args.unresolved_only,
        "new_code_only": args.new_code,
        "thresholds": thresholds,
        "issue_count": len(report_issues),
        "issues": report_issues,
    }


def _line_sort_key(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 2**31 - 1


def _issue_url(
    base_url: str,
    args: argparse.Namespace,
    issue_key: str,
    project_key: str,
) -> str:
    params: Dict[str, str] = {"open": issue_key, "id": project_key}
    if args.branch:
        params["branch"] = args.branch
    if args.pull_request:
        params["pullRequest"] = args.pull_request
    organization = getattr(args, "organization", None)
    if organization:
        params["organization"] = organization
    return f"{base_url}/project/issues?{urlencode(params)}"


def _md_escape(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")


def _location_text(issue: Mapping[str, Any]) -> str:
    file_path = issue.get("file") or "<unknown-file>"
    start_line = issue.get("start_line") or "?"
    end_line = issue.get("end_line")
    if end_line and end_line != start_line:
        line = f"{start_line}-{end_line}"
    else:
        line = str(start_line)
    start_column = issue.get("start_column")
    end_column = issue.get("end_column")
    if start_column is not None:
        column = f", 列 {start_column}"
        if end_column is not None:
            column += f"-{end_column}"
    else:
        column = ""
    return f"{file_path}:{line}{column}"


def render_markdown(report: Mapping[str, Any]) -> str:
    issues = report.get("issues", []) or []
    if report.get("all_projects"):
        project_display = f"全部可见项目（{report.get('project_count', 0)} 个）"
    else:
        project_display = report.get("project_key") or "未指定"
    lines = [
        "# SonarQube 安全性/可靠性问题报告",
        "",
        f"- 项目：`{_md_escape(project_display)}`",
        f"- SonarQube：`{_md_escape(report.get('sonar_url'))}`",
        f"- 查询模式：`{_md_escape(report.get('mode'))}`",
        f"- 生成时间：`{_md_escape(report.get('generated_at'))}`",
        f"- 命中问题：**{report.get('issue_count', 0)}**",
        "- 筛选条件：安全性 ≥ 中危；可靠性 ≥ 高危",
    ]
    if report.get("branch"):
        lines.append(f"- 分支：`{_md_escape(report['branch'])}`")
    if report.get("pull_request"):
        lines.append(f"- Pull Request：`{_md_escape(report['pull_request'])}`")
    lines.extend(
        [
            "",
            "| 项目 | 代码位置 | 匹配条件 | 规则 | 类型/等级 | 状态 | 问题描述 | Sonar 链接 |",
            "|---|---|---|---|---|---|---|---|",
        ]
    )

    for issue in issues:
        criteria = ", ".join(issue.get("matched_criteria_labels", []) or [])
        if issue.get("quality_severities"):
            # In MQR mode, impacts are the values shown in the SonarQube UI.
            # The legacy type/severity fields can still be returned by the
            # API, but they are intentionally not used as the primary display.
            type_or_severity = ", ".join(
                f"{quality}/{severity}"
                for quality, severity in sorted(issue["quality_severities"].items())
            )
        else:
            type_or_severity = issue.get("type") or ""
            if issue.get("severity"):
                type_or_severity = f"{type_or_severity}/{issue['severity']}".strip("/")

        lines.append(
            "| "
            + " | ".join(
                [
                    _md_escape(issue.get("project_name") or issue.get("project_key")),
                    _md_escape(_location_text(issue)),
                    _md_escape(criteria),
                    _md_escape(
                        f"{issue.get('rule', '')} {issue.get('rule_name', '')}".strip()
                    ),
                    _md_escape(type_or_severity),
                    _md_escape(issue.get("status")),
                    _md_escape(issue.get("message")),
                    f"[打开]({issue.get('sonar_url', '')})",
                ]
            )
            + "|"
        )

    if not issues:
        lines.append("| - | - | - | - | - | - | 未找到符合条件的问题 | - |")
    errors = report.get("errors", []) or []
    if errors:
        lines.extend(
            [
                "",
                "## 未能处理的项目",
                "",
                "| 项目 Key | 项目名称 | 原因 |",
                "|---|---|---|",
            ]
        )
        for error in errors:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _md_escape(error.get("project_key")),
                        _md_escape(error.get("project_name")),
                        _md_escape(error.get("error")),
                    ]
                )
                + " |"
            )
    lines.append("")
    return "\n".join(lines)


def render_csv(report: Mapping[str, Any]) -> str:
    output = StringIO()
    fieldnames = [
        "issue_key",
        "project_key",
        "project_name",
        "file",
        "start_line",
        "end_line",
        "start_column",
        "end_column",
        "matched_criteria",
        "rule",
        "rule_name",
        "language",
        "type",
        "severity",
        "quality_severities",
        "status",
        "message",
        "effort",
        "author",
        "tags",
        "sonar_url",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for issue in report.get("issues", []) or []:
        row = dict(issue)
        row["matched_criteria"] = ", ".join(issue.get("matched_criteria_labels", []) or [])
        row["quality_severities"] = json.dumps(
            issue.get("quality_severities", {}), ensure_ascii=False
        )
        row["tags"] = ", ".join(str(tag) for tag in issue.get("tags", []) or [])
        writer.writerow(row)
    return output.getvalue()


def render_report(report: Mapping[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if output_format == "csv":
        return render_csv(report)
    return render_markdown(report)


def _args_for_project(args: argparse.Namespace, project_key: str) -> argparse.Namespace:
    project_args = argparse.Namespace(**vars(args))
    project_args.project_key = project_key
    return project_args


def fetch_one_project_report(
    client: SonarClient,
    args: argparse.Namespace,
) -> Dict[str, Any]:
    """Fetch and normalize one project's report."""

    if args.mode == "standard":
        accumulator, metadata = fetch_standard_issues(client, args)
        mode = "standard"
        mqr_levels = None
    elif args.mode == "mqr":
        accumulator, metadata, mqr_levels = fetch_mqr_issues(client, args)
        mode = "mqr"
    else:
        try:
            accumulator, metadata, mqr_levels = fetch_mqr_issues(client, args)
            mode = "mqr"
        except SonarApiError as exc:
            if exc.status not in (400, 404, 422):
                raise
            if args.verbose:
                print(
                    f"项目 {args.project_key} 不支持新版 MQR 参数，回退到传统查询。",
                    file=sys.stderr,
                )
            accumulator, metadata = fetch_standard_issues(client, args)
            mode = "standard"
            mqr_levels = None

    return build_report(
        accumulator,
        metadata,
        client,
        args,
        mode,
        mqr_security_levels=mqr_levels,
    )


def combine_project_reports(
    reports: Sequence[Mapping[str, Any]],
    projects: Sequence[Mapping[str, Any]],
    errors: Sequence[Mapping[str, Any]],
    client: SonarClient,
    args: argparse.Namespace,
) -> Dict[str, Any]:
    """Combine per-project reports into one result."""

    project_names = {
        str(project.get("key")): str(project.get("name") or "")
        for project in projects
        if project.get("key")
    }
    issues: List[Dict[str, Any]] = []
    for project_report in reports:
        for issue in project_report.get("issues", []) or []:
            if not isinstance(issue, Mapping):
                continue
            normalized = dict(issue)
            project_key = str(normalized.get("project_key") or "")
            normalized["project_name"] = project_names.get(project_key, "")
            issues.append(normalized)

    issues.sort(
        key=lambda item: (
            str(item.get("project_key") or "").lower(),
            str(item.get("file") or "").lower(),
            _line_sort_key(item.get("start_line")),
            str(item.get("issue_key") or ""),
        )
    )

    modes = {str(report.get("mode")) for report in reports if report.get("mode")}
    if len(modes) == 1:
        mode = next(iter(modes))
    elif modes:
        mode = "mixed"
    else:
        mode = "none"

    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sonar_url": client.base_url,
        "organization": getattr(args, "organization", None),
        "project_key": args.project_key,
        "all_projects": not bool(args.project_key),
        "project_count": len(projects),
        "projects": [
            {
                "project_key": str(project.get("key")),
                "project_name": str(project.get("name") or ""),
            }
            for project in projects
        ],
        "branch": args.branch,
        "pull_request": args.pull_request,
        "mode": mode,
        "unresolved_only": args.unresolved_only,
        "new_code_only": args.new_code,
        "thresholds": {
            "security": {
                "mqr_minimum": "MEDIUM",
                "mqr_levels": list(MQR_SECURITY_LEVELS),
                "standard_type": "VULNERABILITY",
                "standard_levels": list(STANDARD_SECURITY_LEVELS),
            },
            "reliability": {
                "mqr_minimum": "HIGH",
                "mqr_levels": list(MQR_RELIABILITY_LEVELS),
                "standard_type": "BUG",
                "standard_levels": list(STANDARD_RELIABILITY_LEVELS),
            },
        },
        "issue_count": len(issues),
        "issues": issues,
        "errors": [dict(error) for error in errors],
    }


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="通过 SonarQube API 导出安全性≥中危、可靠性≥高危的问题及代码位置。"
    )
    parser.add_argument(
        "--url",
        default=os.getenv("SONAR_URL"),
        help="SonarQube 地址，例如 https://sonar.example.com（也可用 SONAR_URL）",
    )
    parser.add_argument(
        "--token",
        default=os.getenv("SONAR_TOKEN"),
        help="SonarQube 用户令牌（推荐使用 SONAR_TOKEN 环境变量）",
    )
    parser.add_argument(
        "--project-key",
        default=os.getenv("SONAR_PROJECT_KEY"),
        help="可选的项目 key；不提供时处理当前账号可见的全部项目",
    )
    parser.add_argument(
        "--organization",
        default=os.getenv("SONAR_ORGANIZATION"),
        help="SonarQube Cloud 组织 key（Server 通常不需要，也可用 SONAR_ORGANIZATION）",
    )
    parser.add_argument(
        "--mode",
        choices=("auto", "mqr", "standard"),
        default="auto",
        help="查询模式；auto 优先使用新版 MQR，失败后回退到传统模式",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "json", "csv"),
        default="markdown",
        dest="output_format",
        help="输出格式，默认 markdown",
    )
    parser.add_argument(
        "--output",
        help="输出文件；不填写时写到标准输出，填写 - 也表示标准输出",
    )
    parser.add_argument(
        "--page-size",
        type=int,
        default=500,
        help="每页数量，范围 1-500，默认 500",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="单次请求超时时间（秒），默认 30",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=3,
        help="连接失败或 5xx/429 时的重试次数，默认 3",
    )
    status_group = parser.add_mutually_exclusive_group()
    status_group.add_argument(
        "--unresolved-only",
        action="store_true",
        dest="unresolved_only",
        default=True,
        help="只导出未解决问题（默认行为，保留此参数用于兼容旧用法）",
    )
    status_group.add_argument(
        "--include-resolved",
        action="store_false",
        dest="unresolved_only",
        help="同时导出已解决、已接受和误报问题",
    )
    parser.add_argument(
        "--new-code",
        action="store_true",
        help="只导出新代码周期内的问题",
    )
    parser.add_argument("--branch", help="分支名称；不能与 --pull-request 同时使用")
    parser.add_argument("--pull-request", help="Pull Request 编号；不能与 --branch 同时使用")
    parser.add_argument("--created-after", help="问题创建时间下限，例如 2026-01-01")
    parser.add_argument("--created-before", help="问题创建时间上限，例如 2026-09-01")
    parser.add_argument("--time-zone", help="created-after/before 使用的时区，例如 Asia/Shanghai")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="跳过 TLS 证书校验，仅适用于自签名证书的内网环境",
    )
    parser.add_argument("--verbose", action="store_true", help="打印请求进度到 stderr")

    args = parser.parse_args(argv)
    if not args.url:
        parser.error("请通过 --url 或 SONAR_URL 提供 SonarQube 地址")
    if not args.token:
        # Prompting keeps the token out of shell history while still allowing
        # an interactive one-off run.
        try:
            args.token = getpass.getpass("SonarQube token: ").strip()
        except (EOFError, KeyboardInterrupt):
            parser.error("未提供 SonarQube token，请设置 SONAR_TOKEN")
    if not args.token:
        parser.error("SonarQube token 不能为空，请设置 SONAR_TOKEN")
    if not 1 <= args.page_size <= 500:
        parser.error("--page-size 必须在 1 到 500 之间")
    if args.timeout <= 0:
        parser.error("--timeout 必须大于 0")
    if args.retries < 0:
        parser.error("--retries 不能小于 0")
    if args.branch and args.pull_request:
        parser.error("--branch 与 --pull-request 不能同时使用")
    return args


def write_output(content: str, output_path: Optional[str]) -> None:
    if not output_path or output_path == "-":
        sys.stdout.write(content)
        return
    Path(output_path).write_text(content, encoding="utf-8")
    print(f"报告已写入: {output_path}", file=sys.stderr)


def run(args: argparse.Namespace) -> int:
    client = SonarClient(
        base_url=args.url,
        token=args.token,
        timeout=args.timeout,
        retries=args.retries,
        insecure=args.insecure,
        verbose=args.verbose,
    )

    if args.project_key:
        projects: List[Dict[str, Any]] = [
            {"key": args.project_key, "name": ""},
        ]
    else:
        print("正在获取当前账号可见的项目列表...", file=sys.stderr)
        projects = list_visible_projects(client, args)
        print(f"发现 {len(projects)} 个当前账号可见项目。", file=sys.stderr)

    reports: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    for index, project in enumerate(projects, start=1):
        project_key = str(project["key"])
        project_args = _args_for_project(args, project_key)
        if args.verbose:
            print(
                f"[{index}/{len(projects)}] 正在处理项目 {project_key}",
                file=sys.stderr,
            )
        try:
            reports.append(fetch_one_project_report(client, project_args))
        except TooManyIssuesError as exc:
            error = {
                "project_key": project_key,
                "project_name": project.get("name", ""),
                "error": str(exc),
            }
            errors.append(error)
            print(f"跳过项目 {project_key}: {exc}", file=sys.stderr)
        except SonarApiError as exc:
            # A bad token is global and should not be hidden by processing the
            # remaining projects. Other project-level errors are kept in the
            # final report so one inaccessible project does not erase results
            # from all the other visible projects.
            if exc.status == 401:
                raise
            error = {
                "project_key": project_key,
                "project_name": project.get("name", ""),
                "error": str(exc),
            }
            errors.append(error)
            print(f"跳过项目 {project_key}: {exc}", file=sys.stderr)

    report = combine_project_reports(reports, projects, errors, client, args)
    write_output(render_report(report, args.output_format), args.output)
    print(
        f"处理完成：项目 {len(projects)} 个，匹配问题 {report['issue_count']} 个，失败项目 {len(errors)} 个。",
        file=sys.stderr,
    )
    return 2 if errors and not reports else 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        args = parse_args(argv)
        return run(args)
    except TooManyIssuesError as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 2
    except SonarApiError as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("已取消。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
