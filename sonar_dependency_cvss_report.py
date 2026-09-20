#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
扫描当前 SonarQube Token 有 Browse 权限的全部项目，
提取 OWASP Dependency-Check 产生的依赖漏洞，
并筛选 CVSS >= 指定阈值的问题。

默认：
    CVSS >= 3
    只查看尚未处理的问题
    同时检查：
      1. Security Hotspots
      2. 普通 Dependency-Check Issues

环境变量：
    SONAR_URL
    SONAR_TOKEN

运行：
    python sonar_dependency_cvss_report.py

指定 CVSS：
    python sonar_dependency_cvss_report.py --min-cvss 3

输出 CSV：
    python sonar_dependency_cvss_report.py --format csv --output dependency.csv

包含已经 REVIEWED / RESOLVED 的问题：
    python sonar_dependency_cvss_report.py --include-reviewed
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import ssl
import sys
from io import StringIO
from typing import Any, Dict, List, Mapping, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


# ============================================================
# Dependency-Check 的 SonarQube Rule
# ============================================================

DEPENDENCY_HOTSPOT_RULE = (
    "OWASP:UsingComponentWithKnownVulnerabilitySecurityHotspot"
)

DEPENDENCY_ISSUE_RULE = (
    "OWASP:UsingComponentWithKnownVulnerability"
)


# ============================================================
# API
# ============================================================

class SonarApiError(RuntimeError):

    def __init__(
        self,
        message: str,
        status: Optional[int] = None,
        response_body: str = "",
    ):
        super().__init__(message)
        self.status = status
        self.response_body = response_body


class SonarClient:

    def __init__(
        self,
        base_url: str,
        token: str,
        timeout: float = 30.0,
        insecure: bool = False,
        verbose: bool = False,
    ):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.verbose = verbose

        self.ssl_context = (
            ssl._create_unverified_context()
            if insecure
            else ssl.create_default_context()
        )

    def get_json(
        self,
        endpoint: str,
        params: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:

        params = params or {}

        query = {
            key: str(value)
            for key, value in params.items()
            if value is not None and value != ""
        }

        url = (
            f"{self.base_url}/{endpoint.lstrip('/')}"
        )

        if query:
            url += "?" + urlencode(query)

        if self.verbose:
            print(
                f"GET {url}",
                file=sys.stderr,
            )

        request = Request(
            url,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self.token}",
            },
            method="GET",
        )

        try:

            with urlopen(
                request,
                timeout=self.timeout,
                context=self.ssl_context,
            ) as response:
                raw = response.read()

        except HTTPError as exc:

            body = exc.read().decode(
                "utf-8",
                errors="replace",
            )

            raise SonarApiError(
                f"HTTP {exc.code}: {body[:500]}",
                status=exc.code,
                response_body=body,
            ) from exc

        except URLError as exc:

            raise SonarApiError(
                f"无法连接 SonarQube: {exc.reason}"
            ) from exc

        try:

            result = json.loads(
                raw.decode("utf-8")
            )

        except Exception as exc:

            raise SonarApiError(
                "SonarQube 返回的不是合法 JSON"
            ) from exc

        if not isinstance(result, dict):
            raise SonarApiError(
                "SonarQube 返回 JSON 顶层不是对象"
            )

        return result


# ============================================================
# 项目
# ============================================================

def list_projects(
    client: SonarClient,
    page_size: int,
) -> List[Dict[str, str]]:

    result: Dict[str, Dict[str, str]] = {}

    page = 1

    while True:

        data = client.get_json(
            "api/components/search",
            {
                "qualifiers": "TRK",
                "p": page,
                "ps": page_size,
            },
        )

        components = data.get(
            "components",
            [],
        )

        if not isinstance(
            components,
            list,
        ):
            components = []

        for item in components:

            if not isinstance(
                item,
                dict,
            ):
                continue

            key = str(
                item.get("key") or ""
            )

            if not key:
                continue

            result[key] = {
                "key": key,
                "name": str(
                    item.get("name")
                    or item.get("longName")
                    or key
                ),
            }

        paging = data.get(
            "paging",
            {},
        )

        try:
            total = int(
                paging.get("total")
                or len(result)
            )
        except Exception:
            total = len(result)

        try:
            effective_page_size = int(
                paging.get("pageSize")
                or page_size
            )
        except Exception:
            effective_page_size = page_size

        if not components:
            break

        if page * effective_page_size >= total:
            break

        page += 1

    return list(
        result.values()
    )


# ============================================================
# CVSS 信息解析
# ============================================================

CVSS_RE = re.compile(
    r"(?:Highest\s+)?CVSS\s+Score\s*:\s*"
    r"([0-9]+(?:\.[0-9]+)?)",
    re.IGNORECASE,
)

REFERENCE_RE = re.compile(
    r"Reference\s*:\s*([^|]+)",
    re.IGNORECASE,
)

REFERENCES_RE = re.compile(
    r"References\s*:\s*(.+)$",
    re.IGNORECASE,
)

FILE_RE = re.compile(
    r"(?:Filename|Filepath)\s*:\s*([^|]+)",
    re.IGNORECASE,
)


def extract_cvss(
    message: str,
) -> Optional[float]:

    match = CVSS_RE.search(
        message or ""
    )

    if not match:
        return None

    try:
        return float(
            match.group(1)
        )
    except ValueError:
        return None


def extract_reference(
    message: str,
) -> str:

    match = REFERENCE_RE.search(
        message or ""
    )

    if match:
        return match.group(1).strip()

    match = REFERENCES_RE.search(
        message or ""
    )

    if match:
        return match.group(1).strip()

    return ""


def extract_file(
    message: str,
) -> str:

    match = FILE_RE.search(
        message or ""
    )

    if not match:
        return ""

    return match.group(1).strip()


def extract_description(
    message: str,
) -> str:

    parts = [
        value.strip()
        for value in (
            message or ""
        ).split("|")
    ]

    if len(parts) <= 1:
        return message.strip()

    return parts[-1]


# ============================================================
# Hotspots
# ============================================================

def fetch_hotspots(
    client: SonarClient,
    project_key: str,
    page_size: int,
    include_reviewed: bool,
) -> List[Dict[str, Any]]:

    page = 1
    result: List[Dict[str, Any]] = []

    while True:

        params: Dict[str, Any] = {
            "project": project_key,
            "sonarsourceSecurity": "others",
            "p": page,
            "ps": page_size,
        }

        if not include_reviewed:
            params["status"] = "TO_REVIEW"

        data = client.get_json(
            "api/hotspots/search",
            params,
        )

        hotspots = data.get(
            "hotspots",
            [],
        )

        if not isinstance(
            hotspots,
            list,
        ):
            hotspots = []

        for hotspot in hotspots:

            if not isinstance(
                hotspot,
                dict,
            ):
                continue

            rule_key = str(
                hotspot.get(
                    "ruleKey"
                )
                or ""
            )

            # 只保留 Dependency-Check
            if (
                rule_key
                != DEPENDENCY_HOTSPOT_RULE
            ):
                continue

            result.append(
                hotspot
            )

        paging = data.get(
            "paging",
            {},
        )

        try:
            total = int(
                paging.get("total")
                or 0
            )
        except Exception:
            total = 0

        try:
            effective_page_size = int(
                paging.get("pageSize")
                or page_size
            )
        except Exception:
            effective_page_size = page_size

        if not hotspots:
            break

        if (
            total
            and page * effective_page_size
            >= total
        ):
            break

        if (
            len(hotspots)
            < effective_page_size
        ):
            break

        page += 1

    return result


# ============================================================
# 普通 Dependency-Check Issues
# ============================================================

def fetch_dependency_issues(
    client: SonarClient,
    project_key: str,
    page_size: int,
    include_reviewed: bool,
) -> List[Dict[str, Any]]:

    page = 1
    result: List[Dict[str, Any]] = []

    while True:

        params: Dict[str, Any] = {
            "componentKeys": project_key,
            "rules": DEPENDENCY_ISSUE_RULE,
            "p": page,
            "ps": page_size,
        }

        if not include_reviewed:
            params["resolved"] = "false"

        data = client.get_json(
            "api/issues/search",
            params,
        )

        issues = data.get(
            "issues",
            [],
        )

        if not isinstance(
            issues,
            list,
        ):
            issues = []

        for issue in issues:

            if isinstance(
                issue,
                dict,
            ):
                result.append(issue)

        paging = data.get(
            "paging",
            {},
        )

        try:
            total = int(
                paging.get(
                    "total",
                    data.get(
                        "total",
                        0,
                    ),
                )
            )
        except Exception:
            total = 0

        try:
            effective_page_size = int(
                paging.get("pageSize")
                or page_size
            )
        except Exception:
            effective_page_size = page_size

        if not issues:
            break

        if (
            total
            and page * effective_page_size
            >= total
        ):
            break

        if (
            len(issues)
            < effective_page_size
        ):
            break

        page += 1

    return result


# ============================================================
# 格式标准化
# ============================================================

def normalize_hotspot(
    base_url: str,
    project: Mapping[str, str],
    hotspot: Mapping[str, Any],
) -> Dict[str, Any]:

    message = str(
        hotspot.get("message")
        or ""
    )

    key = str(
        hotspot.get("key")
        or ""
    )

    project_key = project["key"]

    return {
        "project_key": project_key,
        "project_name": project["name"],
        "source": "Security Hotspot",
        "key": key,
        "rule": str(
            hotspot.get("ruleKey")
            or ""
        ),
        "status": str(
            hotspot.get("status")
            or ""
        ),
        "resolution": str(
            hotspot.get("resolution")
            or ""
        ),
        "cvss": extract_cvss(
            message
        ),
        "reference": extract_reference(
            message
        ),
        "dependency": extract_file(
            message
        ),
        "message": message,
        "description": extract_description(
            message
        ),
        "component": str(
            hotspot.get("component")
            or ""
        ),
        "line": hotspot.get("line"),
        "url": (
            f"{base_url.rstrip('/')}"
            f"/security_hotspots"
            f"?id={quote(project_key)}"
            f"&hotspots={quote(key)}"
        ),
    }


def normalize_issue(
    base_url: str,
    project: Mapping[str, str],
    issue: Mapping[str, Any],
) -> Dict[str, Any]:

    message = str(
        issue.get("message")
        or ""
    )

    key = str(
        issue.get("key")
        or ""
    )

    project_key = project["key"]

    text_range = issue.get(
        "textRange",
        {},
    )

    if not isinstance(
        text_range,
        dict,
    ):
        text_range = {}

    return {
        "project_key": project_key,
        "project_name": project["name"],
        "source": "Issue",
        "key": key,
        "rule": str(
            issue.get("rule")
            or ""
        ),
        "status": str(
            issue.get("status")
            or ""
        ),
        "resolution": str(
            issue.get("resolution")
            or ""
        ),
        "cvss": extract_cvss(
            message
        ),
        "reference": extract_reference(
            message
        ),
        "dependency": extract_file(
            message
        ),
        "message": message,
        "description": extract_description(
            message
        ),
        "component": str(
            issue.get("component")
            or ""
        ),
        "line": text_range.get(
            "startLine"
        ),
        "url": (
            f"{base_url.rstrip('/')}"
            f"/project/issues"
            f"?id={quote(project_key)}"
            f"&issues={quote(key)}"
            f"&open={quote(key)}"
        ),
    }


# ============================================================
# 输出
# ============================================================

def render_markdown(
    items: List[Dict[str, Any]],
    projects: List[Dict[str, str]],
    project_stats: Mapping[str, Any],
    errors: List[Dict[str, str]],
    unparsed: List[Dict[str, Any]],
    min_cvss: float,
) -> str:

    lines: List[str] = []

    lines.append(
        "# SonarQube 依赖漏洞报告"
    )
    lines.append("")

    lines.append(
        f"- 可查看项目：{len(projects)}"
    )
    lines.append(
        f"- CVSS 条件：>= {min_cvss:g}"
    )
    lines.append(
        f"- 需要处理的问题：{len(items)}"
    )
    lines.append(
        f"- CVSS 无法解析：{len(unparsed)}"
    )
    lines.append(
        f"- 扫描失败项目：{len(errors)}"
    )
    lines.append("")

    lines.append(
        "## 项目统计"
    )
    lines.append("")
    lines.append(
        "| 项目 | Key | Hotspot | Issue | CVSS达标 |"
    )
    lines.append(
        "|---|---|---:|---:|---:|"
    )

    for project in projects:

        key = project["key"]

        stats = project_stats.get(
            key,
            {},
        )

        lines.append(
            "| "
            + " | ".join(
                [
                    escape_md(
                        project["name"]
                    ),
                    escape_md(key),
                    str(
                        stats.get(
                            "hotspots",
                            0,
                        )
                    ),
                    str(
                        stats.get(
                            "issues",
                            0,
                        )
                    ),
                    str(
                        stats.get(
                            "matched",
                            0,
                        )
                    ),
                ]
            )
            + " |"
        )

    lines.append("")

    lines.append(
        "## CVSS 达标依赖问题"
    )
    lines.append("")

    if not items:

        lines.append(
            "没有发现符合条件的依赖问题。"
        )
        lines.append("")

    else:

        lines.append(
            "| 项目 | 依赖文件 | CVE/Reference | CVSS | 状态 | 来源 |"
        )
        lines.append(
            "|---|---|---|---:|---|---|"
        )

        for item in items:

            lines.append(
                "| "
                + " | ".join(
                    [
                        escape_md(
                            item[
                                "project_name"
                            ]
                        ),
                        escape_md(
                            item.get(
                                "dependency"
                            )
                            or "-"
                        ),
                        escape_md(
                            item.get(
                                "reference"
                            )
                            or "-"
                        ),
                        str(
                            item.get(
                                "cvss"
                            )
                        ),
                        escape_md(
                            item.get(
                                "status"
                            )
                            or "-"
                        ),
                        escape_md(
                            item.get(
                                "source"
                            )
                            or "-"
                        ),
                    ]
                )
                + " |"
            )

        lines.append("")

        lines.append("## 问题明细")
        lines.append("")

        for index, item in enumerate(
            items,
            start=1,
        ):

            lines.append(
                f"### {index}. "
                f"{item['project_name']} - "
                f"{item.get('reference') or item.get('dependency') or item['key']}"
            )
            lines.append("")

            lines.append(
                f"- 项目 Key：`{item['project_key']}`"
            )
            lines.append(
                f"- CVSS：`{item['cvss']}`"
            )
            lines.append(
                f"- 依赖：`{item.get('dependency') or '-'}`"
            )
            lines.append(
                f"- CVE/Reference：`{item.get('reference') or '-'}`"
            )
            lines.append(
                f"- 状态：`{item.get('status') or '-'}`"
            )
            lines.append(
                f"- 来源：`{item.get('source')}`"
            )
            lines.append(
                f"- Rule：`{item.get('rule')}`"
            )

            if item.get("component"):
                lines.append(
                    f"- Component：`{item['component']}`"
                )

            if item.get("line"):
                lines.append(
                    f"- 行号：`{item['line']}`"
                )

            lines.append(
                f"- Sonar 地址：{item['url']}"
            )

            lines.append("")
            lines.append(
                f"问题描述：{item.get('message') or '-'}"
            )
            lines.append("")

    if unparsed:

        lines.append(
            "## 未解析出 CVSS 的 Dependency-Check 问题"
        )
        lines.append("")

        lines.append(
            "这些问题属于 Dependency-Check，但消息中没有识别到 CVSS，请人工确认："
        )
        lines.append("")

        for item in unparsed:

            lines.append(
                f"- {item['project_name']} / "
                f"{item.get('key')}: "
                f"{item.get('message')}"
            )

        lines.append("")

    if errors:

        lines.append(
            "## 扫描失败项目"
        )
        lines.append("")

        for error in errors:

            lines.append(
                f"- `{error['project_key']}`："
                f"{error['error']}"
            )

        lines.append("")

    return "\n".join(lines)


def escape_md(
    value: Any,
) -> str:

    return (
        str(value or "")
        .replace("|", "\\|")
        .replace("\n", " ")
    )


def render_csv(
    items: List[Dict[str, Any]],
) -> str:

    fields = [
        "project_name",
        "project_key",
        "dependency",
        "reference",
        "cvss",
        "status",
        "resolution",
        "source",
        "rule",
        "component",
        "line",
        "message",
        "url",
    ]

    output = StringIO()

    writer = csv.DictWriter(
        output,
        fieldnames=fields,
    )

    writer.writeheader()

    for item in items:

        writer.writerow(
            {
                field: item.get(
                    field,
                    "",
                )
                for field in fields
            }
        )

    return output.getvalue()


# ============================================================
# 参数
# ============================================================

def parse_args():

    parser = argparse.ArgumentParser(
        description=(
            "扫描所有可查看的 SonarQube 项目，"
            "提取 OWASP Dependency-Check "
            "CVSS 依赖漏洞"
        )
    )

    parser.add_argument(
        "--url",
        default=os.getenv(
            "SONAR_URL"
        ),
    )

    parser.add_argument(
        "--token",
        default=os.getenv(
            "SONAR_TOKEN"
        ),
    )

    parser.add_argument(
        "--min-cvss",
        type=float,
        default=3.0,
    )

    parser.add_argument(
        "--include-reviewed",
        action="store_true",
        help=(
            "包含已经 REVIEWED / "
            "RESOLVED 的问题"
        ),
    )

    parser.add_argument(
        "--format",
        choices=[
            "markdown",
            "json",
            "csv",
        ],
        default="markdown",
    )

    parser.add_argument(
        "--output",
        default=None,
    )

    parser.add_argument(
        "--page-size",
        type=int,
        default=500,
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=30,
    )

    parser.add_argument(
        "--insecure",
        action="store_true",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
    )

    return parser.parse_args()


# ============================================================
# Main
# ============================================================

def main() -> int:

    args = parse_args()

    if not args.url:
        print(
            "缺少 SONAR_URL",
            file=sys.stderr,
        )
        return 2

    if not args.token:
        print(
            "缺少 SONAR_TOKEN",
            file=sys.stderr,
        )
        return 2

    client = SonarClient(
        base_url=args.url,
        token=args.token,
        timeout=args.timeout,
        insecure=args.insecure,
        verbose=args.verbose,
    )

    try:

        print(
            "正在获取当前账号可见项目...",
            file=sys.stderr,
        )

        projects = list_projects(
            client,
            args.page_size,
        )

    except SonarApiError as exc:

        print(
            f"获取项目失败：{exc}",
            file=sys.stderr,
        )
        return 1

    print(
        f"共发现 {len(projects)} 个项目",
        file=sys.stderr,
    )

    matched: List[
        Dict[str, Any]
    ] = []

    unparsed: List[
        Dict[str, Any]
    ] = []

    errors: List[
        Dict[str, str]
    ] = []

    project_stats: Dict[
        str,
        Dict[str, int],
    ] = {}

    for index, project in enumerate(
        projects,
        start=1,
    ):

        key = project["key"]
        name = project["name"]

        print(
            f"[{index}/{len(projects)}] "
            f"扫描 {name} ({key})",
            file=sys.stderr,
        )

        stats = {
            "hotspots": 0,
            "issues": 0,
            "matched": 0,
        }

        project_stats[key] = stats

        project_items: List[
            Dict[str, Any]
        ] = []

        project_failed = False

        # -------------------------
        # Security Hotspots
        # -------------------------

        try:

            hotspots = fetch_hotspots(
                client,
                key,
                args.page_size,
                args.include_reviewed,
            )

            stats["hotspots"] = len(
                hotspots
            )

            for hotspot in hotspots:

                project_items.append(
                    normalize_hotspot(
                        args.url,
                        project,
                        hotspot,
                    )
                )

        except SonarApiError as exc:

            project_failed = True

            errors.append(
                {
                    "project_key": key,
                    "error": (
                        "Hotspot API: "
                        f"{exc}"
                    ),
                }
            )

        # -------------------------
        # 普通 Issue
        # -------------------------

        try:

            issues = (
                fetch_dependency_issues(
                    client,
                    key,
                    args.page_size,
                    args.include_reviewed,
                )
            )

            stats["issues"] = len(
                issues
            )

            for issue in issues:

                project_items.append(
                    normalize_issue(
                        args.url,
                        project,
                        issue,
                    )
                )

        except SonarApiError as exc:

            project_failed = True

            errors.append(
                {
                    "project_key": key,
                    "error": (
                        "Issue API: "
                        f"{exc}"
                    ),
                }
            )

        current_match = 0

        for item in project_items:

            cvss = item.get(
                "cvss"
            )

            if cvss is None:

                unparsed.append(
                    item
                )
                continue

            if float(cvss) < args.min_cvss:
                continue

            matched.append(
                item
            )

            current_match += 1

        stats["matched"] = (
            current_match
        )

        suffix = (
            "（存在 API 错误）"
            if project_failed
            else ""
        )

        print(
            "    "
            f"Dependency Hotspot={stats['hotspots']}，"
            f"Dependency Issue={stats['issues']}，"
            f"CVSS>={args.min_cvss:g}={current_match}"
            f"{suffix}",
            file=sys.stderr,
        )

    # ========================================================
    # 排序
    # ========================================================

    matched.sort(
        key=lambda item: (
            -float(
                item.get("cvss")
                or 0
            ),
            item.get(
                "project_name",
                "",
            ),
            item.get(
                "reference",
                "",
            ),
        )
    )

    # ========================================================
    # 输出
    # ========================================================

    if args.format == "json":

        content = json.dumps(
            {
                "min_cvss": args.min_cvss,
                "projects": projects,
                "issues": matched,
                "unparsed": unparsed,
                "errors": errors,
            },
            ensure_ascii=False,
            indent=2,
        )

        default_output = (
            "sonar-dependency-cvss.json"
        )

    elif args.format == "csv":

        content = render_csv(
            matched
        )

        default_output = (
            "sonar-dependency-cvss.csv"
        )

    else:

        content = render_markdown(
            matched,
            projects,
            project_stats,
            errors,
            unparsed,
            args.min_cvss,
        )

        default_output = (
            "sonar-dependency-cvss.md"
        )

    output = (
        args.output
        or default_output
    )

    with open(
        output,
        "w",
        encoding="utf-8-sig"
        if args.format == "csv"
        else "utf-8",
        newline="",
    ) as fp:
        fp.write(content)

    print(
        "",
        file=sys.stderr,
    )

    print(
        "==============================",
        file=sys.stderr,
    )

    print(
        f"项目总数：{len(projects)}",
        file=sys.stderr,
    )

    print(
        f"CVSS >= {args.min_cvss:g}："
        f"{len(matched)}",
        file=sys.stderr,
    )

    print(
        f"CVSS 无法解析："
        f"{len(unparsed)}",
        file=sys.stderr,
    )

    print(
        f"API 错误："
        f"{len(errors)}",
        file=sys.stderr,
    )

    print(
        f"报告：{output}",
        file=sys.stderr,
    )

    print(
        "==============================",
        file=sys.stderr,
    )

    # 有项目 API 失败时返回非 0，
    # 防止再次发生“全部失败但看起来是 0 个漏洞”
    if errors:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())