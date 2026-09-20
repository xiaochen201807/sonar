#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SonarQube Dependency Risk / CVE / CVSS 导出脚本

用途：
1. 获取 SonarQube Dependency Risks（依赖风险 / SCA）
2. 只保留漏洞类风险
3. 默认筛选 CVSS >= 3.0
4. 输出 Markdown / JSON / CSV
5. 支持单项目和全部可见项目

环境变量：
    SONAR_URL
    SONAR_TOKEN
    SONAR_PROJECT_KEY      可选，不填则尝试扫描全部可见项目
    SONAR_ORGANIZATION     SonarQube Cloud 时可选

示例：
    export SONAR_URL="http://127.0.0.1:9000"
    export SONAR_TOKEN="squ_xxxxx"
    export SONAR_PROJECT_KEY="my-project"

    python3 sonar_dependency_cvss_report.py

    python3 sonar_dependency_cvss_report.py \
        --min-cvss 3 \
        --output dependency-cvss-report.md

    python3 sonar_dependency_cvss_report.py \
        --format csv \
        --output dependency-cvss-report.csv

说明：
    Dependency Risks / SCA 需要 SonarQube Advanced Security。
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import ssl
import sys
from io import StringIO
from typing import Any, Dict, List, Mapping, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


# ============================================================
# Sonar API Client
# ============================================================

class SonarApiError(RuntimeError):
    def __init__(
        self,
        message: str,
        status: Optional[int] = None,
        response_body: str = "",
    ) -> None:
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
    ) -> None:
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

        url = f"{self.base_url}/{endpoint.lstrip('/')}"

        if query:
            url += "?" + urlencode(query)

        if self.verbose:
            print(f"GET {url}", file=sys.stderr)

        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.token}",
        }

        request = Request(
            url,
            headers=headers,
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
            body = exc.read().decode("utf-8", errors="replace")

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
            data = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise SonarApiError(
                "SonarQube 返回内容不是合法 JSON"
            ) from exc

        if not isinstance(data, dict):
            raise SonarApiError(
                "SonarQube 返回 JSON 顶层结构不是对象"
            )

        return data


# ============================================================
# Projects
# ============================================================

def list_projects(
    client: SonarClient,
    organization: Optional[str],
    page_size: int,
) -> List[Dict[str, str]]:

    projects: List[Dict[str, str]] = []

    page = 1

    while True:
        params: Dict[str, Any] = {
            "qualifiers": "TRK",
            "p": page,
            "ps": page_size,
        }

        if organization:
            params["organization"] = organization

        result = client.get_json(
            "api/components/search",
            params,
        )

        components = result.get("components") or []

        for item in components:
            if not isinstance(item, dict):
                continue

            key = item.get("key")

            if not key:
                continue

            projects.append(
                {
                    "key": str(key),
                    "name": str(
                        item.get("name")
                        or item.get("longName")
                        or key
                    ),
                }
            )

        paging = result.get("paging") or {}

        total = int(
            paging.get("total")
            or result.get("total")
            or len(components)
        )

        page_size_from_server = int(
            paging.get("pageSize")
            or page_size
        )

        if page * page_size_from_server >= total:
            break

        if not components:
            break

        page += 1

    return projects


# ============================================================
# Dependency Risk API
# ============================================================

DEPENDENCY_API_CANDIDATES = [
    # 不同 SonarQube 版本可能存在差异，所以逐个尝试。
    "api/v2/dependency-risks",
    "api/v2/dependency-risks/search",
    "api/dependency-risks/search",
    "api/dependency_risks/search",
]


def fetch_dependency_risk_page(
    client: SonarClient,
    project_key: str,
    branch: Optional[str],
    pull_request: Optional[str],
    page: int,
    page_size: int,
    endpoint: Optional[str] = None,
) -> tuple[str, Dict[str, Any]]:

    endpoints = (
        [endpoint]
        if endpoint
        else DEPENDENCY_API_CANDIDATES
    )

    last_error: Optional[Exception] = None

    parameter_variants = [
        {
            "projectKey": project_key,
            "branch": branch,
            "pullRequest": pull_request,
            "pageIndex": page,
            "pageSize": page_size,
        },
        {
            "projectKey": project_key,
            "branchKey": branch,
            "pullRequestKey": pull_request,
            "pageIndex": page,
            "pageSize": page_size,
        },
        {
            "project": project_key,
            "branch": branch,
            "pullRequest": pull_request,
            "p": page,
            "ps": page_size,
        },
    ]

    for current_endpoint in endpoints:

        for params in parameter_variants:

            try:
                result = client.get_json(
                    current_endpoint,
                    params,
                )

                return current_endpoint, result

            except SonarApiError as exc:

                last_error = exc

                # 404 / 400 很可能只是 API 或参数形式不匹配，
                # 继续尝试其它 endpoint。
                if exc.status in (
                    400,
                    404,
                    405,
                ):
                    continue

                # 没权限就直接报错
                if exc.status in (
                    401,
                    403,
                ):
                    raise

    raise SonarApiError(
        "没有找到可用的 Dependency Risk API。"
        "请确认 SonarQube 已启用 Advanced Security / SCA。"
    ) from last_error


def extract_items(
    payload: Mapping[str, Any],
) -> List[Dict[str, Any]]:

    candidate_keys = [
        "dependencyRisks",
        "risks",
        "items",
        "results",
        "issues",
    ]

    for key in candidate_keys:

        value = payload.get(key)

        if isinstance(value, list):
            return [
                item
                for item in value
                if isinstance(item, dict)
            ]

    # 有些 v2 API 可能套一层 page
    page_data = payload.get("page")

    if isinstance(page_data, dict):

        for key in candidate_keys:

            value = page_data.get(key)

            if isinstance(value, list):
                return [
                    item
                    for item in value
                    if isinstance(item, dict)
                ]

    return []


def has_next_page(
    payload: Mapping[str, Any],
    current_page: int,
    page_size: int,
    item_count: int,
) -> bool:

    paging = payload.get("paging")

    if isinstance(paging, dict):

        total = paging.get("total")

        if total is not None:

            try:
                total = int(total)

                return current_page * page_size < total

            except (TypeError, ValueError):
                pass

    page_info = payload.get("page")

    if isinstance(page_info, dict):

        total = page_info.get("totalElements")

        if total is not None:

            try:
                return (
                    current_page * page_size
                    < int(total)
                )

            except (TypeError, ValueError):
                pass

        if page_info.get("hasNext") is not None:
            return bool(page_info.get("hasNext"))

    return item_count >= page_size


def fetch_dependency_risks(
    client: SonarClient,
    project_key: str,
    branch: Optional[str],
    pull_request: Optional[str],
    page_size: int,
) -> List[Dict[str, Any]]:

    page = 1
    endpoint: Optional[str] = None

    all_items: List[Dict[str, Any]] = []

    while True:

        endpoint, result = fetch_dependency_risk_page(
            client=client,
            project_key=project_key,
            branch=branch,
            pull_request=pull_request,
            page=page,
            page_size=page_size,
            endpoint=endpoint,
        )

        items = extract_items(result)

        all_items.extend(items)

        if not has_next_page(
            result,
            page,
            page_size,
            len(items),
        ):
            break

        page += 1

    return all_items


# ============================================================
# Risk normalization
# ============================================================

def first_value(
    obj: Mapping[str, Any],
    *keys: str,
) -> Any:

    for key in keys:

        value = obj.get(key)

        if value not in (
            None,
            "",
            [],
            {},
        ):
            return value

    return None


def to_float(
    value: Any,
) -> Optional[float]:

    if value is None:
        return None

    if isinstance(value, (int, float)):
        return float(value)

    try:
        return float(str(value).strip())
    except ValueError:
        return None


def normalize_risk(
    project_key: str,
    project_name: str,
    risk: Mapping[str, Any],
) -> Dict[str, Any]:

    vulnerability = risk.get("vulnerability")

    if not isinstance(vulnerability, dict):
        vulnerability = {}

    dependency = risk.get("dependency")

    if not isinstance(dependency, dict):
        dependency = {}

    release = risk.get("release")

    if not isinstance(release, dict):
        release = {}

    package = risk.get("package")

    if not isinstance(package, dict):
        package = {}

    # ---------- CVSS ----------

    cvss = first_value(
        risk,
        "cvssScore",
        "cvss",
        "score",
    )

    if cvss is None:
        cvss = first_value(
            vulnerability,
            "cvssScore",
            "cvss",
            "score",
        )

    # 有些 API 会返回：
    # cvss = {"score": 7.5, "version": "3.1"}
    if isinstance(cvss, dict):

        cvss_score = to_float(
            first_value(
                cvss,
                "score",
                "baseScore",
                "value",
            )
        )

        cvss_version = str(
            first_value(
                cvss,
                "version",
                "cvssVersion",
            )
            or ""
        )

    else:

        cvss_score = to_float(cvss)

        cvss_version = str(
            first_value(
                risk,
                "cvssVersion",
            )
            or first_value(
                vulnerability,
                "cvssVersion",
            )
            or ""
        )

    # ---------- CVE ----------

    cve = first_value(
        risk,
        "cve",
        "cveId",
        "cveIdentifier",
    )

    if cve is None:
        cve = first_value(
            vulnerability,
            "cve",
            "cveId",
            "id",
        )

    cves = risk.get("cves")

    if not cve and isinstance(cves, list):
        cve = ", ".join(
            str(item)
            for item in cves
        )

    # ---------- Package ----------

    package_name = first_value(
        risk,
        "packageName",
        "dependencyName",
        "componentName",
    )

    if not package_name:

        package_name = first_value(
            dependency,
            "name",
            "packageName",
            "key",
        )

    if not package_name:

        package_name = first_value(
            release,
            "name",
            "packageName",
            "artifactId",
        )

    if not package_name:

        package_name = first_value(
            package,
            "name",
            "packageName",
        )

    # ---------- Version ----------

    version = first_value(
        risk,
        "version",
        "packageVersion",
        "dependencyVersion",
    )

    if not version:

        version = first_value(
            dependency,
            "version",
        )

    if not version:

        version = first_value(
            release,
            "version",
        )

    if not version:

        version = first_value(
            package,
            "version",
        )

    # ---------- Type ----------

    risk_type = str(
        first_value(
            risk,
            "type",
            "riskType",
            "category",
        )
        or ""
    ).upper()

    # ---------- Severity ----------

    severity = str(
        first_value(
            risk,
            "severity",
            "riskSeverity",
            "impactSeverity",
        )
        or first_value(
            vulnerability,
            "severity",
        )
        or ""
    ).upper()

    # ---------- Status ----------

    status = str(
        first_value(
            risk,
            "status",
            "riskStatus",
            "resolution",
        )
        or ""
    ).upper()

    # ---------- Identifiers ----------

    risk_id = str(
        first_value(
            risk,
            "id",
            "key",
            "uuid",
            "riskId",
        )
        or ""
    )

    title = str(
        first_value(
            risk,
            "title",
            "name",
            "message",
            "description",
        )
        or first_value(
            vulnerability,
            "title",
            "name",
            "description",
        )
        or ""
    )

    # ---------- CWE ----------

    cwe = first_value(
        risk,
        "cwe",
        "cweId",
        "cwes",
    )

    if cwe is None:
        cwe = first_value(
            vulnerability,
            "cwe",
            "cweId",
            "cwes",
        )

    if isinstance(cwe, list):
        cwe = ", ".join(
            str(item)
            for item in cwe
        )

    # ---------- Fix version ----------

    fixed_version = first_value(
        risk,
        "fixedVersion",
        "recommendedVersion",
        "upgradeVersion",
    )

    remediation = risk.get("remediation")

    if (
        not fixed_version
        and isinstance(remediation, dict)
    ):
        fixed_version = first_value(
            remediation,
            "fixedVersion",
            "recommendedVersion",
            "version",
        )

    return {
        "project_key": project_key,
        "project_name": project_name,

        "risk_id": risk_id,

        "type": risk_type,
        "severity": severity,
        "status": status,

        "package": str(package_name or ""),
        "version": str(version or ""),

        "cve": str(cve or ""),
        "cwe": str(cwe or ""),

        "cvss": cvss_score,
        "cvss_version": cvss_version,

        "title": title,

        "fixed_version": str(
            fixed_version or ""
        ),

        "raw": dict(risk),
    }


# ============================================================
# Filtering
# ============================================================

def is_vulnerability(
    item: Mapping[str, Any],
) -> bool:

    risk_type = str(
        item.get("type") or ""
    ).upper()

    # Sonar 中漏洞类型通常是 VULNERABILITY
    if risk_type == "VULNERABILITY":
        return True

    # 某些版本接口 type 可能为空，
    # 此时只要存在 CVE 或 CVSS 也认为是漏洞。
    if item.get("cve"):
        return True

    if item.get("cvss") is not None:
        return True

    return False


def filter_risks(
    items: List[Dict[str, Any]],
    min_cvss: float,
    include_resolved: bool,
) -> List[Dict[str, Any]]:

    result: List[Dict[str, Any]] = []

    for item in items:

        if not is_vulnerability(item):
            continue

        cvss = item.get("cvss")

        # 这里严格按照你的要求：
        # CVSS >= 3
        if cvss is None:
            continue

        if float(cvss) < min_cvss:
            continue

        if not include_resolved:

            status = str(
                item.get("status") or ""
            ).upper()

            if status in (
                "SAFE",
                "ACCEPTED",
                "FIXED",
                "RESOLVED",
                "CLOSED",
            ):
                continue

        result.append(item)

    result.sort(
        key=lambda x: (
            -(x.get("cvss") or 0),
            x.get("project_name") or "",
            x.get("package") or "",
            x.get("cve") or "",
        )
    )

    return result


# ============================================================
# Output
# ============================================================

def render_markdown(
    items: List[Dict[str, Any]],
    min_cvss: float,
) -> str:

    lines: List[str] = []

    lines.append(
        "# SonarQube 依赖漏洞 CVSS 报告"
    )

    lines.append("")

    lines.append(
        f"- CVSS 筛选条件：`>= {min_cvss:g}`"
    )

    lines.append(
        f"- 命中数量：`{len(items)}`"
    )

    lines.append("")

    if not items:

        lines.append(
            "当前没有发现符合条件的依赖漏洞。"
        )

        lines.append("")

        return "\n".join(lines)

    lines.append(
        "| 项目 | 依赖 | 当前版本 | CVE | CVSS | 严重性 | 状态 | 建议版本 | 描述 |"
    )

    lines.append(
        "|---|---|---|---|---:|---|---|---|---|"
    )

    for item in items:

        def cell(value: Any) -> str:
            return (
                str(value or "")
                .replace("|", "\\|")
                .replace("\n", " ")
            )

        lines.append(
            "| "
            + " | ".join(
                [
                    cell(
                        item.get("project_name")
                        or item.get("project_key")
                    ),
                    cell(item.get("package")),
                    cell(item.get("version")),
                    cell(item.get("cve")),
                    cell(item.get("cvss")),
                    cell(item.get("severity")),
                    cell(item.get("status")),
                    cell(
                        item.get("fixed_version")
                    ),
                    cell(item.get("title")),
                ]
            )
            + " |"
        )

    lines.append("")

    lines.append(
        "## 明细"
    )

    lines.append("")

    for index, item in enumerate(
        items,
        start=1,
    ):

        lines.append(
            f"### {index}. "
            f"{item.get('package') or '未知依赖'}"
            f" {item.get('version') or ''}"
        )

        lines.append("")

        lines.append(
            f"- 项目："
            f"`{item.get('project_name') or item.get('project_key')}`"
        )

        lines.append(
            f"- CVE："
            f"`{item.get('cve') or '-'} `"
        )

        lines.append(
            f"- CVSS："
            f"`{item.get('cvss')}`"
        )

        if item.get("cvss_version"):

            lines.append(
                f"- CVSS 版本："
                f"`{item.get('cvss_version')}`"
            )

        lines.append(
            f"- 严重性："
            f"`{item.get('severity') or '-'} `"
        )

        lines.append(
            f"- 状态："
            f"`{item.get('status') or '-'} `"
        )

        if item.get("cwe"):

            lines.append(
                f"- CWE："
                f"`{item.get('cwe')}`"
            )

        if item.get("fixed_version"):

            lines.append(
                f"- 建议升级版本："
                f"`{item.get('fixed_version')}`"
            )

        if item.get("title"):

            lines.append(
                f"- 问题：{item.get('title')}"
            )

        lines.append("")

    return "\n".join(lines)


def render_csv(
    items: List[Dict[str, Any]],
) -> str:

    output = StringIO()

    fields = [
        "project_key",
        "project_name",
        "package",
        "version",
        "cve",
        "cwe",
        "cvss",
        "cvss_version",
        "severity",
        "status",
        "fixed_version",
        "title",
        "risk_id",
    ]

    writer = csv.DictWriter(
        output,
        fieldnames=fields,
    )

    writer.writeheader()

    for item in items:

        writer.writerow(
            {
                key: item.get(key, "")
                for key in fields
            }
        )

    return output.getvalue()


def render_json(
    items: List[Dict[str, Any]],
) -> str:

    data = []

    for item in items:

        copied = dict(item)

        # 默认 JSON 也不输出完整原始响应，
        # 避免文件太大。
        copied.pop(
            "raw",
            None,
        )

        data.append(copied)

    return json.dumps(
        data,
        ensure_ascii=False,
        indent=2,
    )


# ============================================================
# CLI
# ============================================================

def parse_args() -> argparse.Namespace:

    parser = argparse.ArgumentParser(
        description=(
            "获取 SonarQube Dependency Risks，"
            "筛选 CVSS 达到指定阈值的依赖漏洞"
        )
    )

    parser.add_argument(
        "--url",
        default=os.getenv("SONAR_URL"),
        help="SonarQube 地址，默认读取 SONAR_URL",
    )

    parser.add_argument(
        "--token",
        default=os.getenv("SONAR_TOKEN"),
        help="SonarQube Token，默认读取 SONAR_TOKEN",
    )

    parser.add_argument(
        "--project-key",
        default=os.getenv(
            "SONAR_PROJECT_KEY"
        ),
        help=(
            "SonarQube 项目 Key；"
            "不指定则扫描当前 Token 可见项目"
        ),
    )

    parser.add_argument(
        "--organization",
        default=os.getenv(
            "SONAR_ORGANIZATION"
        ),
    )

    parser.add_argument(
        "--branch",
        default=None,
    )

    parser.add_argument(
        "--pull-request",
        default=None,
    )

    parser.add_argument(
        "--min-cvss",
        type=float,
        default=3.0,
        help="最低 CVSS，默认 3.0",
    )

    parser.add_argument(
        "--include-resolved",
        action="store_true",
        help=(
            "包含 SAFE / ACCEPTED / "
            "FIXED 等已处理风险"
        ),
    )

    parser.add_argument(
        "--format",
        choices=(
            "markdown",
            "json",
            "csv",
        ),
        default="markdown",
    )

    parser.add_argument(
        "--output",
        default=None,
    )

    parser.add_argument(
        "--page-size",
        type=int,
        default=100,
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=30,
    )

    parser.add_argument(
        "--insecure",
        action="store_true",
        help="忽略 HTTPS 证书校验",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
    )

    return parser.parse_args()


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

        if args.project_key:

            projects = [
                {
                    "key": args.project_key,
                    "name": args.project_key,
                }
            ]

        else:

            print(
                "正在获取当前账号可见项目...",
                file=sys.stderr,
            )

            projects = list_projects(
                client,
                args.organization,
                args.page_size,
            )

        print(
            f"共发现 {len(projects)} 个项目",
            file=sys.stderr,
        )

        all_items: List[Dict[str, Any]] = []

        for index, project in enumerate(
            projects,
            start=1,
        ):

            project_key = project["key"]
            project_name = project["name"]

            print(
                f"[{index}/{len(projects)}] "
                f"扫描 {project_name} "
                f"({project_key})",
                file=sys.stderr,
            )

            try:

                raw_risks = fetch_dependency_risks(
                    client=client,
                    project_key=project_key,
                    branch=args.branch,
                    pull_request=args.pull_request,
                    page_size=args.page_size,
                )

            except SonarApiError as exc:

                print(
                    f"  获取依赖风险失败: {exc}",
                    file=sys.stderr,
                )

                # 单项目模式直接报错退出，
                # 全项目模式跳过该项目。
                if args.project_key:
                    raise

                continue

            for raw in raw_risks:

                all_items.append(
                    normalize_risk(
                        project_key,
                        project_name,
                        raw,
                    )
                )

        filtered = filter_risks(
            all_items,
            min_cvss=args.min_cvss,
            include_resolved=args.include_resolved,
        )

        if args.format == "json":

            content = render_json(
                filtered
            )

        elif args.format == "csv":

            content = render_csv(
                filtered
            )

        else:

            content = render_markdown(
                filtered,
                args.min_cvss,
            )

        output = args.output

        if not output:

            extension = {
                "markdown": "md",
                "json": "json",
                "csv": "csv",
            }[args.format]

            output = (
                f"sonar-dependency-cvss."
                f"{extension}"
            )

        with open(
            output,
            "w",
            encoding="utf-8",
            newline="",
        ) as fp:
            fp.write(content)

        print(
            "",
            file=sys.stderr,
        )

        print(
            f"依赖风险总数：{len(all_items)}",
            file=sys.stderr,
        )

        print(
            f"CVSS >= {args.min_cvss:g} "
            f"且需要处理：{len(filtered)}",
            file=sys.stderr,
        )

        print(
            f"报告已生成：{output}",
            file=sys.stderr,
        )

        return 0

    except SonarApiError as exc:

        print(
            f"错误：{exc}",
            file=sys.stderr,
        )

        return 1


if __name__ == "__main__":
    raise SystemExit(main())