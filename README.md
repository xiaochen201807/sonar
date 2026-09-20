# SonarQube 问题整理脚本

`sonar_issue_report.py` 通过 SonarQube 的 `api/issues/search` 接口整理：

- 安全性（Security）为中危及以上：Medium / High / Blocker
- 可靠性（Reliability）为高危及以上：High / Blocker

脚本会输出问题规则、描述、状态、文件路径、起止行列、匹配条件以及 SonarQube 页面链接，并自动分页和去重。

## 使用

推荐通过环境变量提供连接信息：

```bash
export SONAR_URL="http://XXXXXXXXXX:9000/"
export SONAR_TOKEN="XXXXXXXXXXX"

set "SONAR_URL=http://XXXXXXXXXX:9000/"
set "SONAR_TOKEN=XXXXXXXXXXX"

python3 sonar_issue_report.py --output sonar-issues.md
```

不设置 `SONAR_PROJECT_KEY` 时，脚本会先枚举当前 Token 可浏览的全部项目，再逐个整理问题。如果只想处理一个项目，可以额外设置：

```bash
export SONAR_PROJECT_KEY="your-project-key"
python3 sonar_issue_report.py --output one-project.md
```

也可以输出 JSON 或 CSV：

```bash
python3 sonar_issue_report.py --format json --output sonar-issues.json
python3 sonar_issue_report.py --format csv --output sonar-issues.csv
```

常用选项：

```bash
# 默认只看未解决问题；下面的参数可以显式写出该行为
python3 sonar_issue_report.py --unresolved-only --output open-issues.md

# 如果需要包含 FIXED、ACCEPTED、FALSE_POSITIVE 等状态
python3 sonar_issue_report.py --include-resolved --output all-issues.md

# 只看指定分支的新代码
python3 sonar_issue_report.py --branch develop --new-code --output new-code.md

# 旧版 SonarQube 或自动识别失败时，显式使用传统 API
python3 sonar_issue_report.py --mode standard --output sonar-issues.md
```

`--mode auto` 默认优先使用 SonarQube 10.2+ 的 MQR 参数；如果服务端不支持，会回退到传统模式。传统模式的等价映射是：安全性使用 `VULNERABILITY` 的 `MAJOR/CRITICAL/BLOCKER`，可靠性使用 `BUG` 的 `CRITICAL/BLOCKER`。

需要的 SonarQube 权限是目标项目的 `Browse`。如果使用 SonarQube Cloud，还需要提供组织 key：

```bash
set SONAR_ORGANIZATION=your-organization-key
```

脚本只使用 Python 标准库，不需要安装第三方依赖。
