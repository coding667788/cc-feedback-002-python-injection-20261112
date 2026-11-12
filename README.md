# 离线跨模块 Python 注入漏洞扫描器

一个只用 Python 3.12 标准库（`ast` + `sqlite3`）实现的离线静态污点分析器。
它只解析源码文本，**不导入、不执行**被扫描项目，也不依赖任何现成扫描引擎或
大模型接口。

## 1. 能力范围

### 污点来源与传播
- 以 FastAPI 风格路由函数（`@get/@post/...` 装饰器，按装饰器名字匹配）的
  参数作为污点来源，每个参数是独立 source。
- 支持至少三层直接函数调用（样例 `deep_chain_route` 实际为四帧：
  route → `three_layer_entry` → `stage_one` → `stage_two` → `stage_three`）。
- 支持绝对导入、相对导入（`from . import` / `from .. import`）与
  `import ... as ...`、`from ... import ... as ...` 别名。
- 简单 `if` 分支按路径分叉解释，互斥分支各自独立走到底，不会拼成一条路径。
- 字段敏感：固定对象属性（`obj.field`）与常量键字典（`payload["name"]`）的
  污点带字段路径，一个字段的污点不会扩散到其它字段。
- 上下文敏感：同一被调函数的安全调用与受污染调用分别实例化，互不污染。

### 漏洞规则
- SQL 注入：`sqlite3` 风格的 `execute/executemany/executescript` 查询字符串
  拼接（`+`、`%`、f-string）。固定 SQL + 绑定参数（`execute("... ?", (x,))`）
  因字符串本身无污点而不报警。
- 命令注入：`subprocess.run/call/Popen/...` 且 `shell=True`，以及
  `os.system/os.popen` 的命令字符串拼接。固定原生程序 + `shell=False`
  参数列表不报警。
- 净化语义：`int(x)` 成功后再 `str(...)` 得到的十进制字符串标记为
  `safe_int`，视为干净；`try/except` 的异常分支若继续使用原字符串，仍按
  未净化污点报警。

### 报告
- JSON 报告包含 source、危险参数、文件、行号、sink、源码片段、符号污点项和
  完整传播路径（调用证据 + 分支证据）。
- 超出支持范围的构造（循环、lambda、推导式、非常量下标、未解析调用、
  `**kwargs` 等）写入 `unsupported` 数组，明确报告而不是当成零漏洞。

### 缓存
- SQLite 持久化缓存（`scan_cache.sqlite3`），含 `file_facts` 与 `summaries`
  两张表。
- 函数摘要的 `basis` = 自身源码哈希 + 所有被调方 `basis` 的哈希，因此修改
  公共函数后，其传递依赖的调用者自动失效重算，无关模块继续复用。
- 删除文件/函数会清除对应陈旧摘要。
- 所有缓存写入在单事务内提交，借助 SQLite 回滚日志，写入中断（进程被杀）
  后重启仍得到与干净全量扫描一致的结果。

## 2. 目录结构

```
taint_scanner/
  models.py        # Term / Finding / FlowStep / UnsupportedItem 数据结构
  modulegraph.py   # 项目发现、ast 解析、绝对/相对导入与别名解析
  analysis.py      # 符号解释器、过程间上下文/字段/分支敏感引擎
  cache.py         # SQLite 持久化缓存与序列化
  scanner.py       # 扫描编排、增量失效、故障注入点
  report.py        # JSON 报告
  cli.py           # 命令行
samples/           # 自建正反例 FastAPI 风格工程（仅被解析，不执行）
tests/             # unittest 自动化测试（17 个用例）
```

## 3. Windows 运行说明（原生 Python 3.12，无 Docker）

在项目根目录打开 PowerShell，确认 `python --version` 为 3.12.x。

扫描并输出 JSON 报告：

```powershell
python -m taint_scanner scan samples -o report.json
```

常用参数：

```powershell
# 指定缓存目录（默认在被扫描目录下的 .taint_cache）
python -m taint_scanner scan samples --cache-dir .demo_cache -o report.json

# 忽略缓存，干净全量重算
python -m taint_scanner scan samples --no-cache -o report.json

# 清空缓存后再扫描
python -m taint_scanner scan samples --clear-cache -o report.json
```

运行自动化测试：

```powershell
python -m unittest discover -s tests -t . -v
```

## 4. 样例工程说明（samples/）

| 路由 | 预期 |
| --- | --- |
| `unsafe_sql_route` | SQL 拼接，报警 |
| `safe_sql_route` | 固定 SQL + 绑定参数，不报警 |
| `safe_integer_route` | `int()` 成功后 `str()`，不报警 |
| `failover_integer_route` | `except` 分支用原字符串，报警 |
| `field_isolation_route` | 仅 `payload["name"]` 报警，`code` 字段不扩散 |
| `object_field_route` | 仅 `account.account_id` 报警，`display_name` 不扩散 |
| `command_unsafe_route` | `shell=True` 拼接，报警 |
| `command_safe_route` | `shell=False` 参数列表，不报警 |
| `branch_route` | 仅 `if` 取真分支报警，互斥 else 不拼接 |
| `deep_chain_route` | 四帧跨模块命令注入，附完整调用链 |
| `alias_route` | 相对导入 + 模块别名的 SQL 注入 |
| `same_helper_mixed_route` | 同一助手安全/受污染调用分开 |
| `dynamic_dispatch_route` | 含循环，记入 unsupported |

## 5. 实测结果（本机 Windows + Python 3.12.8）

干净全量扫描：

```json
{ "route_count": 13, "finding_count": 9, "unsupported_count": 2,
  "reused_summaries": 0, "recomputed_summaries": 34, "cache_hit_files": 8 }
```

紧接着第二次扫描（命中缓存）：

```json
{ "route_count": 13, "finding_count": 9, "unsupported_count": 2,
  "reused_summaries": 34, "recomputed_summaries": 0, "cache_hit_files": 8 }
```

两次报告的 finding（含完整 flow 细节与 taint_terms）和 unsupported 完全一致
（由 `tests/test_cache.py` 断言）。

自动化测试：`Ran 17 tests ... OK`，覆盖跨模块传播、三层以上调用、字典/对象
字段隔离、互斥分支、净化成功/失败分支、缓存复用、公共函数修改失效、函数
删除、以及三个故障注入点（`after_file_facts` / `after_summaries` /
`before_commit`）下杀进程后的中断恢复。

异常分支 finding 的证据示例：

```json
{
  "kind": "sql_injection",
  "source": "app.main::failover_integer_route",
  "file": "app/database.py", "lineno": 37,
  "function": "load_by_identifier_failover",
  "flow": [
    { "kind": "call", "file": "app/main.py", "lineno": 51,
      "detail": "call app.database::load_by_identifier_failover(...identifier)" },
    { "kind": "branch", "file": "app/database.py", "lineno": 32,
      "detail": "try block raised an exception; handler entered" }
  ]
}
```

## 6. 未完成项与已知限制

- 循环（`for/while`）只分析一次且不迭代，循环体内依赖迭代值的污点可能不
  完整，会显式记入 `unsupported`。
- 不建模 lambda、列表/字典/集合推导式、生成器、非常量下标、切片、
  `**kwargs` 展开、`nonlocal`、动态/间接调用（如把函数对象赋给变量再调用），
  遇到即记入 `unsupported`。
- 不做常量条件判定，`if` 的两个分支都视为可行；不会做路径条件冲突求解。
- 类的继承、多态分派、`self` 方法的虚分派未完整建模；当前支持固定类的
  构造与 `self` 字段写入。
- 仅识别 sqlite3 风格 SQL sink 与 `os`/`subprocess` 命令 sink；其它 ORM、
  `eval/exec/pickle` 等未纳入规则。
- 分支总数超过 `MAX_PATHS=64` 或调用深度超过 `MAX_CALL_DEPTH=20` 时降级并
  报告 unsupported，避免路径爆炸。
- 缓存按文件哈希与内容 basis 失效；未实现基于时间戳的快速跳过（当前哈希
  已足够保证正确性）。
