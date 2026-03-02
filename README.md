# 远程SSH执行器(astrbot_plugin_ssh)

一个功能弱小的 AstrBot 插件，允许您通过聊天窗口连接远程 SSH 服务器并执行命令。支持交互式 Shell 会话、状态保持、LLM 函数调用，并具备不完善的安全保护机制。

## 风险提示

本插件可直接在远程服务器执行命令，存在高风险。请仅在可信环境使用，并自行承担误操作、数据损坏、服务中断等风险。

## 功能特性

- 交互式 Shell 会话，支持 `cd` 等上下文命令并保持状态
- 支持密码登录与私钥登录（私钥优先）
- 命令输出支持自动转图片返回
- 自动会话管理，闲置超时自动断开
- 支持 `/ssh log` 查看最近执行记录、`/ssh out` 主动断开
- 支持 LLM 工具调用（`ssh_exec`）

## 安全机制

- 仅管理员可用
- SSH 主机密钥校验默认启用
  - 首次连接（TOFU）自动获取并写入 `known_hosts`
  - 后续连接严格校验，密钥变化会拒绝连接
- 命令安全检查采用三层策略
  - 黑名单命令：直接拦截
  - 白名单命令：直接执行
  - 非白名单命令：需 `/ssh yes` 二次确认（30 秒内）
- LLM 工具默认仅执行白名单命令
- 可开启 `enable_dangerous_commands=true` 一键关闭命令保护（白名单/黑名单/二次确认全部失效）
- 输出保护
  - 单命令最大输出字节数默认 32KB
  - 单命令最大执行等待默认 30 秒
  - 超限后截断并提示
- 日志与历史脱敏
  - 命令与输出按正则脱敏（token/secret/key/private key/base64/db uri 等）
  - 可配置关闭历史记录
- 用户侧错误提示最小化
  - 连接失败仅返回通用错误
  - 详细错误仅写入日志

## 安装

将本插件目录 `astrbot_plugin_ssh` 放到 AstrBot 的 `data/plugins/` 目录。

或在插件安装中使用仓库地址：

```text
https://github.com/HSOS6/astrbot_plugin_ssh
```

## 配置说明

在 AstrBot 管理面板中配置以下项：

| 配置项 | 说明 | 默认值 |
| :--- | :--- | :--- |
| `host` | SSH 主机地址 | `192.168.1.128` |
| `port` | SSH 端口 | `22` |
| `username` | SSH 用户名 | `root` |
| `password` | SSH 密码（可为空） | `123456` |
| `private_key` | SSH 私钥内容（PEM，填写后优先使用） | `""` |
| `timeout` | SSH 连接超时（秒） | `10` |
| `idle_timeout` | 会话闲置断开时间（分钟） | `30` |
| `log_size` | `/ssh log` 展示条数 | `5` |
| `enable_history` | 是否记录命令历史 | `true` |
| `enable_dangerous_commands` | 是否关闭命令安全保护 | `false` |
| `command_whitelist` | 自定义命令白名单（留空使用内置） | `[]` |
| `max_output_bytes` | 单命令最大输出字节数 | `32768` |
| `max_exec_time` | 单命令最大执行等待（秒） | `30` |
| `known_hosts_path` | known_hosts 文件路径（留空使用插件目录） | `""` |

## 指令用法

以下命令仅管理员可用：

- `/ssh <命令>` 执行命令
- `/ssh log` 查看最近执行记录
- `/ssh out` 断开当前 SSH 会话
- `/ssh yes` 对待确认命令进行确认执行
- `/ssh no` 取消待确认命令

## LLM 调用

插件注册了 `ssh_exec` 工具，可让模型执行白名单内运维命令。

示例：

- “查看一下服务器 CPU 和内存情况”
- “列出 /var/log 目录下最新文件”

## 常见问题

### 出现 `Host key is not trusted`

表示服务器当前主机密钥与 `known_hosts` 中记录不一致，常见于重装系统或更换主机。

处理方式：删除 `known_hosts` 中该主机对应行，重新连接让插件重新完成 TOFU。

## 更新日志

### v1.4.0

- 增加主机密钥 TOFU + 严格校验机制
- 命令安全升级为黑名单 + 白名单 + 二次确认
- 增加输出总量/执行时长限制，防止可用性风险
- 增加日志与历史系统化脱敏
- 增加 `enable_history`、`command_whitelist`、`max_output_bytes`、`max_exec_time`
- 连接失败对用户返回通用错误，详细异常仅写日志

### v1.3.1

- 增加私钥登录支持

### v1.3.0
- 修改了一些bug，增加了一些问题
### v1.2.0

- 常规修复与优化

### v1.1.Beta

- 支持 `ssh log` 查看执行记录

### v1.0.Beta
- 初始版本发布。
- 支持交互式 Shell、LLM 调用。
- 初始版本发布
