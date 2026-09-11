# TYUT 校园网保活

太原理工 eportal/Dr.COM 登录保持脚本：定时检测认证状态，掉线自动重登。
纯 Python + `requests`，无其他依赖。

实现分两层：`drcom.py` 认证协议（状态查询 / 登录端点级联 / 应答判定），
`tyut_login.py` 保活循环与日志；更换认证方式只动 `drcom.py`。

## 依赖

- Python 3
- `requests`

## 用法

```bash
# 常驻（推荐）：日志落同目录 logs.txt（已 gitignore）
./run.sh

# 后台常驻（断开终端/注销后仍存活）
setsid nohup ./run.sh </dev/null &

# 只跑一轮（手动测试；在线退 0，重登失败退 1）
python3 tyut_login.py --once

# 调试：流水日志 + 打印服务端原始应答
python3 tyut_login.py --once -v --dump
```

常用选项：

| 选项 | 说明 |
|---|---|
| `--interval N` | 活跃/刚恢复时的检查间隔（秒，默认 60） |
| `--steady N` | 长时间稳定后的检查间隔（秒，默认 300） |
| `--campus-prefix P` | 校网段门闸（逗号分隔 CIDR，默认 `101.7.0.0/16`）：客户端 IP 不在其中就不登录 |
| `--retry-base N` / `--retry-max N` | 掉线重试退避的起始/上限秒数（默认 10 / 60） |
| `--no-probe` | 关闭连通性探测（portal 说在线 ≠ 真能上网，探测用于识别僵死会话） |
| `--dry-run` | 掉线时只打印本应发送的登录请求，不真登录（零风险自检） |
| `--ip X.X.X.X` | 手动指定客户端 IP（调试用；给定时绕过校网段门闸） |

## 行为要点

- **动作收窄**：只有 portal 可达、客户端 IP 在校网段、且未登录时才发起登录；
  其余情况（校外、断网等）只做慢速观察，不会误登录。
- **在线判定**：`result=1` 且连通性探测（204）通过才算在线；重登后同样复核。
- **节奏**：连续稳定 5 轮后转入慢查（默认 300s）；异常或刚恢复时快查（默认 60s）；
  查询/重登失败按 10→60s 退避。

## 日志

日志去向由启动方式决定（脚本只写 stdout）：

- `./run.sh` → 同目录 `logs.txt`（已 gitignore，方便整体清理）
- 默认只写**事件**（掉线 / 重登 / 门闸切换）与**每小时汇总**；
  `-v` 加回每分钟流水；`--dump` 打印服务端原始应答。

## 凭证

优先配置文件（脚本同目录 `.env`，建议 `chmod 600`）：

```ini
TYUT_USER=2023xxxxxx
TYUT_PASS=密码
```

命令行 `--user/--password` 与环境变量 `TYUT_USER`/`TYUT_PASS` 仍可用，
优先级：命令行 > 环境变量 > 脚本同目录 `.env`。

模板见 `.env.example`，复制为 `.env` 后填入。

## 登录端点

按序尝试，得到明确应答的端点自动提到最前：

1. `https://drcom.tyut.edu.cn:804/eportal/portal/login`（XOR 加密参数）
2. `http://drcom.tyut.edu.cn:803/eportal/portal/login`（同上）
3. `https://drcom.tyut.edu.cn/drcom/login`（旧 CGI，明文参数）

服务端返回「Portal协议认证超时！」一类临时故障时不算业务拒绝：继续换下一个
端点，全部失败则按退避间隔在下一轮重试。密码错误等业务拒绝在首个端点即停，
避免对同一账号连打触发风控。
