# TYUT 校园网保活

太原理工 eportal/Dr.COM 登录保持脚本：定时检测认证状态，掉线自动重登。
纯 Python + `requests`，无其他依赖。

## 依赖

- Python 3
- `requests`

## 用法

```bash
# 常驻：在线时每 60s 查一次，掉线自动重登
python3 tyut_login.py

# 只跑一轮（手动测试；在线退 0，重登失败退 1）
python3 tyut_login.py --once

# 调试：输出明细 + 打印服务端原始应答
python3 tyut_login.py --once -v --dump
```

常用选项：

| 选项 | 说明 |
|---|---|
| `--interval N` | 在线时检查间隔秒数（默认 60） |
| `--retry-base N` / `--retry-max N` | 掉线重试退避的起始/上限秒数（默认 10 / 60） |
| `--no-probe` | 关闭连通性探测（portal 说在线 ≠ 真能上网，探测用于识别僵死会话） |
| `--dry-run` | 掉线时只打印本应发送的登录请求，不真登录（零风险自检） |
| `--ip X.X.X.X` | 手动指定客户端 IP（调试用） |

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
