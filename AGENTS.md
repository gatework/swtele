# swtele 开发说明

遵循 [gatework Go 工程规范（go-standards/STANDARD.md）](https://github.com/gatework/go-standards/blob/v1.2.0/STANDARD.md)；提交前运行 `make check`。

本模块面向网络运维管理，做两件事：

1. 把异构多厂商设备的运行态回显（以及配置）解析为厂商无关的设备对象模型，按采集批次组成全网台账。
2. 在台账上提供运维功能：IP/MAC 定位、LLDP/CDP 拓扑、光模块质量、错包增长、抖动、设备健康，以及 IRF、聚合、STP、路由邻居的风险发现。

设计见 [docs/design.md](docs/design.md)，决策见 [docs/adr](docs/adr)，术语见 [GLOSSARY.md](GLOSSARY.md)。

成熟度：v0，未投产，不承诺兼容（GEN-1）。

## 边界

- 共享机制来自 [netops](../netops-next)。本模块不重新实现这些机制，通用缺口应补到 netops。用到的包：
  - 文本解析 `parse`、证据与覆盖度 `evidence`、回显与快照 `capture`、`store/snapshot`
  - 接口名归一 `iface`、LLDP 计数核对 `neighbor`、VLAN 集合 `set`
  - 规则引擎 `assess`、报表 `report`、存储 `store`、启动 `bootstrap`、终端 `term`
- 根包 `swtele` 是纯模型，不做 I/O。以 `Device` 为聚合根，由 System、Stack、Interfaces、Aggregates、Bridging、Routing、Neighbors 组合而成。可缺失的值用 `Opt[T]`。
- `vendors/<厂商>` 只负责一种 CLI 语法 → 模型。每条命令一个解码函数，按 `clidoc.Step` 声明它喂给哪些维度。厂商之间互不依赖。`vendors/registry.go` 按平台别名分派，未知平台按回显命令识别。
- `vendors/internal/clidoc` 是回显的共同前置：剥离回显与提示符，按正文识别 CLI 拒绝（不信 sidecar 的 success），统计未消费的行，并统一解析空值、速率、时长与时间。
- `ledger` 建全网索引（地址、名称、MAC、ARP、MAC 表）。`topology` 由 LLDP/CDP 推出链路与端口角色。`locate` 做终端定位。`check` 是 assess 规则目录。这四个包只读模型。
- 端口与适配器：
  - `internal/workflow` 只用注入的端口：`Source`、`Decoder`、`Ledgers`、`Inventory`。
  - `adapter/snapshot` 读快照目录，`adapter/store` 按批次存 JSON。
  - `internal/bootstrap` 负责组装，`internal/cli` 是中文命令行。

`architecture.yaml` 声明并由 `make check` 强制以上依赖方向。

## 语义约定

- **维度覆盖**
  - 每条命令把解析状态记到它喂给的维度上：complete、partial（有未识别行或计数核对不一致）、failed（设备拒绝或采集失败），未采集为 not_requested。
  - 规则用 `Meta.Requires` 声明所需维度，维度不完整时引擎跳过该规则，不误报。
- **字段来源优先级**
  - 运行态优先。多源字段按可信度取值：`display interface`、`show interface` 优先于 brief 和 counters 表，后者只补缺。
  - brief 中截断的描述不覆盖完整描述。
- **单位**：功率 dBm，温度 °C，速率 bit/s（Comware 的 bytes/sec 乘以 8），内存字节，时间 UTC。设备未带时区的时间按配置的时区解释，默认 UTC+8。
- **定位**
  - 学到该 MAC 的端口中，对端是受管设备的算经过口。即使对端已老化该表项，终端也在更远处。
  - 接入口（edge）与面向非受管邻居（AP、桌面交换机）的端口是末端口。
- **无 DOM 的光模块**：全零读数（0°C、0V、0mA、-40dBm）视为不支持诊断，不当作无光。

## 安全

- Issue 只记录代码与行号，不含设备文本。
- `clidoc.Doc.Unparsed` 只供语料诊断使用，不进入日志或报告。

## 测试

- 单元测试只用合成样例（RFC 5737 地址）。真实语料不进仓库（TST-3）。
- 私有语料：`make corpus SWTELE_CORPUS=~/Documents/Snapshots/devices`。会检查六个厂商的每条命令都完整解析、无未识别行，并跑一遍拓扑与定位；只输出聚合计数。用 `SWTELE_VENDOR=<名称>` 可单独查看某个二期厂商。
- 用 CLI 做验证时，一律使用临时的 HOME（例如 scratchpad 下的目录）。HOME 为空时程序会拒绝运行。
- 模糊测试：`make fuzz`。
- 在线采集（collect/watch）已用假 Dialer 测通，但未经实机验证。新增的采集命令须实机验证后才能进入默认采集清单（`vendors/profile.go`）。
