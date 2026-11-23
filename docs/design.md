# swtele 设计

## 目标

为网络运维提供一个确定的基本面：

- 每台设备有哪些端口，它们的状态、速率、VLAN、地址；
- 设备之间如何互联；
- 一个 IP 落在哪个接入口；
- 光模块是否健康；
- 哪些口的错包在增长；
- CPU、内存、温度、IRF、MAD、聚合、STP、路由邻居是否正常。

借鉴的商用产品：

- IP Fabric / Forward：快照台账与意图校验。
- SolarWinds UDT / Netdisco：终端定位。
- Catalyst Center / U-Center：Device 360 与光模块健康。
- NetBrain：拓扑与链路两端一致性。

## 数据流

```
快照目录 (<ip>/NN-<cmd>.output + .json)      ← netops store/snapshot 布局
    │  adapter/snapshot
    ▼
capture.Capture ──vendors.Decode──▶ swtele.Device（每台一份，带维度覆盖度）
                                         │ adapter/store（JSON 批次）
                                         ▼
                                   ledger.Ledger（全网索引）
                     ┌───────────────┼──────────────────┐
                topology.Build   locate.Locator     check.Catalog（netops assess）
                     │                 │                  │
                     └──────────── internal/cli（中文）────┘
```

## 设备对象模型（根包）

| 对象 | 内容 |
|---|---|
| `Device` | 身份（netops `device.Device`）、观测时间、维度覆盖度、Issues |
| `System` | 型号、版本、运行时长、CPU（按 机框/槽位/CPU）、内存、传感器、风扇、电源 |
| `Stack` | IRF/vPC/HA：成员（角色、优先级、MAC）、IRF 物理链路、MAD（模式、状态、成员） |
| `Interface` | 名称、类型、管理/运行/协议状态、down 原因、速率、双工、MTU、MAC、介质；二层（模式、PVID、允许 VLAN）、地址、VRF、所属聚合；计数（双向包/字节/单播/组播/广播/pause/错误/丢弃，CRC/runts/giants 等）、设备自报速率、抖动时间；光模块 |
| `Transceiver` | 在位、库存（厂商/PN/SN/类型）、DOM 支持、温度、电压，每通道偏置/收光/发光；每个读数带告警/预警阈值，`Level()`、`Margin()` |
| `Aggregate` | 模式（静态/LACP）、系统 ID、成员（选中、状态码、参考口、LACP 本端/对端标志） |
| `Bridging` | VLAN、MAC 表（动态/静态/认证/远端 VTEP/系统）、STP（down-port 原因等） |
| `Routing` | ARP（IP/MAC/VLAN/接口/VRF/老化）、路由邻居（OSPF/BGP，状态、时长、前缀数）、路由 |
| `Neighbor` | LLDP/CDP：本端口、系统名、对端口、机箱 MAC、管理地址、平台、能力、PVID |

可缺失的值都是 `Opt[T]`，"0" 与 "未上报" 不混淆。

## 厂商解码

- 每条命令对应一个 `clidoc.Step{Command, Dims, Decode}`。
- `clidoc.Run` 依次执行各步骤并登记覆盖度。
- 解码函数标记它理解的每一行；未标记的行变成 netops `parse` 的 `unparsed_line` Issue，所在维度随之降为 partial。在 830 台语料上，H3C（716 台）和 NX-OS（83 台）的每条命令都达到 0 未识别行。

## 定位算法

1. **IP → MAC**：查全网 ARP。多台网关一致时取多数；多个不同 MAC 解析到同一 IP 时提示 IP 冲突。
2. **MAC → 端口**：查全网 MAC 表，去重同一端口在不同 VLAN 的表项。
3. **分类**：
   - 对端是受管设备的口（LLDP/CDP 解析到台账设备，聚合按成员判断）、IRF/隧道口、down 口都是经过口。
   - edge 口和面向非受管邻居（AP、IP 电话、桌面交换机）的口是末端口。
4. **结论**：
   - 1 个 edge 末端口为精确；若该口学到多个 MAC，标记为共享接入口。
   - 仅有非受管邻居口时，结论为"位于某某之后"。
   - 多个 edge 末端口为不唯一（漂移、环路或重复 MAC）。
   - 只在互联口上学到时为仅网关可见。
5. VRRP/HSRP 虚拟 MAC 与设备自身 MAC 单独提示。

## 拓扑

- 远端设备按机箱 MAC（设备的桥 MAC 与各接口 MAC）、系统名（去域名）、管理地址解析，但不信任 169.254/16。
- 两端互见为 confirmed，单端可见为 one_way，远端不在台账为 unmanaged。
- 一个端口看到多个邻居为 shared：中间有转发 LLDP 的非网管交换机，这种链路不参与两端一致性检查。

## 风险目录（check）

| 规则 | 依据 |
|---|---|
| （共同前提） | 光模块类规则只评估接口 up 的物理口：down 口不收不发，读数不反映链路质量 |
| `optics.rx_power` | up 口收光越过模块阈值或无光，区分偏低和偏高（过载） |
| `optics.module` | 温度、电压、偏置、发光越限 |
| `optics.rx_margin` | 收光距下限不足 `margin_db` |
| `optics.lane_imbalance` | 多通道收光差超过 `spread_db` |
| `optics.link_loss` | 对端发光减本端收光超出预算：多模 3 dB，单模 10 dB |
| `optics.swapped` | 与上批次相比模块序列号变化 |
| `counters.error_growth` | 与上批次相比 CRC、错误、giants、runts 增长，计数回退视为清零，不计 |
| `counters.error_history`、`counters.discard_growth`、`capacity.utilization` | 历史累计错包、出向丢包增长、利用率 |
| `flap.recent` | 互联口近期 up/down，默认不含接入口 |
| `flap.logged`、`flap.resets` | 日志中反复 up/down、接口复位次数增长 |
| `health.cpu`、`health.memory`、`health.temperature`、`health.fan_power` | 设备运行状态 |
| `stack.mad_disabled`、`stack.mad_status`、`stack.link`、`stack.member_lost` | 多成员未开 MAD、MAD 异常、IRF 链路 down 或单链路、成员减少 |
| `lag.member_unselected`、`lag.lacp_state`、`lag.single_member`、`lag.same_member` | 聚合异常与冗余不足 |
| `stp.down_port` | 端口被 STP 保护关闭 |
| `routing.peer_down`、`routing.peer_recent`、`routing.peer_lost` | 路由邻居未建立、近期重建、消失 |
| `link.speed_mismatch`、`link.half_duplex`、`link.pvid_mismatch`、`link.one_way` | 链路两端一致性 |

阈值是 assess 参数，可用策略文件（配置项 `policy`）启停或调整。

## 存储

- `~/.local/share/gatework/swtele/ledger/<批次>/{manifest.json,devices/<ip>.json}` 与 `ledger/LATEST`，均为原子写。
- 830 台设备的批次约 300 MB，主要是 MAC 表。查询时全量加载，约 2 秒。
- 增长类规则会自动比较上一批次。

## 配置叠加

- `import --configs <备份目录>`，或配置项 `configs`，按文件名中的管理地址匹配设备。
- 解析使用 netops `config.Comware()` / `config.Cisco()`，结果写入 `Device.Config`，即配置意图：端口模式、PVID、允许 VLAN、shutdown、聚合组、VRF、地址、STP 边缘口与 BPDU 保护、vPC、VLAN、STP 全局、IRF 优先级、MAD BFD、静态路由。
- 意图与运行态分开存放。漂移由 `config.*` 规则报告。
- NX-OS 端口默认的管理状态随版本和 `system default switchport shutdown` 而变，所以只认明确写出的 shutdown / no shutdown。

## 批次对比与终端轨迹

- `delta.Compare` 把每台设备展开为带键的事实，用 netops `diff.Maps` 比对。覆盖的变化：设备增减、端口状态/速率/描述、光模块序列号、邻居、路由邻居、堆叠角色、聚合成员、VLAN、软件版本。
- 任一批次中该维度未完整采集时，不参与比对。
- 每次导入后，对全部已解析的 ARP 做定位，按 MAC+IP 记入 `sightings/endpoints.json`：首次出现、最近出现、当前接入口，以及最近 10 次迁移。超过 `history_days`（默认 90 天）未见的终端会被清理。

## 在线采集与定时巡检

- `swtele collect [选择器]`：从 `inventory` 中选出 H3C 与 NX-OS 设备，用 net-connector 建立 SSH 会话，经 netops `ops.Collect` 执行采集清单（`vendors.Profile`）。结果合并进 `raw/`（netops snapshot 布局），再按导入流程生成批次。
- 凭据来自 `~/.gatework/.env` 中的 `NC_DEVICE_USERNAME` / `NC_DEVICE_PASSWORD`。
- 采集清单只含语料采集时已被全网设备接受的命令。已能解码、但未经实机验证的 `display version` / `show version` 需要 `extra_commands: true` 才会采集。
- `swtele watch`：用 netops `job` 按计划（`schedule` 或 `--every`）运行"采集、导入、评估"。高危发现与终端迁移作为 netops 事件写入 `events_file`，运行记录保存在 `runs/`。
- 批次保留 `retention_batches` 个（默认 30）。

## 二期厂商

| 包 | 平台 | 语料 | 说明 |
|---|---|---|---|
| `vendors/hillstone` | StoneOS（SG-6000） | 20 台 | HA 角色取自提示符 `(M)/(B)`；光模块 "normal range" 作为告警阈值；`show lacp aggregateN` 用前缀步骤匹配 |
| `vendors/alteon` | Radware Alteon | 8 台 | 菜单式命令；端口按编号命名，管理口为 `mgmt`；IP 接口命名为 `IF<n>`；菜单提示符 `>> …#` 由 clidoc 识别 |
| `vendors/panos` | PAN-OS | 2 台 | 首行回显 `user@host(role)> 命令`；光功率按 mW 换算为 dBm（0 mW 视为无光） |
| `vendors/ios` | IOS / IOS-XE（Catalyst） | 1 台 | 结构与 NX-OS 接近；五张 DOM 阈值表分别解析 |

这四个平台都没有配置叠加。语料中 830 台设备全部可以解码。

## 未完成

- **在线采集与 watch 未经实机验证**：已用假 Dialer 测通 `ops.Collect`、raw 存储、导入的整条链路。
- **补采命令**：`display stp brief`、`show vpc brief`、路由表摘要，需实机验证并补解码器。
- **netops 缺口**：
  - `iface` 缺 Vlan-interface、LoopBack、M-GE、SGE、REG、NULL 等族，当前在 `swtele.InterfaceKey` 中补齐。
  - `neighbor` 的 Comware LLDP list 模板不识别 System Name 在前的版式，当前改用本地行计数。
