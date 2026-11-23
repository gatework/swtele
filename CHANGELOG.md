# Changelog

## v0.1.0

- 设备对象模型：系统、堆叠/MAD、接口（计数、速率、抖动、光模块 DOM）、聚合、二层（MAC/STP）、三层（ARP、路由邻居）、LLDP/CDP 邻居。
- H3C Comware 与 Cisco NX-OS 回显解码，语料中每条命令 0 未识别行。
- 台账索引、LLDP/CDP 拓扑（confirmed/one_way/shared/unmanaged）与端口角色。
- IP/MAC 定位：经过口与末端口分类、共享接入口、非受管设备之后、虚拟网关 MAC 与 IP 冲突提示。
- 风险目录：光模块、错包增长、抖动、设备健康、IRF/MAD、聚合、STP、路由邻居、链路一致性。
- 配置叠加（Comware/NX-OS）与配置漂移规则（端口模式、允许 VLAN、管理状态、聚合归属、边缘口 BPDU 保护、STP 关闭、配置过旧）。
- 批次对比（diff）、终端接入轨迹（history）、批次保留策略。
- 在线采集（collect，net-connector + netops ops.Collect）与定时巡检（watch，netops job + 事件文件）。
- 光模块类规则只评估接口 up 的物理口（down 口读数不反映链路质量），`optics` 列表对 down 口不评级。
- 设备 360 健康分与主要风险；capacity（闲置口与热点口）、errors、flap、health 专项命令，以及 rebuild。
- 缺少设备凭据时 collect 在连接任何设备之前拒绝运行。
- CLI 按用户视角重写：所有输出中文化（状态、角色、链路、级别、IRF 角色）、统一按配置时区显示、对象渲染为“端口 X”、缺失值不再输出占位符；每个列表输出“匹配 N / 共 M”与数据时间。
- 分析命令接受 netops 选择器位置参数（地址、网段、名称、`role=`/`site=`/`platform=` 等），统一 `--format table|json|csv|markdown`、`--sort`、`--limit`。
- 场景过滤（`query` 包，可组合谓词）：
  - `optics --abnormal/--dark/--no-dom/--idle-module/--non-original/--swapped/--level/--margin-below`，评估列写明原因（如“收光偏高预警”）。
  - `port --status/--idle/--errors/--growing/--flapping/--half-duplex/--speed-below/--util-above/--macs-above/--no-desc/--desc-mismatch/--drift`。
  - 新增 `devices` 列表：`--cpu-above/--mem-above/--temp-alarm/--fan-psu-fault/--score-below/--irf-no-mad/--irf-split/--single-uplink/--stale-config/--incomplete`。
  - `topology --hops/--state/--mismatch`，导出 Mermaid/DOT。
  - `risk` 默认按问题汇总，`--detail`、`--category`、`--exclude`，`--new/--resolved` 与上一批次比较。
  - `capacity --free-below`；`locate --exact-only`。
- 设备 360：型号缺失时由邻居 LLDP/CDP 通告补全（注明来源）、采集覆盖一行汇总、环境、端口与速率分布、邻居与路由邻居列表、错包口。
- 拓扑：对端口 ID 为 MAC 时解析为接口名，同一端口对同一设备的多条通告合并，消除 mgmt0 单向误报；只通告 LLDP Station 或系统名为网卡型号的邻居按终端处理。
- 定位：网关只取路由设备，其中优先作为其他设备默认网关的一台，并显示网段所在的三层接口；其余 ARP 持有者折叠为“另有 N 台”；网络设备自身地址直接回答所属设备与上联口。
- 错误率改为 CRC/入包（上限 100%），errors 先列 up 口与仍在增长的口。
- capacity：配置为 shutdown 的端口计入“管理关闭”，不算可回收闲置口。
- batches 显示时间、设备数、来源（导入/刷新自）与最新标记；diff 无变化时直接说明，有变化时按类别汇总。
- 二期厂商解码：Hillstone StoneOS、Radware Alteon、PAN-OS、Cisco IOS-XE，语料中均为 0 未识别行。
- 数据目录无法确定（HOME 为空）时拒绝运行，避免数据写入当前目录。
- JSON 批次存储；中文命令行 import、batches、device、port、locate、topology、optics、risk、report。
