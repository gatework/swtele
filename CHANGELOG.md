# Changelog

## Unreleased

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
- 二期厂商解码：Hillstone StoneOS、Radware Alteon、PAN-OS、Cisco IOS-XE，语料中均为 0 未识别行。
- 数据目录无法确定（HOME 为空）时拒绝运行，避免数据写入当前目录。
- JSON 批次存储；中文命令行 import、batches、device、port、locate、topology、optics、risk、report。
