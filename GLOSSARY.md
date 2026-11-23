# 术语

- **台账（Ledger）**：一个采集批次中全部设备的运行态及其索引。
- **批次（Batch）**：一次导入或采集，存放在 `ledger/<时间>/` 下。
- **维度（Dimension）**：独立采集的一类事实，如 interfaces、optics、arp。每个维度都有覆盖状态。
- **覆盖状态**：complete、partial、failed、not_requested。规则只在所需维度 complete 时运行。
- **接入口（edge）**：面向终端的端口。
- **互联口（infra）**：面向受管设备或网络设备（交换机、路由器、AP）的端口。
- **堆叠口（stack）**：IRF 物理口、vPC peer-link、隧道。
- **经过口 / 末端口**：定位时学到该 MAC 的端口中，对端为受管设备的是经过口，其余是末端口。
- **非受管邻居**：LLDP/CDP 可见、但不在台账中的设备。
- **DOM**：光模块数字诊断（温度、电压、偏置、收发光）。
- **MAD**：IRF 多主检测（BFD、LACP、ARP、ND）。
