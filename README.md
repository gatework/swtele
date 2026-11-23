# swtele

swtele 是网络设备运行态台账。它解析 H3C Comware、Cisco NX-OS、Cisco IOS-XE、Hillstone StoneOS、Radware Alteon 和 PAN-OS 的运行态回显，为每台设备建立厂商无关的对象模型，并在全网台账上提供以下功能：

- IP/MAC 定位到接入端口
- LLDP/CDP 拓扑
- 光模块质量（收光越限、余量、通道不均、链路衰耗）
- 错包增长、端口抖动
- CPU、内存、温度
- IRF/MAD、聚合、STP 与路由邻居的风险发现

## 安装

使用 Go 1.26 或更高版本安装。

```sh
go install github.com/gatework/swtele/cmd/swtele@v0.1.0
```

## 使用

```
swtele import ~/Documents/Snapshots/devices   # 导入快照，生成台账批次
swtele device SW01                            # 设备 360
swtele port SW01 GE1/0/1                      # 端口台账（含光模块与口下终端）
swtele locate 192.0.2.10 --why                # IP 定位
swtele topology SW01                          # 互联拓扑
swtele risk --severity high                   # 风险
swtele report --format markdown               # 汇总报表
swtele capacity --detail                      # 端口使用率、可回收闲置口、热点口
swtele errors | flap | health                 # 错包、抖动、设备运行专项
swtele rebuild                                # 解析器升级后按来源重放生成新批次
swtele diff                                   # 与上一批次比较
swtele history 192.0.2.10                     # 终端接入轨迹
swtele collect site=hq                        # 在线采集（需 inventory 与凭据）
swtele watch --every '@every 4h'              # 定时采集、评估、输出事件
```

数据在 `~/.local/share/gatework/swtele`。配置文件 `~/.gatework/swtele.yml` 可选，可设置以下字段：

```yaml
timezone: 8              # 设备时间未带时区时按 UTC+8 解释
inventory: inventory.yml # netops 清单：按管理地址补设备名、平台、站点
policy: policy.yml       # netops assess 策略：启停规则、调整阈值
trunk_limit: 32          # 无邻居通告的 trunk 口学到多少 MAC 视为上联
configs: ~/Documents/backups  # 配置备份目录（主机名-管理地址.txt），自动叠加
history_days: 90         # 终端轨迹保留天数
retention_batches: 30    # 保留的台账批次数
ssh: {host_key_policy: strict, connect_retries: 1}
workers: 16
extra_commands: false    # 是否采集未经实机验证的命令
schedule: "@every 4h"    # watch 的计划
events_file: ~/.local/share/gatework/swtele/events.jsonl
```

在线采集的凭据放在 `~/.gatework/.env`：`NC_DEVICE_USERNAME`、`NC_DEVICE_PASSWORD`。

设计见 [docs/design.md](docs/design.md)。
