package cli

// Chinese texts of the command line.
const (
	shortHelp    = "查看帮助"
	flagHelp     = "查看帮助"
	flagVersion  = "显示版本"
	errPrefix    = "错误："
	errUsageHint = "（运行 swtele --help 查看用法）"

	shortRoot = "网络设备运行态台账：端口、邻居、光模块、错包、IRF、STP 与 IP 定位"
	longRoot  = `swtele 解析设备运行态回显（及配置），为每台设备建立厂商无关的台账，
并在全网台账上做 IP/MAC 定位、拓扑、光模块质量、错包增长、抖动与风险评估。

数据目录：~/.local/share/gatework/swtele（台账批次为 JSON 文件）
配置文件：~/.gatework/swtele.yml（可选）`

	flagConfig  = "配置文件路径（默认 ~/.gatework/swtele.yml）"
	flagBatch   = "台账批次（默认最新）"
	flagJSON    = "以 JSON 输出"
	flagLimit   = "最多显示的行数（0 不限）"
	flagFormat  = "报表格式：text、markdown、json"
	flagSev     = "只显示不低于该级别的发现：info、low、medium、high、critical"
	flagRule    = "只显示规则 ID 匹配该前缀的发现"
	flagDevice  = "只评估匹配的设备（地址或名称）"
	flagWhy     = "同时显示定位经过的互联端口"
	flagConfigs = "配置备份目录（文件名形如 主机名-管理地址.txt），叠加为配置意图"

	shortImport   = "从快照目录导入运行态回显，生成新的台账批次"
	shortBatches  = "列出台账批次"
	shortDevice   = "设备 360：系统、堆叠、端口汇总"
	shortPort     = "端口台账：状态、速率、VLAN、IP、光模块、计数、邻居"
	shortLocate   = "定位 IP 或 MAC 所在的接入端口"
	shortTopology = "设备互联拓扑（LLDP/CDP）"
	shortRisk     = "运行风险评估（光模块、错包、抖动、IRF、聚合、路由邻居…）"
	shortReport   = "生成台账与风险汇总报表"
	shortOptics   = "光模块台账与收发光"
	shortCollect  = "在线采集清单中的设备并生成新的台账批次"
	shortWatch    = "按计划定时采集、评估并输出事件"
	flagEvery     = "计划：@every 4h、@daily 或 5 段 cron（默认取配置 schedule，否则 @every 4h）"
	flagOnce      = "立即执行一次后退出"
	shortCapacity = "端口容量：使用率、可回收闲置口与热点端口"
	shortRebuild  = "用当前解析器重放批次来源，生成新批次（解析器升级后使用）"
	shortErrors   = "错包与丢包：增长、历史累计与利用率"
	shortFlap     = "端口抖动：近期 up/down、日志反复与复位"
	shortHealth   = "设备运行：CPU、内存、温度、风扇电源、IRF/MAD、聚合、路由邻居"
	flagIdleDays  = "down 超过多少天视为可回收闲置口"
	flagHot       = "利用率达到多少百分比视为热点"
	flagDetail    = "列出闲置口与热点端口明细"
	shortHistory  = "终端接入轨迹：首次/最近出现与历史迁移"
	shortDiff     = "比较两个台账批次的变化"
)
