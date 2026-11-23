package swtele

// NoLight is the receive power, in dBm, that devices print for "no signal".
const NoLight = -40.0

// DOMSupport tells whether a transceiver reports diagnostics.
type DOMSupport string

// DOM support states.
const (
	DOMUnknown     DOMSupport = ""
	DOMSupported   DOMSupport = "supported"
	DOMUnsupported DOMSupport = "unsupported"
)

// Transceiver is the pluggable module in a port.
type Transceiver struct {
	// Present is false for an empty cage.
	Present   bool          `json:"present"`
	Inventory XcvrInventory `json:"inventory,omitzero"`
	DOM       DOMSupport    `json:"dom,omitempty"`
	Temp      Reading       `json:"temperature_c,omitzero"`
	Voltage   Reading       `json:"voltage_v,omitzero"`
	// Lanes holds bias and optical power: one lane for SFP, four for QSFP.
	Lanes []Lane `json:"lanes,omitempty"`
}

// XcvrInventory identifies a module.
type XcvrInventory struct {
	Vendor     string   `json:"vendor,omitempty"`
	PartNumber string   `json:"part_number,omitempty"`
	Serial     string   `json:"serial,omitempty"`
	Type       string   `json:"type,omitempty"`
	ProductID  string   `json:"product_id,omitempty"`
	Date       string   `json:"date,omitempty"`
	Wavelength Opt[int] `json:"wavelength_nm,omitzero"`
}

// Lane is one optical lane.
type Lane struct {
	Index   int     `json:"index"`
	Bias    Reading `json:"bias_ma,omitzero"`
	RxPower Reading `json:"rx_dbm,omitzero"`
	TxPower Reading `json:"tx_dbm,omitzero"`
}

// Reading is one diagnostic value with the module's thresholds.
type Reading struct {
	Value Opt[float64] `json:"value,omitzero"`
	Th    Thresholds   `json:"thresholds,omitzero"`
}

// IsZero reports an empty reading, for omitzero.
func (r Reading) IsZero() bool { return !r.Value.OK && r.Th.IsZero() }

// Thresholds are the alarm and warning limits of a reading.
type Thresholds struct {
	HighAlarm Opt[float64] `json:"high_alarm,omitzero"`
	HighWarn  Opt[float64] `json:"high_warn,omitzero"`
	LowWarn   Opt[float64] `json:"low_warn,omitzero"`
	LowAlarm  Opt[float64] `json:"low_alarm,omitzero"`
}

// IsZero reports that no threshold is known.
func (t Thresholds) IsZero() bool {
	return !t.HighAlarm.OK && !t.HighWarn.OK && !t.LowWarn.OK && !t.LowAlarm.OK
}

// Level grades a reading against its thresholds.
type Level string

// Levels, from best to worst.
const (
	LevelUnknown Level = ""
	LevelNormal  Level = "normal"
	LevelWarn    Level = "warning"
	LevelAlarm   Level = "alarm"
)

// Level grades the reading against its own thresholds. A reading without
// value is unknown; one without thresholds is normal.
func (r Reading) Level() Level {
	v, ok := r.Value.Get()
	if !ok {
		return LevelUnknown
	}
	switch {
	case above(v, r.Th.HighAlarm), below(v, r.Th.LowAlarm):
		return LevelAlarm
	case above(v, r.Th.HighWarn), below(v, r.Th.LowWarn):
		return LevelWarn
	}
	return LevelNormal
}

// Margin returns the distance from the value to the nearest warning (or,
// lacking one, alarm) threshold; negative means the threshold is crossed.
// ok is false without a value or thresholds.
func (r Reading) Margin() (margin float64, ok bool) {
	v, has := r.Value.Get()
	if !has {
		return 0, false
	}
	hi, lo := r.Th.HighWarn, r.Th.LowWarn
	if !hi.OK {
		hi = r.Th.HighAlarm
	}
	if !lo.OK {
		lo = r.Th.LowAlarm
	}
	switch {
	case hi.OK && lo.OK:
		return min(hi.V-v, v-lo.V), true
	case hi.OK:
		return hi.V - v, true
	case lo.OK:
		return v - lo.V, true
	}
	return 0, false
}

// Dark reports a power reading at the "no light" sentinel or below.
func (r Reading) Dark() bool { return r.Value.OK && r.Value.V <= NoLight }

func above(v float64, limit Opt[float64]) bool { return limit.OK && v > limit.V }
func below(v float64, limit Opt[float64]) bool { return limit.OK && v < limit.V }
