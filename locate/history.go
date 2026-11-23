package locate

import "time"

// Place is where an endpoint was attached.
type Place struct {
	Device string    `json:"device"`
	Mgmt   string    `json:"mgmt"`
	Port   string    `json:"port"`
	VLAN   int       `json:"vlan,omitempty"`
	Since  time.Time `json:"since"`
}

// Record is the history of one endpoint.
type Record struct {
	IP    string    `json:"ip"`
	MAC   string    `json:"mac"`
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
	Batch string    `json:"batch"`
	Place Place     `json:"place"`
	// Moves are the previous places, most recent first.
	Moves []Place `json:"moves,omitempty"`
}

// Move is an endpoint that changed port in the latest batch.
type Move struct {
	IP, MAC  string
	From, To Place
}
