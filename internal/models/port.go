package models

// Protocol represents the network protocol type
type Protocol string

const (
	TCP Protocol = "TCP"
	UDP Protocol = "UDP"
)

// PortState represents the state of a port
type PortState string

const (
	Listening   PortState = "LISTENING"
	Established PortState = "ESTABLISHED"
	TimeWait    PortState = "TIME_WAIT"
	CloseWait   PortState = "CLOSE_WAIT"
	SynSent     PortState = "SYN_SENT"
	SynReceived PortState = "SYN_RECEIVED"
	FinWait1    PortState = "FIN_WAIT1"
	FinWait2    PortState = "FIN_WAIT2"
	Closing     PortState = "CLOSING"
	LastAck     PortState = "LAST_ACK"
	Closed      PortState = "CLOSED"
)

// RiskLevel represents the conflict risk level
type RiskLevel string

const (
	Low    RiskLevel = "LOW"
	Medium RiskLevel = "MEDIUM"
	High   RiskLevel = "HIGH"
)

// PortEntry represents a single port connection entry
type PortEntry struct {
	Protocol     Protocol
	LocalAddress string
	LocalPort    int
	State        PortState
	PID          int
	ProcessName  string
	ProcessPath  string
	User         string
}
