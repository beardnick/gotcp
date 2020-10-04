package tcp

import "github.com/google/gopacket/layers"

type State int

const (
	CLOSED State = iota
	LISTEN
	SYN_RCVD
	SYN_SENT
	ESTAB
	FIN_WAIT_1
	CLOSE_WAIT
	CLOSING
	FINWAIT_2
	TIME_WAIT
	LAST_ACK
)

func (s State) String() string {
	switch s {
	case CLOSED:
		return "CLOSED"
	case LISTEN:
		return "LISTEN"
	case SYN_RCVD:
		return "SYN_RCVD"
	case SYN_SENT:
		return "SYN_SENT"
	case ESTAB:
		return "ESTAB"
	case FIN_WAIT_1:
		return "FIN_WAIT_1"
	case CLOSE_WAIT:
		return "CLOSE_WAIT"
	case CLOSING:
		return "CLOSING"
	case FINWAIT_2:
		return "FINWAIT_2"
	case TIME_WAIT:
		return "TIME_WAIT"
	case LAST_ACK:
		return "LAST_ACK"
	}
	return "UNKNOWN"
}

type TcpHandler struct {
	Header       layers.TCP
	CurrentState State
}
