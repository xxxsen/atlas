package outbound

// IOutboundManager describes the behaviour required from an outbound manager.

type IOutboundManager interface {
	Get(tag string) (IDnsOutbound, bool)
}
