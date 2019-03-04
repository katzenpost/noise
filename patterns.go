package noise

// HandshakeNN describes an interactive handshake pattern where neither the
// initiator nor the responder has an static key.
// See: http://noiseprotocol.org/noise.html, section 7.5.
var HandshakeNN = HandshakePattern{
	Name: "NN",
	Messages: [][]MessagePattern{
		{MessagePatternE},
		{MessagePatternE, MessagePatternDHEE},
	},
}

// HandshakeKN describes an interactive handshake pattern where the responder
// has pre-knowledge of the initiator's static public key.
// See: http://noiseprotocol.org/noise.html, section 7.5.
var HandshakeKN = HandshakePattern{
	Name:                 "KN",
	InitiatorPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE},
		{MessagePatternE, MessagePatternDHEE, MessagePatternDHSE},
	},
}

// HandshakeNK describes an interactive handshake pattern where the initiator
// has pre-knowledge of the responder's static public key.
// See: http://noiseprotocol.org/noise.html, section 7.5.
var HandshakeNK = HandshakePattern{
	Name:                 "NK",
	ResponderPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternDHES},
		{MessagePatternE, MessagePatternDHEE},
	},
}

// HandshakeKK describes an interactive handshake pattern where both the initiator
// and the responder has pre-knowledge of the other's static public key.
// See: http://noiseprotocol.org/noise.html, section 7.5.
var HandshakeKK = HandshakePattern{
	Name:                 "KK",
	InitiatorPreMessages: []MessagePattern{MessagePatternS},
	ResponderPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternDHES, MessagePatternDHSS},
		{MessagePatternE, MessagePatternDHEE, MessagePatternDHSE},
	},
}

// HandshakeNX describes an interactive handshake pattern where the responder
// public key has been "transmitted" to the initiator.
// See: http://noiseprotocol.org/noise.html, section 7.5.
var HandshakeNX = HandshakePattern{
	Name: "NX",
	Messages: [][]MessagePattern{
		{MessagePatternE},
		{MessagePatternE, MessagePatternDHEE, MessagePatternS, MessagePatternDHES},
	},
}

// HandshakeKX describes an interactive handshake pattern where the responder has
// pre-knowledge of the initiator static public key and the responder's
// static public key has been "transmitted" to the initiator.
// See: http://noiseprotocol.org/noise.html, section 7.5.
var HandshakeKX = HandshakePattern{
	Name:                 "KX",
	InitiatorPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE},
		{MessagePatternE, MessagePatternDHEE, MessagePatternDHSE, MessagePatternS, MessagePatternDHES},
	},
}

// HandshakeXN describes an interactive handshake pattern where the initiator
// public key has been "transmitted" to the responder.
// See: http://noiseprotocol.org/noise.html, section 7.5.
var HandshakeXN = HandshakePattern{
	Name: "XN",
	Messages: [][]MessagePattern{
		{MessagePatternE},
		{MessagePatternE, MessagePatternDHEE},
		{MessagePatternS, MessagePatternDHSE},
	},
}

// HandshakeIN describes an interactive handshake pattern where the initiator's
// static public key has been immediately transmitted to the responder, despite
// reduced or absent identity hiding.
// See: http://noiseprotocol.org/noise.html, section 7.5.
var HandshakeIN = HandshakePattern{
	Name: "IN",
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternS},
		{MessagePatternE, MessagePatternDHEE, MessagePatternDHSE},
	},
}

// HandshakeXK describes an interactiv handshake pattern where the initiator has
// pre-knowledge of the responder's static public key and the initiator's
// static public key has been "transmitted" to the responder.
// See: http://noiseprotocol.org/noise.html, section 7.5.
var HandshakeXK = HandshakePattern{
	Name:                 "XK",
	ResponderPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternDHES},
		{MessagePatternE, MessagePatternDHEE},
		{MessagePatternS, MessagePatternDHSE},
	},
}

// HandshakeIK describes an interactive handshake pattern where the initiator's
// static public key has been immediately transmitted to the responder, despite
// reduced or absent identity hiding, and the initiator has pre-knowledge
// of the responder's static public key.
// See: http://noiseprotocol.org/noise.html, section 7.5.
var HandshakeIK = HandshakePattern{
	Name:                 "IK",
	ResponderPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternDHES, MessagePatternS, MessagePatternDHSS},
		{MessagePatternE, MessagePatternDHEE, MessagePatternDHSE},
	},
}

// HandshakeXX describes an interactive handshake pattern where both the initiator
// and the responder have transmitted each static public key to the other.
// See: http://noiseprotocol.org/noise.html, section 7.5.
var HandshakeXX = HandshakePattern{
	Name: "XX",
	Messages: [][]MessagePattern{
		{MessagePatternE},
		{MessagePatternE, MessagePatternDHEE, MessagePatternS, MessagePatternDHES},
		{MessagePatternS, MessagePatternDHSE},
	},
}

// HandshakeIX describes an interactive handshake pattern where the initiator's
// static public key has been immediately transmitted to the responder, despite
// reduced or absent identity hiding, and the initiator has pre-knowledge
// of the responder's static public key.
// See: http://noiseprotocol.org/noise.html, section 7.5.
var HandshakeIX = HandshakePattern{
	Name: "IX",
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternS},
		{MessagePatternE, MessagePatternDHEE, MessagePatternDHSE, MessagePatternS, MessagePatternDHES},
	},
}

// HandshakeN describes a one-way handshake pattern where there is no
// static public key for the sender.
// See: http://noiseprotocol.org/noise.html, section 7.4.
var HandshakeN = HandshakePattern{
	Name:                 "N",
	ResponderPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternDHES},
	},
}

// HandshakeK describes a one-way handshake pattern where the sender's static
// public key is known to the recipient.
// See: http://noiseprotocol.org/noise.html, section 7.4.
var HandshakeK = HandshakePattern{
	Name:                 "K",
	InitiatorPreMessages: []MessagePattern{MessagePatternS},
	ResponderPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternDHES, MessagePatternDHSS},
	},
}

// HandshakeX describes a one-way handshake pattern where the sender's static
// public key is transmitted to the recipient.
// See: http://noiseprotocol.org/noise.html, section 7.4.
var HandshakeX = HandshakePattern{
	Name:                 "X",
	ResponderPreMessages: []MessagePattern{MessagePatternS},
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternDHES, MessagePatternS, MessagePatternDHSS},
	},
}

// HandshakeXXhfs describes an interactive handshake pattern where both the
// initiator and the responder have transmitted each static public key to the
// other in the Hybrid Forward Secrecy algorithm.
var HandshakeXXhfs = HandshakePattern{
	Name: "XXhfs",
	Messages: [][]MessagePattern{
		{MessagePatternE, MessagePatternF},
		{MessagePatternE, MessagePatternF, MessagePatternDHEE, MessagePatternFF, MessagePatternS, MessagePatternDHES},
		{MessagePatternS, MessagePatternDHSE},
	},
}
