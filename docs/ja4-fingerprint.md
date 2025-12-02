# JA4 Fingerprint

[JA4 is a TLS client fingerprint](https://foxio.io/ja4) based on client's TLS Client Hello packet.

## TLS Client Hello message

[TLS Handshake](https://wiki.osdev.org/TLS_Handshake)

## Golang Implementations

### refraction-networking/utls

[refraction-network/utls | GitHub](https://github.com/refraction-networking/utls) is a fork of the Go standard TLS library, providing low-level access to the ClientHello for mimicry purposes. Its creation seems to stem from the fact that "Golang's ClientHello has a very unique fingerprint", which is undirable for those with privacy in mind.

The [utls/handshake_message.go](https://github.com/refraction-networking/utls/blob/master/handshake_messages.go) file implements a `clientHelloMsg` struct that contains the relevant information about the TLS Client Hello packet.

```golang
type clientHelloMsg struct {
	original                         []byte
	vers                             uint16
	random                           []byte
	sessionId                        []byte
	cipherSuites                     []uint16
	compressionMethods               []uint8
	serverName                       string
	ocspStapling                     bool
	supportedCurves                  []CurveID
	supportedPoints                  []uint8
	ticketSupported                  bool
	sessionTicket                    []uint8
	supportedSignatureAlgorithms     []SignatureScheme
	supportedSignatureAlgorithmsCert []SignatureScheme
	secureRenegotiationSupported     bool
	secureRenegotiation              []byte
	extendedMasterSecret             bool
	alpnProtocols                    []string
	scts                             bool
	// ems                              bool // [uTLS] actually implemented due to its prevalence // removed since crypto/tls implements it
	supportedVersions       []uint16
	cookie                  []byte
	keyShares               []keyShare
	earlyData               bool
	pskModes                []uint8
	pskIdentities           []pskIdentity
	pskBinders              [][]byte
	quicTransportParameters []byte
	encryptedClientHello    []byte
	// extensions are only populated on the server-side of a handshake
	extensions []uint16

	// [uTLS]
	nextProtoNeg bool
}
```



### wi1dcard/fingerproxy

[wi1dcard/fingerproxy | GitHub](https://github.com/wi1dcard/fingerproxy) an HTTPS reverse proxy which parses the client TLS connection to create a fingerprint which is then passed to the origin via HTTP request headers.

The [pkg/ja4/ja4.go](https://github.com/wi1dcard/fingerproxy/blob/master/pkg/ja4/ja4.go) file implements a `JA4Fingerprint` struct that contains the relevant information to construct a JA4 fingerprint.

```golang
type JA4Fingerprint struct {
	//
	// JA4_a
	//

	Protocol             byte
	TLSVersion           tlsVersion
	SNI                  byte
	NumberOfCipherSuites numberOfCipherSuites
	NumberOfExtensions   numberOfExtensions
	FirstALPN            string

	//
	// JA4_b
	//

	CipherSuites cipherSuites

	//
	// JA4_c
	//

	Extensions          extensions
	SignatureAlgorithms signatureAlgorithms
}
```

There are following functions that implement the necessary unmarshalling of the packet bytes (to a Client Hello message structure using the utls library above) and data manipulation to generate the JA4 fingerprint.

We can see an example of the implementation in use within the [pkg/ja4pcap/pcap.go](https://github.com/wi1dcard/fingerproxy/blob/master/pkg/ja4pcap/pcap.go) file:

```golang
j := ja4.JA4Fingerprint{}
err := j.UnmarshalBytes(pl, 't')

...

return j.String(), nil
```

### voukatas/go-ja4

[voukatas/go-ja4 | GitHub](https://github.com/voukatas/go-ja4) is a Go-based implementation for generting JA4 / JA4S fingerprints.

The [pkg/ja4/ja4.go](https://github.com/voukatas/go-ja4/blob/main/pkg/ja4/ja4.go) file implements a `ParseClientHelloForJA4` function which takes in the bytes of the Client Hello message packet.