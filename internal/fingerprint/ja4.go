package fingerprint

// This package has been implemented from libraries
// https://github.com/voukatas/go-ja4

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"

	utls "github.com/refraction-networking/utls"
)

type JA4Key string

const JA4 JA4Key = "ja4"

// voukatas/go-ja4

func IsGreaseValue(val uint16) bool {
	highByte := uint8(val >> 8)
	lowByte := uint8(val & 0xff)
	return (val&0x0f0f) == 0x0a0a && highByte == lowByte
}

func IsAlnum(b byte) bool {
	return unicode.IsLetter(rune(b)) || unicode.IsDigit(rune(b))
}

func MapTLSVersion(version uint16) string {
	switch version {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfefd:
		return "d2" // DTLS 1.2
	case 0xfeff:
		return "d1" // DTLS 1.0
	case 0xfefc:
		return "d3" // DTLS 1.3
	default:
		return "00"
	}
}

func BuildHexList(values []uint16) string {
	hexList := make([]string, len(values))
	for i, val := range values {
		hexList[i] = fmt.Sprintf("%04x", val)
	}
	return strings.Join(hexList, ",")
}

func ComputeTruncatedSHA256(data string) string {
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:6])
}

func CompleteClientHelloMessage(payload []byte) (int, error) {
	offset := 0

	// Skip TLS/DTLS record headers (5 bytes)
	offset += 5

	if offset+4 > len(payload) {
		return -1, fmt.Errorf("payload too short")
	}

	// Handshake Type and Length
	handshakeType := payload[offset]
	handshakeLength := int(payload[offset+1])<<16 | int(payload[offset+2])<<8 | int(payload[offset+3])

	offset += 4

	// Client Hello
	if handshakeType != 0x01 {
		return -1, fmt.Errorf("not a Client Hello message")
	}

	if offset+handshakeLength > len(payload) {
		return (offset + handshakeLength) - len(payload), nil
	}

	return 0, nil
}

func ParseJA4(payload []byte, protocol byte) (string, error) {
	offset := 0

	// Skip TLS/DTLS record headers (5 bytes)
	offset += 5

	if offset+4 > len(payload) {
		return "", fmt.Errorf("payload too short")
	}

	// Handshake Type and Length
	handshakeType := payload[offset]
	handshakeLength := int(payload[offset+1])<<16 | int(payload[offset+2])<<8 | int(payload[offset+3])

	offset += 4

	// Client Hello
	if handshakeType != 0x01 {
		return "", fmt.Errorf("not a Client Hello message")
	}

	if offset+handshakeLength > len(payload) {
		return "", fmt.Errorf("imcomplete Client Hello message, payload length: %d, handshake length + offset: %d", len(payload), offset+handshakeLength)
	}

	// Start building the JA4 fingerprint
	var ja4Str strings.Builder

	ja4Str.WriteByte(protocol)

	// Client Version
	if offset+2 > len(payload) {
		return "", fmt.Errorf("payload too short for client version")
	}
	clientVersion := binary.BigEndian.Uint16(payload[offset : offset+2])
	offset += 2

	// Initialize TLS Version
	tlsVersion := "00"

	// Skip Random (32 bytes)
	if offset+32 > len(payload) {
		return "", fmt.Errorf("payload too short for server random")
	}
	offset += 32

	// Session ID
	if offset+1 > len(payload) {
		return "", fmt.Errorf("payload too short for session ID length")
	}
	sessionIDLen := int(payload[offset])
	offset += 1 + sessionIDLen

	// Cipher Suites
	if offset+2 > len(payload) {
		return "", fmt.Errorf("payload too short for cipher suites length")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2

	if offset+cipherSuitesLen > len(payload) {
		return "", fmt.Errorf("incomplete cipher suites data")
	}

	ciphers := make([]uint16, 0)

	for i := 0; i < cipherSuitesLen; i += 2 {
		cipher := binary.BigEndian.Uint16(payload[offset+i : offset+i+2])
		if !IsGreaseValue(cipher) {
			ciphers = append(ciphers, cipher)
		}
	}
	offset += cipherSuitesLen

	// Compression Methods
	if offset+1 > len(payload) {
		return "", fmt.Errorf("payload too short for compression methods length")
	}
	compressionMethodsLen := int(payload[offset])
	offset += 1 + compressionMethodsLen

	// Extensions
	if offset+2 > len(payload) {
		return "", fmt.Errorf("payload too short for extensions length")
	}
	extensionsLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2

	extensions := make([]uint16, 0)
	extensionCountWithSNI_ALPN := 0
	sniFound := false
	alpn := "00"
	sigAlgoCount := 0
	signatureAlgorithms := make([]uint16, 0)
	supportedVersionsFound := false
	highestSupportedVersion := uint16(0)

	extensionsEnd := offset + extensionsLen

	for offset+4 <= extensionsEnd && offset+4 <= len(payload) {
		extType := binary.BigEndian.Uint16(payload[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		offset += 4

		if offset+extLen > extensionsEnd || offset+extLen > len(payload) {
			break
		}

		extDataEnd := offset + extLen

		if IsGreaseValue(extType) {
			// Skip GREASE extension
			offset = extDataEnd
			continue
		}

		extensionCountWithSNI_ALPN++

		if extType != 0x0000 && extType != 0x0010 { // SNI_EXT and ALPN_EXT
			extensions = append(extensions, extType)
		}

		if extType == 0x0000 { // SNI_EXT
			sniFound = true
		}

		if extType == 0x0010 && extLen > 0 { // ALPN_EXT
			alpnOffset := offset
			if alpnOffset+2 > extDataEnd {
				return "", fmt.Errorf("payload too short for ALPN list length")
			}
			alpnListLen := int(binary.BigEndian.Uint16(payload[alpnOffset : alpnOffset+2]))
			alpnOffset += 2
			if alpnOffset+alpnListLen > extDataEnd {
				return "", fmt.Errorf("incomplete ALPN list")
			}
			if alpnListLen > 0 {
				if alpnOffset+1 > extDataEnd {
					return "", fmt.Errorf("payload too short for ALPN string length")
				}
				alpnStrLen := int(payload[alpnOffset])
				alpnOffset += 1
				if alpnOffset+alpnStrLen > extDataEnd {
					return "", fmt.Errorf("incomplete ALPN string")
				}
				if alpnStrLen > 0 {
					alpnValue := payload[alpnOffset : alpnOffset+alpnStrLen]
					// Get the ALPN string
					alpnStr := string(alpnValue)
					if !IsAlnum(alpnValue[0]) {
						alpn = "99"
					} else {
						alpn = alpnStr
					}
				}
			}
		}

		// SIGNATURE_ALGORITHMS_EXT
		if extType == 0x000d {
			sigOffset := offset
			if sigOffset+2 > extDataEnd {
				return "", fmt.Errorf("payload too short for signature algorithms length")
			}
			sigAlgsLen := int(binary.BigEndian.Uint16(payload[sigOffset : sigOffset+2]))
			sigOffset += 2
			if sigOffset+sigAlgsLen > extDataEnd {
				return "", fmt.Errorf("incomplete signature algorithms data")
			}
			for j := 0; j < sigAlgsLen; j += 2 {
				sigAlgo := binary.BigEndian.Uint16(payload[sigOffset+j : sigOffset+j+2])
				if !IsGreaseValue(sigAlgo) {
					signatureAlgorithms = append(signatureAlgorithms, sigAlgo)
					sigAlgoCount++
				}
			}
		}

		// SUPPORTED_VERSIONS_EXT
		if extType == 0x002b {
			supportedVersionsFound = true
			svOffset := offset
			if svOffset+1 > extDataEnd {
				return "", fmt.Errorf("payload too short for supported versions length")
			}
			svLen := int(payload[svOffset])
			svOffset += 1
			if svOffset+svLen > extDataEnd {
				return "", fmt.Errorf("incomplete supported versions data")
			}
			for j := 0; j < svLen; j += 2 {
				if svOffset+j+1 >= extDataEnd {
					break
				}
				version := binary.BigEndian.Uint16(payload[svOffset+j : svOffset+j+2])
				//fmt.Printf("--- client hello version in hex %x \n", version)
				if !IsGreaseValue(version) && version > highestSupportedVersion {
					highestSupportedVersion = version
				}
			}
		}

		// Move to the next extension
		offset = extDataEnd
	}

	// Determine TLS Version
	if supportedVersionsFound {
		tlsVersion = MapTLSVersion(highestSupportedVersion)
	} else {
		tlsVersion = MapTLSVersion(clientVersion)
	}

	// SNI Indicator
	sniIndicator := 'i'
	if sniFound {
		sniIndicator = 'd'
	}

	// Cipher Count
	cipherCountDisplay := len(ciphers)
	if cipherCountDisplay > 99 {
		cipherCountDisplay = 99
	}

	// Extension Count
	totalExtensionCount := extensionCountWithSNI_ALPN
	if totalExtensionCount > 99 {
		totalExtensionCount = 99
	}

	// Build the JA4 string up to ALPN
	ja4Str.WriteString(tlsVersion)
	ja4Str.WriteByte(byte(sniIndicator))

	// ALPN Characters
	alpnFirstChar := '0'
	alpnLastChar := '0'
	if len(alpn) > 0 {
		alpnFirstChar = rune(alpn[0])
		alpnLastChar = rune(alpn[len(alpn)-1])
	}

	// Build the complete JA4 string
	ja4Str.WriteString(fmt.Sprintf("%02d%02d%c%c_", cipherCountDisplay, totalExtensionCount, alpnFirstChar, alpnLastChar))

	// Sort ciphers
	sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })

	// Compute JA4_b (Cipher Hash)
	cipherStr := BuildHexList(ciphers)
	var ja4b string
	if len(ciphers) == 0 {
		ja4b = "000000000000"
	} else {
		ja4b = ComputeTruncatedSHA256(cipherStr)
	}
	ja4Str.WriteString(ja4b)
	ja4Str.WriteByte('_')

	// Sort extensions
	sort.Slice(extensions, func(i, j int) bool { return extensions[i] < extensions[j] })

	// Compute JA4_c (Extension Hash)
	extStr := BuildHexList(extensions)
	if sigAlgoCount > 0 {
		extStr += "_"
		sigAlgoStr := BuildHexList(signatureAlgorithms)
		extStr += sigAlgoStr
	}

	var ja4c string
	if len(extensions) == 0 {
		ja4c = "000000000000"
	} else {
		ja4c = ComputeTruncatedSHA256(extStr)
	}
	ja4Str.WriteString(ja4c)

	return ja4Str.String(), nil
}

// wi1dcard/fingerproxy

func sortUint16(sl []uint16) {
	sort.Slice(sl, func(x int, y int) bool { return sl[x] < sl[y] })
}

func joinUint16(slice []uint16, sep string) string {
	var buffer bytes.Buffer
	for i, u := range slice {
		if i != 0 {
			buffer.WriteString(sep)
		}
		buffer.WriteString(fmt.Sprintf("%04x", u))
	}
	return buffer.String()
}

func isGREASEUint16(v uint16) bool {
	// First byte is same as second byte
	// and lowest nibble is 0xa
	return ((v >> 8) == v&0xff) && v&0xf == 0xa
}

func truncatedSha256(in string) string {
	sha := sha256.New()
	sha.Write([]byte(in))
	return fmt.Sprintf("%x", sha.Sum(nil))[:12]
}

type (
	tlsVersion           uint16
	numberOfCipherSuites int
	numberOfExtensions   int

	cipherSuites        []uint16
	extensions          []uint16
	signatureAlgorithms []uint16
)

func (x tlsVersion) String() string {
	switch uint16(x) {
	case utls.VersionTLS10:
		return "10"
	case utls.VersionTLS11:
		return "11"
	case utls.VersionTLS12:
		return "12"
	case utls.VersionTLS13:
		return "13"
	}
	return "00"
}
func (x numberOfCipherSuites) String() string { return fmt.Sprintf("%02d", min(x, 99)) }
func (x numberOfExtensions) String() string   { return fmt.Sprintf("%02d", min(x, 99)) }
func (x cipherSuites) String() string         { return joinUint16(x, cipherSuitesSeparator) }
func (x extensions) String() string           { return joinUint16(x, extensionsSeparator) }
func (x signatureAlgorithms) String() string  { return joinUint16(x, signatureAlgorithmSeparator) }

const (
	extensionAndSignatureAlgorithmSeparator = "_"
	cipherSuitesSeparator                   = ","
	extensionsSeparator                     = ","
	signatureAlgorithmSeparator             = ","
)

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

func (j *JA4Fingerprint) UnmarshalBytes(clientHelloRecord []byte, protocol byte) error {
	chs := &utls.ClientHelloSpec{}
	// allowBluntMimicry: true
	// realPSK: false
	err := chs.FromRaw(clientHelloRecord, true, false)
	if err != nil {
		return fmt.Errorf("cannot parse client hello: %w", err)
	}
	return j.Unmarshal(chs, protocol)
}

func (j *JA4Fingerprint) Unmarshal(chs *utls.ClientHelloSpec, protocol byte) error {
	var err error

	// ja4_a
	j.Protocol = protocol
	j.unmarshalTLSVersion(chs)
	j.unmarshalSNI(chs)
	j.unmarshalNumberOfCipherSuites(chs)
	j.unmarshalNumberOfExtensions(chs)
	j.unmarshalFirstALPN(chs)

	// ja4_b
	j.unmarshalCipherSuites(chs, false)

	// ja4_c
	err = j.unmarshalExtensions(chs, false)
	if err != nil {
		return err
	}
	j.unmarshalSignatureAlgorithm(chs)

	return nil
}

func (j *JA4Fingerprint) String() string {
	ja4a := fmt.Sprintf(
		"%s%s%s%s%s%s",
		string(j.Protocol),
		j.TLSVersion,
		string(j.SNI),
		j.NumberOfCipherSuites,
		j.NumberOfExtensions,
		j.FirstALPN,
	)

	ja4b := truncatedSha256(j.CipherSuites.String())

	var ja4c string
	if len(j.SignatureAlgorithms) == 0 {
		ja4c = truncatedSha256(j.Extensions.String())
	} else {
		ja4c = truncatedSha256(fmt.Sprintf("%s_%s", j.Extensions, j.SignatureAlgorithms))
	}

	ja4 := fmt.Sprintf("%s_%s_%s", ja4a, ja4b, ja4c)

	return ja4
}

func (j *JA4Fingerprint) unmarshalTLSVersion(chs *utls.ClientHelloSpec) {
	var vers uint16
	if chs.TLSVersMax == 0 {
		// SupportedVersionsExtension found, extract version from extension, ref:
		// https://github.com/FoxIO-LLC/ja4/blob/61319bfc0d0038e0a240a8ab83aef1fdd821d404/technical_details/JA4.md?plain=1#L32
		for _, e := range chs.Extensions {
			if sve, ok := e.(*utls.SupportedVersionsExtension); ok {
				for _, v := range sve.Versions {
					// find the highest non-GREASE version
					if !isGREASEUint16(v) && v > vers {
						vers = v
					}
				}
			}
		}
	} else {
		vers = chs.TLSVersMax
	}

	j.TLSVersion = tlsVersion(vers)
}

func (j *JA4Fingerprint) unmarshalSNI(chs *utls.ClientHelloSpec) {
	for _, e := range chs.Extensions {
		if _, ok := e.(*utls.SNIExtension); ok {
			j.SNI = 'd'
			return
		}
	}
	j.SNI = 'i'
}

func (j *JA4Fingerprint) unmarshalNumberOfCipherSuites(chs *utls.ClientHelloSpec) {
	var n int
	for _, c := range chs.CipherSuites {
		if !isGREASEUint16(c) {
			n++
		}
	}
	j.NumberOfCipherSuites = numberOfCipherSuites(n)
}

func (j *JA4Fingerprint) unmarshalNumberOfExtensions(chs *utls.ClientHelloSpec) {
	var n int
	for _, e := range chs.Extensions {
		if _, ok := e.(*utls.UtlsGREASEExtension); ok {
			continue
		}
		n++
	}
	j.NumberOfExtensions = numberOfExtensions(n)
}

func (j *JA4Fingerprint) unmarshalFirstALPN(chs *utls.ClientHelloSpec) {
	var alpn string
	for _, e := range chs.Extensions {
		if a, ok := e.(*utls.ALPNExtension); ok {
			if len(a.AlpnProtocols) > 0 {
				alpn = a.AlpnProtocols[0]
			}
		}
	}
	if alpn == "" {
		j.FirstALPN = "00"
		return
	}
	// https://github.com/FoxIO-LLC/ja4/blob/e7226cb51729f70fce740e615f8b2168ad68f67c/python/ja4.py#L241-L245
	if len(alpn) > 2 {
		alpn = string(alpn[0]) + string(alpn[len(alpn)-1])
	}
	if alpn[0] > 127 {
		alpn = "99"
	}
	j.FirstALPN = alpn
}

// keepOriginalOrder should be false unless keeping the original order of cipher
// suites, ref:
// https://github.com/FoxIO-LLC/ja4/blob/61319bfc0d0038e0a240a8ab83aef1fdd821d404/technical_details/JA4.md?plain=1#L140C52-L140C60
func (j *JA4Fingerprint) unmarshalCipherSuites(chs *utls.ClientHelloSpec, keepOriginalOrder bool) {
	var cipherSuites []uint16
	for _, c := range chs.CipherSuites {
		if isGREASEUint16(c) {
			continue
		}
		cipherSuites = append(cipherSuites, c)
	}
	if !keepOriginalOrder {
		sortUint16(cipherSuites)
	}
	j.CipherSuites = cipherSuites
}

// keepOriginalOrder (-o option) should be false unless keeping SNI and ALPN extension
// and the original order of extensions, ref:
// https://github.com/FoxIO-LLC/ja4/blob/61319bfc0d0038e0a240a8ab83aef1fdd821d404/technical_details/JA4.md?plain=1#L140C52-L140C60
func (j *JA4Fingerprint) unmarshalExtensions(chs *utls.ClientHelloSpec, keepOriginalOrder bool) error {
	var extensions []uint16
	for _, e := range chs.Extensions {
		// exclude GREASE extensions
		if _, ok := e.(*utls.UtlsGREASEExtension); ok {
			continue
		}

		if !keepOriginalOrder {
			// SNI and ALPN extension should not be included, ref:
			// https://github.com/FoxIO-LLC/ja4/blob/61319bfc0d0038e0a240a8ab83aef1fdd821d404/technical_details/JA4.md?plain=1#L79
			if _, ok := e.(*utls.SNIExtension); ok {
				continue
			}
			if _, ok := e.(*utls.ALPNExtension); ok {
				continue
			}
		}

		// hack utls to allow reading padding extension data below
		if pe, ok := e.(*utls.UtlsPaddingExtension); ok {
			pe.WillPad = true
		}

		l := e.Len()
		if l == 0 {
			return fmt.Errorf("extension data should not be empty")
		}

		buf := make([]byte, l)
		n, err := e.Read(buf)
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("failed to read extension: %w", err)
		}

		if n < 2 {
			return fmt.Errorf("extension data is too short, expect more than 2, actual %d", n)
		}
		extId := uint16(buf[0])<<8 | uint16(buf[1])

		extensions = append(extensions, extId)
	}

	if !keepOriginalOrder {
		sortUint16(extensions)
	}
	j.Extensions = extensions
	return nil
}

func (j *JA4Fingerprint) unmarshalSignatureAlgorithm(chs *utls.ClientHelloSpec) {
	var algo []uint16
	for _, e := range chs.Extensions {
		if sae, ok := e.(*utls.SignatureAlgorithmsExtension); ok {
			for _, a := range sae.SupportedSignatureAlgorithms {
				algo = append(algo, uint16(a))
			}
		}
	}
	j.SignatureAlgorithms = algo
}
