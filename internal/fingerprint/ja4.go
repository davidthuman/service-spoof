package fingerprint

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// GREASE values per RFC 8701
var greaseValues = map[uint16]bool{
	0x0A0A: true, 0x1A1A: true, 0x2A2A: true, 0x3A3A: true,
	0x4A4A: true, 0x5A5A: true, 0x6A6A: true, 0x7A7A: true,
	0x8A8A: true, 0x9A9A: true, 0xAAAA: true, 0xBABA: true,
	0xCACA: true, 0xDADA: true, 0xEAEA: true, 0xFAFA: true,
}

// JA4Fingerprint represents a complete JA4 fingerprint
type JA4Fingerprint struct {
	Raw            string
	PartA          string
	PartB          string
	PartC          string
	TLSVersion     string
	CipherCount    int
	ExtensionCount int
	SNI            string
	ALPN           string
}

// GenerateJA4 creates a JA4 fingerprint from ClientHelloInfo
func GenerateJA4(hello *tls.ClientHelloInfo) *JA4Fingerprint {
	if hello == nil {
		return &JA4Fingerprint{Raw: ""}
	}

	// Part A: Metadata
	protocol := "t" // TCP/TLS (could be "q" for QUIC, "d" for DTLS)
	version := getTLSVersion(hello)
	sniType := detectSNIType(hello.ServerName)

	ciphers := filterGREASE(hello.CipherSuites)
	cipherCount := len(ciphers)

	// Count extensions (approximate based on available fields)
	extCount := countExtensions(hello)

	alpn := extractALPN(hello.SupportedProtos)

	partA := fmt.Sprintf("%s%s%s%02d%02d%s",
		protocol, version, sniType, cipherCount, extCount, alpn)

	// Part B: Cipher hash
	partB := hashCiphers(ciphers)

	// Part C: Extension hash
	partC := hashExtensions(hello)

	fingerprint := fmt.Sprintf("%s_%s_%s", partA, partB, partC)

	return &JA4Fingerprint{
		Raw:            fingerprint,
		PartA:          partA,
		PartB:          partB,
		PartC:          partC,
		TLSVersion:     version,
		CipherCount:    cipherCount,
		ExtensionCount: extCount,
		SNI:            hello.ServerName,
		ALPN:           strings.Join(hello.SupportedProtos, ","),
	}
}

// filterGREASE removes GREASE values from a uint16 slice
func filterGREASE(values []uint16) []uint16 {
	result := make([]uint16, 0, len(values))
	for _, v := range values {
		if !greaseValues[v] {
			result = append(result, v)
		}
	}
	return result
}

// getTLSVersion extracts TLS version (prefer SupportedVersions extension)
func getTLSVersion(hello *tls.ClientHelloInfo) string {
	// Use SupportedVersions extension if available (TLS 1.3 clients)
	if len(hello.SupportedVersions) > 0 {
		// Filter GREASE and get highest version
		versions := filterGREASE(hello.SupportedVersions)
		if len(versions) > 0 {
			// Take first (highest priority)
			return mapTLSVersion(versions[0])
		}
	}

	// Fallback: Return TLS 1.3 as default (most common modern version)
	return "13"
}

// mapTLSVersion converts version code to JA4 format
func mapTLSVersion(version uint16) string {
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
	case 0xfeff:
		return "d1" // DTLS 1.0
	case 0xfefd:
		return "d2" // DTLS 1.2
	default:
		return "00"
	}
}

// detectSNIType determines if SNI is a domain or IP
func detectSNIType(serverName string) string {
	if serverName == "" {
		return "i"
	}
	// Check if it's an IP address
	if net.ParseIP(serverName) != nil {
		return "i"
	}
	return "d"
}

// extractALPN gets first and last char of first ALPN protocol
func extractALPN(protocols []string) string {
	if len(protocols) == 0 {
		return "00"
	}

	first := protocols[0]
	if len(first) == 0 {
		return "00"
	}

	// Extract alphanumeric characters only
	alphanumeric := extractAlphanumeric(first)
	if len(alphanumeric) == 0 {
		return "00"
	}
	if len(alphanumeric) == 1 {
		return string(alphanumeric[0]) + string(alphanumeric[0])
	}

	return string(alphanumeric[0]) + string(alphanumeric[len(alphanumeric)-1])
}

// extractAlphanumeric returns only alphanumeric characters
func extractAlphanumeric(s string) string {
	result := ""
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			result += string(c)
		}
	}
	return result
}

// countExtensions estimates extension count from available fields
func countExtensions(hello *tls.ClientHelloInfo) int {
	count := 0

	if hello.ServerName != "" {
		count++ // SNI (0x0000)
	}
	if len(hello.SupportedProtos) > 0 {
		count++ // ALPN (0x0010)
	}
	if len(hello.SupportedVersions) > 0 {
		count++ // supported_versions (0x002b)
	}
	if len(hello.SupportedCurves) > 0 {
		count++ // supported_groups (0x000a)
	}
	if len(hello.SupportedPoints) > 0 {
		count++ // ec_point_formats (0x000b)
	}
	if len(hello.SignatureSchemes) > 0 {
		count++ // signature_algorithms (0x000d)
	}

	// Note: This is an approximation. Full implementation would parse raw extensions.
	// Common extensions we're missing: session_ticket, status_request, etc.

	return count
}

// hashCiphers creates Part B (sorted cipher hash)
func hashCiphers(ciphers []uint16) string {
	if len(ciphers) == 0 {
		return "000000000000"
	}

	// Convert to hex strings
	hexCiphers := make([]string, len(ciphers))
	for i, c := range ciphers {
		hexCiphers[i] = fmt.Sprintf("%04x", c)
	}

	// Sort
	sort.Strings(hexCiphers)

	// Join with comma
	joined := strings.Join(hexCiphers, ",")

	// SHA256 and truncate
	return truncatedSHA256(joined)
}

// hashExtensions creates Part C (sorted extensions + signature algorithms)
func hashExtensions(hello *tls.ClientHelloInfo) string {
	// Build extension list (approximate)
	extensions := []string{}

	// Note: We can't get all extensions without raw parsing
	// Build list from available fields

	if len(hello.SupportedVersions) > 0 {
		extensions = append(extensions, "002b") // supported_versions
	}
	if len(hello.SupportedCurves) > 0 {
		extensions = append(extensions, "000a") // supported_groups
	}
	if len(hello.SupportedPoints) > 0 {
		extensions = append(extensions, "000b") // ec_point_formats
	}
	if len(hello.SignatureSchemes) > 0 {
		extensions = append(extensions, "000d") // signature_algorithms
	}

	// Note: Excluding SNI (0000) and ALPN (0010) per JA4 spec
	// If we had full extension list, we'd filter them here

	// Sort extensions
	sort.Strings(extensions)
	extString := strings.Join(extensions, ",")

	// Add signature algorithms (in original order, not sorted)
	sigAlgs := make([]string, 0, len(hello.SignatureSchemes))
	for _, sig := range hello.SignatureSchemes {
		sigAlgs = append(sigAlgs, fmt.Sprintf("%04x", uint16(sig)))
	}
	sigString := strings.Join(sigAlgs, ",")

	// Combine with underscore
	combined := extString
	if sigString != "" {
		if combined != "" {
			combined += "_"
		}
		combined += sigString
	}

	return truncatedSHA256(combined)
}

// truncatedSHA256 returns first 12 characters of SHA256 hash
func truncatedSHA256(input string) string {
	if input == "" {
		return "000000000000"
	}

	hash := sha256.Sum256([]byte(input))
	hexHash := hex.EncodeToString(hash[:])

	if len(hexHash) < 12 {
		return hexHash + strings.Repeat("0", 12-len(hexHash))
	}

	return hexHash[:12]
}

// String returns a human-readable representation of the JA4 fingerprint
func (fp *JA4Fingerprint) String() string {
	if fp.Raw == "" {
		return "JA4: (empty)"
	}

	var sb strings.Builder
	sb.WriteString("JA4: ")
	sb.WriteString(fp.Raw)
	sb.WriteString("\n")
	sb.WriteString("  Part A: ")
	sb.WriteString(fp.PartA)
	sb.WriteString(" (TLS ")
	sb.WriteString(fp.TLSVersion)
	sb.WriteString(", ")
	sb.WriteString(strconv.Itoa(fp.CipherCount))
	sb.WriteString(" ciphers, ")
	sb.WriteString(strconv.Itoa(fp.ExtensionCount))
	sb.WriteString(" extensions)")
	sb.WriteString("\n")
	sb.WriteString("  Part B: ")
	sb.WriteString(fp.PartB)
	sb.WriteString(" (cipher hash)")
	sb.WriteString("\n")
	sb.WriteString("  Part C: ")
	sb.WriteString(fp.PartC)
	sb.WriteString(" (extension hash)")

	if fp.SNI != "" {
		sb.WriteString("\n")
		sb.WriteString("  SNI: ")
		sb.WriteString(fp.SNI)
	}
	if fp.ALPN != "" {
		sb.WriteString("\n")
		sb.WriteString("  ALPN: ")
		sb.WriteString(fp.ALPN)
	}

	return sb.String()
}
