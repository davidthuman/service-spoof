package fingerprint

import (
	"crypto/tls"
	"testing"
)

func TestFilterGREASE(t *testing.T) {
	tests := []struct {
		name     string
		input    []uint16
		expected []uint16
	}{
		{
			name:     "empty slice",
			input:    []uint16{},
			expected: []uint16{},
		},
		{
			name:     "no GREASE values",
			input:    []uint16{0x1301, 0x1302, 0x1303},
			expected: []uint16{0x1301, 0x1302, 0x1303},
		},
		{
			name:     "all GREASE values",
			input:    []uint16{0x0A0A, 0x1A1A, 0x2A2A},
			expected: []uint16{},
		},
		{
			name:     "mixed values",
			input:    []uint16{0x0A0A, 0x1301, 0x1A1A, 0x1302},
			expected: []uint16{0x1301, 0x1302},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterGREASE(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("filterGREASE() length = %d, want %d", len(result), len(tt.expected))
				return
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("filterGREASE()[%d] = %x, want %x", i, result[i], tt.expected[i])
				}
			}
		})
	}
}

func TestMapTLSVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  uint16
		expected string
	}{
		{"TLS 1.3", 0x0304, "13"},
		{"TLS 1.2", 0x0303, "12"},
		{"TLS 1.1", 0x0302, "11"},
		{"TLS 1.0", 0x0301, "10"},
		{"SSL 3.0", 0x0300, "s3"},
		{"DTLS 1.0", 0xfeff, "d1"},
		{"DTLS 1.2", 0xfefd, "d2"},
		{"Unknown", 0x9999, "00"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapTLSVersion(tt.version)
			if result != tt.expected {
				t.Errorf("mapTLSVersion(%x) = %s, want %s", tt.version, result, tt.expected)
			}
		})
	}
}

func TestDetectSNIType(t *testing.T) {
	tests := []struct {
		name       string
		serverName string
		expected   string
	}{
		{"empty", "", "i"},
		{"domain", "example.com", "d"},
		{"IPv4", "192.168.1.1", "i"},
		{"IPv6", "2001:0db8:85a3::8a2e:0370:7334", "i"},
		{"subdomain", "www.example.com", "d"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectSNIType(tt.serverName)
			if result != tt.expected {
				t.Errorf("detectSNIType(%s) = %s, want %s", tt.serverName, result, tt.expected)
			}
		})
	}
}

func TestExtractALPN(t *testing.T) {
	tests := []struct {
		name      string
		protocols []string
		expected  string
	}{
		{"empty", []string{}, "00"},
		{"h2", []string{"h2"}, "h2"},
		{"http/1.1", []string{"http/1.1"}, "h1"},
		{"multiple", []string{"h2", "http/1.1"}, "h2"},
		{"single char", []string{"x"}, "xx"},
		{"alphanumeric extraction", []string{"h2c"}, "hc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractALPN(tt.protocols)
			if result != tt.expected {
				t.Errorf("extractALPN(%v) = %s, want %s", tt.protocols, result, tt.expected)
			}
		})
	}
}

func TestTruncatedSHA256(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int // length
	}{
		{"empty", "", 12},
		{"short", "abc", 12},
		{"normal", "1234567890abcdef", 12},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncatedSHA256(tt.input)
			if len(result) != tt.expected {
				t.Errorf("truncatedSHA256(%s) length = %d, want %d", tt.input, len(result), tt.expected)
			}
			// Verify it's valid hex
			for _, c := range result {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					t.Errorf("truncatedSHA256(%s) contains invalid hex char: %c", tt.input, c)
				}
			}
		})
	}
}

func TestGenerateJA4_NilInput(t *testing.T) {
	result := GenerateJA4(nil)
	if result.Raw != "" {
		t.Errorf("GenerateJA4(nil) should return empty fingerprint, got %s", result.Raw)
	}
}

func TestGenerateJA4_BasicFingerprint(t *testing.T) {
	hello := &tls.ClientHelloInfo{
		ServerName: "example.com",
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		SupportedVersions: []uint16{tls.VersionTLS13},
		SupportedProtos:   []string{"h2", "http/1.1"},
		SignatureSchemes: []tls.SignatureScheme{
			tls.ECDSAWithP256AndSHA256,
			tls.ECDSAWithP384AndSHA384,
		},
		SupportedCurves: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
	}

	result := GenerateJA4(hello)

	// Verify structure
	parts := len(result.Raw)
	if parts == 0 {
		t.Error("GenerateJA4() returned empty fingerprint")
	}

	// Verify format: partA_partB_partC
	if len(result.PartA) == 0 || len(result.PartB) != 12 || len(result.PartC) != 12 {
		t.Errorf("GenerateJA4() invalid format: PartA=%s, PartB=%s, PartC=%s",
			result.PartA, result.PartB, result.PartC)
	}

	// Verify TLS version
	if result.TLSVersion != "13" {
		t.Errorf("GenerateJA4() TLSVersion = %s, want 13", result.TLSVersion)
	}

	// Verify SNI
	if result.SNI != "example.com" {
		t.Errorf("GenerateJA4() SNI = %s, want example.com", result.SNI)
	}

	// Verify ALPN
	if result.ALPN != "h2,http/1.1" {
		t.Errorf("GenerateJA4() ALPN = %s, want h2,http/1.1", result.ALPN)
	}

	// Verify cipher count
	if result.CipherCount != 3 {
		t.Errorf("GenerateJA4() CipherCount = %d, want 3", result.CipherCount)
	}
}

func TestGenerateJA4_WithGREASE(t *testing.T) {
	hello := &tls.ClientHelloInfo{
		ServerName: "example.com",
		CipherSuites: []uint16{
			0x0A0A, // GREASE
			tls.TLS_AES_128_GCM_SHA256,
			0x1A1A, // GREASE
			tls.TLS_AES_256_GCM_SHA384,
		},
		SupportedVersions: []uint16{
			0x0A0A, // GREASE
			tls.VersionTLS13,
		},
	}

	result := GenerateJA4(hello)

	// Should filter out GREASE values
	if result.CipherCount != 2 {
		t.Errorf("GenerateJA4() with GREASE: CipherCount = %d, want 2", result.CipherCount)
	}
}

func TestJA4Fingerprint_String(t *testing.T) {
	fp := &JA4Fingerprint{
		Raw:            "t13d0305h2_abc123456789_def123456789",
		PartA:          "t13d0305h2",
		PartB:          "abc123456789",
		PartC:          "def123456789",
		TLSVersion:     "13",
		CipherCount:    3,
		ExtensionCount: 5,
		SNI:            "example.com",
		ALPN:           "h2",
	}

	result := fp.String()
	if len(result) == 0 {
		t.Error("String() returned empty string")
	}
	if result[:4] != "JA4:" {
		t.Errorf("String() should start with 'JA4:', got %s", result[:4])
	}
}

func TestJA4Fingerprint_String_Empty(t *testing.T) {
	fp := &JA4Fingerprint{Raw: ""}
	result := fp.String()
	if result != "JA4: (empty)" {
		t.Errorf("String() for empty fingerprint = %s, want 'JA4: (empty)'", result)
	}
}
