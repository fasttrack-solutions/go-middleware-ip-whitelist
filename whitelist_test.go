package ipwhitelist

import (
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseIPs(t *testing.T) {
	ip := "120.110.1.1"
	ips := ip + ",10.19.0.0/16"

	lookup, subnets, err := ParseIPs(ips)
	require.NoError(t, err)

	require.Len(t, lookup, 1)
	require.Len(t, subnets, 1)

	require.True(t, lookup[ip])
	require.False(t, lookup["99.1.1.1"])

	subnet := subnets[0]

	validIP := net.ParseIP("10.19.0.5")
	require.True(t, subnet.Contains(validIP))

	invalidIP := net.ParseIP("127.0.0.1")
	require.False(t, subnet.Contains(invalidIP))
}

func TestGetClientIPUsesCFConnectingIP(t *testing.T) {
	r := &http.Request{
		Header:     http.Header{},
		RemoteAddr: "10.0.0.1:12345",
	}
	r.Header.Set("CF-Connecting-IP", "203.0.113.5")

	ip, err := GetClientIP(r)
	require.NoError(t, err)
	require.Equal(t, "203.0.113.5", ip)
}

func TestGetClientIPCFTakesPrecedence(t *testing.T) {
	r := &http.Request{
		Header:     http.Header{},
		RemoteAddr: "10.0.0.1:12345",
	}
	// CF-Connecting-IP must win over any (spoofable) X-Real-IP / X-Forwarded-For.
	r.Header.Set("CF-Connecting-IP", "203.0.113.5")
	r.Header.Set("X-REAL-IP", "198.51.100.7")
	r.Header.Set("X-FORWARDED-FOR", "198.51.100.8")

	ip, err := GetClientIP(r)
	require.NoError(t, err)
	require.Equal(t, "203.0.113.5", ip)
}

func TestGetClientIPFallsBackToXRealIP(t *testing.T) {
	r := &http.Request{
		Header:     http.Header{},
		RemoteAddr: "10.0.0.1:12345",
	}
	// No CF-Connecting-IP: X-Real-IP is used, preferred over X-Forwarded-For.
	r.Header.Set("X-REAL-IP", "198.51.100.7")
	r.Header.Set("X-FORWARDED-FOR", "198.51.100.8")

	ip, err := GetClientIP(r)
	require.NoError(t, err)
	require.Equal(t, "198.51.100.7", ip)
}

func TestGetClientIPFallsBackToXForwardedFor(t *testing.T) {
	r := &http.Request{
		Header:     http.Header{},
		RemoteAddr: "10.0.0.1:12345",
	}
	// No CF-Connecting-IP and no X-Real-IP: first valid X-Forwarded-For entry wins.
	r.Header.Set("X-FORWARDED-FOR", "198.51.100.8,203.0.113.9")

	ip, err := GetClientIP(r)
	require.NoError(t, err)
	require.Equal(t, "198.51.100.8", ip)
}

func TestSubnetContainsIP(t *testing.T) {
	ip1 := "10.19.0.100"
	ip2 := "120.20.20.10"
	invalidIP := "500.0.0.1"
	cidrs := "10.19.0.0/16,120.20.0.0/8"

	_, subnets, err := ParseIPs(cidrs)
	require.NoError(t, err)

	require.True(t, subnetContainsIP(ip1, subnets))
	require.True(t, subnetContainsIP(ip2, subnets))
	require.False(t, subnetContainsIP(invalidIP, subnets))
}
