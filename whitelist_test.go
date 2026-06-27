package ipwhitelist

import (
	"net"
	"net/http"
	"net/http/httptest"
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

func TestParseTrustedProxies(t *testing.T) {
	subnets, err := ParseTrustedProxies("10.0.0.1, 192.168.0.0/16")
	require.NoError(t, err)
	require.Len(t, subnets, 2)

	require.True(t, ipInSubnets(net.ParseIP("10.0.0.1"), subnets))
	require.False(t, ipInSubnets(net.ParseIP("10.0.0.2"), subnets))
	require.True(t, ipInSubnets(net.ParseIP("192.168.5.5"), subnets))

	empty, err := ParseTrustedProxies("")
	require.NoError(t, err)
	require.Nil(t, empty)

	_, err = ParseTrustedProxies("not-an-ip")
	require.Error(t, err)
}

// requestWithRemote builds a request with the given peer (host:port) and headers.
func requestWithRemote(remoteAddr string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remoteAddr
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestGetClientIP_IgnoresSpoofedHeaders(t *testing.T) {
	// Default GetClientIP must never trust forwarding headers.
	r := requestWithRemote("203.0.113.7:51234", map[string]string{
		"X-Real-IP":       "10.0.0.1",
		"X-Forwarded-For": "10.0.0.1, 192.168.1.1",
	})

	ip, err := GetClientIP(r)
	require.NoError(t, err)
	require.Equal(t, "203.0.113.7", ip, "spoofed headers must be ignored; connection peer wins")
}

func TestGetClientIP_RemoteAddrWithoutPort(t *testing.T) {
	r := requestWithRemote("203.0.113.7", nil)
	ip, err := GetClientIP(r)
	require.NoError(t, err)
	require.Equal(t, "203.0.113.7", ip)
}

func TestGetClientIP_InvalidRemoteAddr(t *testing.T) {
	r := requestWithRemote("not-an-ip", nil)
	_, err := GetClientIP(r)
	require.Error(t, err)
}

func TestGetClientIPTrusting_UntrustedPeerIgnoresHeaders(t *testing.T) {
	trusted, err := ParseTrustedProxies("10.0.0.0/8")
	require.NoError(t, err)

	// Peer is NOT a trusted proxy -> headers ignored, peer is the client.
	r := requestWithRemote("203.0.113.7:9999", map[string]string{
		"X-Real-IP":       "10.0.0.1",
		"X-Forwarded-For": "10.0.0.1",
	})

	ip, err := GetClientIPTrusting(r, trusted)
	require.NoError(t, err)
	require.Equal(t, "203.0.113.7", ip)
}

func TestGetClientIPTrusting_TrustedPeerUsesXFFRightmostUntrusted(t *testing.T) {
	trusted, err := ParseTrustedProxies("10.0.0.0/8")
	require.NoError(t, err)

	// Peer is a trusted proxy. XFF: client, then two of our own proxies.
	// We must walk from the right, skip the trusted hops, and pick 198.51.100.23.
	r := requestWithRemote("10.0.0.5:443", map[string]string{
		"X-Forwarded-For": "198.51.100.23, 10.0.0.9, 10.0.0.5",
	})

	ip, err := GetClientIPTrusting(r, trusted)
	require.NoError(t, err)
	require.Equal(t, "198.51.100.23", ip)
}

func TestGetClientIPTrusting_TrustedPeerStopsAtSpoofedEntry(t *testing.T) {
	trusted, err := ParseTrustedProxies("10.0.0.0/8")
	require.NoError(t, err)

	// Attacker prepends a spoofed whitelisted IP, then the genuine right-most
	// untrusted hop is the attacker's real address. We must return the
	// right-most untrusted entry (the attacker), NOT the spoofed left entry.
	r := requestWithRemote("10.0.0.5:443", map[string]string{
		"X-Forwarded-For": "192.168.1.1, 203.0.113.99, 10.0.0.5",
	})

	ip, err := GetClientIPTrusting(r, trusted)
	require.NoError(t, err)
	require.Equal(t, "203.0.113.99", ip, "must not honor a left-side spoofed entry")
}

func TestGetClientIPTrusting_TrustedPeerFallsBackToXRealIP(t *testing.T) {
	trusted, err := ParseTrustedProxies("10.0.0.0/8")
	require.NoError(t, err)

	r := requestWithRemote("10.0.0.5:443", map[string]string{
		"X-Real-IP": "198.51.100.50",
	})

	ip, err := GetClientIPTrusting(r, trusted)
	require.NoError(t, err)
	require.Equal(t, "198.51.100.50", ip)
}

func TestGetClientIPTrusting_TrustedPeerNoHeadersFallsBackToPeer(t *testing.T) {
	trusted, err := ParseTrustedProxies("10.0.0.0/8")
	require.NoError(t, err)

	r := requestWithRemote("10.0.0.5:443", nil)
	ip, err := GetClientIPTrusting(r, trusted)
	require.NoError(t, err)
	require.Equal(t, "10.0.0.5", ip)
}

// serve runs the middleware around a sentinel handler and returns the response.
func serve(mw func(http.Handler) http.Handler, r *http.Request) *httptest.ResponseRecorder {
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestIPWhitelist_SpoofedHeaderRejected(t *testing.T) {
	whitelist, subnets, err := ParseIPs("10.0.0.1,10.19.0.0/16")
	require.NoError(t, err)

	mw := IPWhitelist(whitelist, subnets)

	// Attacker from an untrusted source spoofs a whitelisted IP via headers.
	r := requestWithRemote("203.0.113.7:51234", map[string]string{
		"X-Real-IP":       "10.0.0.1",
		"X-Forwarded-For": "10.19.0.50",
	})

	rec := serve(mw, r)
	require.Equal(t, http.StatusForbidden, rec.Code, "spoofed header must not bypass the allowlist")
	require.Contains(t, rec.Body.String(), "203.0.113.7")
}

func TestIPWhitelist_GenuineConnectionAllowed(t *testing.T) {
	whitelist, subnets, err := ParseIPs("10.0.0.1,10.19.0.0/16")
	require.NoError(t, err)

	mw := IPWhitelist(whitelist, subnets)

	// Exact match on the connection peer.
	rec := serve(mw, requestWithRemote("10.0.0.1:5555", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	// Subnet match on the connection peer.
	rec = serve(mw, requestWithRemote("10.19.0.42:5555", nil))
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestIPWhitelist_NonWhitelistedConnectionDenied(t *testing.T) {
	whitelist, subnets, err := ParseIPs("10.0.0.1,10.19.0.0/16")
	require.NoError(t, err)

	mw := IPWhitelist(whitelist, subnets)

	rec := serve(mw, requestWithRemote("203.0.113.7:5555", nil))
	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestIPWhitelistTrusting_HonorsHeaderOnlyFromTrustedProxy(t *testing.T) {
	whitelist, subnets, err := ParseIPs("198.51.100.0/24")
	require.NoError(t, err)

	trusted, err := ParseTrustedProxies("10.0.0.0/8")
	require.NoError(t, err)

	mw := IPWhitelistTrusting(whitelist, subnets, trusted)

	// From a trusted proxy: the forwarded client (in the whitelist) is allowed.
	r := requestWithRemote("10.0.0.5:443", map[string]string{
		"X-Forwarded-For": "198.51.100.77, 10.0.0.5",
	})
	require.Equal(t, http.StatusOK, serve(mw, r).Code)

	// Same headers from an UNtrusted peer: header ignored, peer denied.
	r = requestWithRemote("203.0.113.7:443", map[string]string{
		"X-Forwarded-For": "198.51.100.77, 10.0.0.5",
	})
	require.Equal(t, http.StatusForbidden, serve(mw, r).Code)

	// From a trusted proxy but forwarded client NOT in whitelist: denied.
	r = requestWithRemote("10.0.0.5:443", map[string]string{
		"X-Forwarded-For": "203.0.113.99, 10.0.0.5",
	})
	require.Equal(t, http.StatusForbidden, serve(mw, r).Code)
}
