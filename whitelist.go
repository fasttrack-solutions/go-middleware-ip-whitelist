package ipwhitelist

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// GetClientIP returns the client IP derived solely from the connection peer
// (r.RemoteAddr). It deliberately ignores client-supplied forwarding headers
// (X-Real-IP / X-Forwarded-For) because those are attacker controlled and
// trusting them allows an allowlist bypass. Use GetClientIPTrusting when the
// service is deployed behind a known, trusted reverse proxy.
func GetClientIP(r *http.Request) (string, error) {
	return GetClientIPTrusting(r, nil)
}

// GetClientIPTrusting returns the real client IP.
//
// By default it uses the connection peer (r.RemoteAddr), which is the only
// trustworthy source. Forwarding headers (X-Real-IP / X-Forwarded-For) are
// honored ONLY when the immediate peer (r.RemoteAddr) is itself one of the
// configured trustedProxies. This prevents a direct-to-origin attacker from
// spoofing a whitelisted IP via a header.
//
// When the peer is trusted, X-Forwarded-For is parsed from the right (closest
// hop) towards the left, skipping any addresses that are themselves trusted
// proxies, and returns the right-most untrusted address. If X-Forwarded-For
// yields nothing usable, X-Real-IP is consulted (only from a trusted peer).
func GetClientIPTrusting(r *http.Request, trustedProxies []*net.IPNet) (string, error) {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr may not always carry a port; fall back to the raw value.
		peer = r.RemoteAddr
	}

	peerIP := net.ParseIP(peer)
	if peerIP == nil {
		return "", fmt.Errorf("no valid ip found")
	}

	// Only consider forwarding headers when the request actually arrived from a
	// configured trusted proxy. Otherwise the headers are untrusted and the
	// connection peer is the client.
	if !ipInSubnets(peerIP, trustedProxies) {
		return peerIP.String(), nil
	}

	if clientIP, ok := clientIPFromXFF(r.Header.Get("X-Forwarded-For"), trustedProxies); ok {
		return clientIP, nil
	}

	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		if parsed := net.ParseIP(realIP); parsed != nil {
			return parsed.String(), nil
		}
	}

	// Trusted peer but no usable forwarded address: fall back to the peer.
	return peerIP.String(), nil
}

// clientIPFromXFF parses an X-Forwarded-For header value and returns the
// right-most address that is NOT itself a trusted proxy. The right-most entry
// is the hop closest to our trusted proxy and is the least forgeable; walking
// leftwards past trusted proxies yields the first untrusted client. Entries to
// the left of the first untrusted hop are attacker-influenced and ignored.
func clientIPFromXFF(header string, trustedProxies []*net.IPNet) (string, bool) {
	if header == "" {
		return "", false
	}

	parts := strings.Split(header, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(parts[i])
		ip := net.ParseIP(candidate)
		if ip == nil {
			// A malformed entry breaks the chain of trust; stop walking.
			return "", false
		}

		if ipInSubnets(ip, trustedProxies) {
			// This hop is one of our own proxies; keep walking left.
			continue
		}

		return ip.String(), true
	}

	return "", false
}

func ipInSubnets(ip net.IP, subnets []*net.IPNet) bool {
	for _, subnet := range subnets {
		if subnet != nil && subnet.Contains(ip) {
			return true
		}
	}

	return false
}

func subnetContainsIP(ip string, subnets []*net.IPNet) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	return ipInSubnets(parsedIP, subnets)
}

// ParseIPs takes a list of IPs and checks for CIDR notation
// it returns a map and a slice of subnets
func ParseIPs(list string) (map[string]bool, []*net.IPNet, error) {
	if len(list) == 0 {
		return nil, nil, nil
	}

	ips := strings.Split(list, ",")

	subnets := []*net.IPNet{}
	lookup := make(map[string]bool, len(ips))

	for _, ip := range ips {
		if strings.Contains(ip, "/") {
			_, subnet, err := net.ParseCIDR(ip)
			if err != nil {
				return nil, nil, err
			}

			subnets = append(subnets, subnet)
			continue
		}

		validIP := net.ParseIP(ip)
		if validIP == nil {
			return nil, nil, fmt.Errorf("invalid IP provided: %s", ip)
		}

		lookup[ip] = true
	}

	return lookup, subnets, nil
}

// ParseTrustedProxies parses a comma-separated list of trusted proxy addresses
// or CIDR ranges into subnets. A bare IP is treated as a /32 (IPv4) or /128
// (IPv6). Use the returned slice with IPWhitelistTrusting / GetClientIPTrusting
// so forwarding headers are only honored from these peers.
func ParseTrustedProxies(list string) ([]*net.IPNet, error) {
	list = strings.TrimSpace(list)
	if len(list) == 0 {
		return nil, nil
	}

	parts := strings.Split(list, ",")
	subnets := make([]*net.IPNet, 0, len(parts))

	for _, raw := range parts {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}

		if strings.Contains(entry, "/") {
			_, subnet, err := net.ParseCIDR(entry)
			if err != nil {
				return nil, err
			}

			subnets = append(subnets, subnet)
			continue
		}

		ip := net.ParseIP(entry)
		if ip == nil {
			return nil, fmt.Errorf("invalid trusted proxy provided: %s", entry)
		}

		bits := 32
		if ip.To4() == nil {
			bits = 128
		}

		subnets = append(subnets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}

	return subnets, nil
}

// IPWhitelist takes a list of IPs and checks incoming requests for matches.
//
// It derives the client IP from the connection peer only and does NOT trust
// forwarding headers. Use IPWhitelistTrusting if the service is fronted by a
// known, trusted reverse proxy.
func IPWhitelist(whitelist map[string]bool, subnets []*net.IPNet) func(http.Handler) http.Handler {
	return IPWhitelistTrusting(whitelist, subnets, nil)
}

// IPWhitelistTrusting behaves like IPWhitelist but additionally trusts
// forwarding headers when the request arrives from one of trustedProxies.
// Pass a nil/empty trustedProxies to keep header trust disabled (safe default).
func IPWhitelistTrusting(whitelist map[string]bool, subnets []*net.IPNet, trustedProxies []*net.IPNet) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			ip, err := GetClientIPTrusting(r, trustedProxies)
			if err != nil || (!whitelist[ip] && !subnetContainsIP(ip, subnets)) {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(fmt.Sprintf("Client IP %s denied", ip)))
				return
			}

			h.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
