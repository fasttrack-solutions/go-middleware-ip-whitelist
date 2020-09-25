package ipwhitelist

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

func clientIP(r *http.Request) (string, error) {
	ip := r.Header.Get("X-REAL-IP")
	netIP := net.ParseIP(ip)
	if netIP != nil {
		return ip, nil
	}

	ips := r.Header.Get("X-FORWARDED-FOR")
	splitIps := strings.Split(ips, ",")
	for _, ip := range splitIps {
		netIP := net.ParseIP(ip)
		if netIP != nil {
			return ip, nil
		}
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", err
	}

	netIP = net.ParseIP(ip)
	if netIP != nil {
		return ip, nil
	}

	return "", fmt.Errorf("No valid ip found")
}

func subnetContainsIP(ip string, subnets []*net.IPNet) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, subnet := range subnets {
		if subnet.Contains(parsedIP) {
			return true
		}
	}

	return false
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

// IPWhitelist takes a list of IPs and checks incoming requests for matches.
func IPWhitelist(whitelist map[string]bool, subnets []*net.IPNet) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			ip, _ := clientIP(r)

			if !whitelist[ip] && !subnetContainsIP(ip, subnets) {
				msg := fmt.Sprintf("Client IP %s denied", ip)
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(msg))
				return
			}

			h.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
