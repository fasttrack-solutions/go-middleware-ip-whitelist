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

// IPWhitelist takes a list of IPs and checks incoming requests for matches.
func IPWhitelist(whitelist map[string]bool) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			ip, _ := clientIP(r)

			if !whitelist[ip] {
				msg := fmt.Sprintf("Client IP %s denied", ip)
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(msg))
				return
			}

			h.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
