package validate

import (
	"encoding/json"
	"errors"
	"net"
	"strings"
)

func NormalizeDomain(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}

func TTL(ttl, min, max int) error {
	if ttl < min || ttl > max {
		return errors.New("ttl out of range")
	}
	return nil
}

func AData(data string) error {
	var p map[string]any
	if err := json.Unmarshal([]byte(data), &p); err != nil {
		return err
	}
	mode, _ := p["mode"].(string)
	if mode == "SINGLE" {
		ip, _ := p["ip"].(string)
		if net.ParseIP(ip) == nil || strings.Contains(ip, ":") {
			return errors.New("invalid ipv4")
		}
		return nil
	}
	if mode == "GEO" {
		i, _ := p["iran_ip"].(string)
		f, _ := p["foreign_ip"].(string)
		if net.ParseIP(i) == nil || strings.Contains(i, ":") || net.ParseIP(f) == nil || strings.Contains(f, ":") {
			return errors.New("invalid geo ipv4")
		}
		return nil
	}
	return errors.New("unknown a mode")
}
