package policyreason

import (
	"fmt"
	"strings"
	"unicode"
)

// Rule contains the supported policy matchers. Build appends populated fields
// in this fixed order: APN, QCI, ARP, bearer type, idle timeout.
type Rule struct {
	APN            string
	QCI            uint8
	ARPPriorityMin uint8
	ARPPriorityMax uint8
	BearerType     string
	IdleSeconds    int
}

func Build(feature, action string, rule Rule) string {
	parts := []string{sanitize(feature), sanitize(action)}
	if value := sanitize(rule.APN); value != "" {
		parts = append(parts, "apn", value)
	}
	if rule.QCI != 0 {
		parts = append(parts, "qci", fmt.Sprint(rule.QCI))
	}
	if rule.ARPPriorityMin != 0 || rule.ARPPriorityMax != 0 {
		parts = append(parts, "arp")
		if rule.ARPPriorityMin != 0 {
			parts = append(parts, fmt.Sprint(rule.ARPPriorityMin))
		}
		if rule.ARPPriorityMax != 0 {
			parts = append(parts, fmt.Sprint(rule.ARPPriorityMax))
		}
	}
	if value := sanitize(rule.BearerType); value != "" {
		parts = append(parts, value)
	}
	if rule.IdleSeconds != 0 {
		parts = append(parts, "idle", fmt.Sprint(rule.IdleSeconds))
	}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			out = append(out, part)
		}
	}
	return strings.Join(out, "-")
}

func sanitize(value string) string {
	var b strings.Builder
	separator := false
	for _, r := range strings.ToLower(value) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			separator = false
			continue
		}
		if b.Len() > 0 && !separator {
			b.WriteByte('-')
			separator = true
		}
	}
	return strings.Trim(b.String(), "-")
}
