package jshunter

import (
	"net"
	"strconv"
	"strings"
)

// normalizeNumericHost decodes the non-standard IPv4 encodings that net.ParseIP
// rejects but the C resolver (inet_aton, used by the OS dialer) accepts, so the
// SSRF guard can catch them. Covered forms:
//
//	decimal      2130706433        -> 127.0.0.1
//	hex          0x7f000001        -> 127.0.0.1
//	octal parts  0177.0.0.01       -> 127.0.0.1
//	short forms  127.1 / 127.0.1   -> 127.0.0.1 / 127.0.0.1
//
// It returns the equivalent net.IP, or nil when host is a normal hostname or a
// value net.ParseIP already handles. No DNS lookup is performed, so the guard
// stays a deterministic, offline, unit-testable string check.
func normalizeNumericHost(host string) net.IP {
	if host == "" {
		return nil
	}
	parts := strings.Split(host, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return nil
	}
	vals := make([]uint64, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			return nil
		}
		// base 0: 0x -> hex, leading 0 -> octal, otherwise decimal. This mirrors
		// inet_aton's per-segment parsing. A segment containing a DNS letter
		// fails to parse, so real hostnames fall through to a nil return.
		v, err := strconv.ParseUint(p, 0, 64)
		if err != nil {
			return nil
		}
		vals = append(vals, v)
	}

	var n uint64
	switch len(vals) {
	case 1: // a
		n = vals[0]
	case 2: // a.b  -> a.(24-bit b)
		if vals[0] > 0xff || vals[1] > 0xffffff {
			return nil
		}
		n = vals[0]<<24 | vals[1]
	case 3: // a.b.c -> a.b.(16-bit c)
		if vals[0] > 0xff || vals[1] > 0xff || vals[2] > 0xffff {
			return nil
		}
		n = vals[0]<<24 | vals[1]<<16 | vals[2]
	case 4: // a.b.c.d
		for _, v := range vals {
			if v > 0xff {
				return nil
			}
		}
		n = vals[0]<<24 | vals[1]<<16 | vals[2]<<8 | vals[3]
	}
	if n > 0xffffffff {
		return nil
	}

	// A plain dotted-quad (all parts <= 255, 4 parts) is already handled by
	// net.ParseIP upstream; only report the encodings that ParseIP misses so we
	// never second-guess a value the standard parser accepts.
	if len(vals) == 4 && net.ParseIP(host) != nil {
		return nil
	}

	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// isInternalIP reports whether ip falls in a range the SSRF guard blocks by
// default (loopback, RFC1918 private, link-local, or unspecified).
func isInternalIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}
