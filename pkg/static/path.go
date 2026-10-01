// SPDX-License-Identifier: AGPL-3.0-only

package static

import "strings"

// URL path rules of static-site contract §4. Every byte has exactly one
// accepted representation, so an accepted path is its own canonical form and
// lookup is an exact, case-sensitive byte comparison.

// literal reports whether b is in L: RFC 3986 unreserved, sub-delims, ":"
// and "@".
func literal(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	}
	return strings.IndexByte("-._~!$&'()*+,;=:@", b) >= 0
}

func upperHex(b byte) bool { return b >= '0' && b <= '9' || b >= 'A' && b <= 'F' }

func unhex(b byte) byte {
	if b <= '9' {
		return b - '0'
	}
	return b - 'A' + 10
}

// validRequestSegment applies §4.3 rules 3-6 to one non-empty segment.
func validRequestSegment(segment string) bool {
	if segment == "" || len(segment) > MaxSegmentBytes || segment == "." || segment == ".." {
		return false
	}
	for index := 0; index < len(segment); index++ {
		b := segment[index]
		if b != '%' {
			if !literal(b) {
				return false
			}
			continue
		}
		if index+2 >= len(segment) || !upperHex(segment[index+1]) || !upperHex(segment[index+2]) {
			return false
		}
		decoded := unhex(segment[index+1])<<4 | unhex(segment[index+2])
		if literal(decoded) || decoded == '/' || decoded == '\\' || decoded < 0x20 || decoded == 0x7f {
			return false
		}
		index += 2
	}
	return true
}

// validFileSegment applies §4.2: a request-valid segment whose only escape
// is "%20".
func validFileSegment(segment string) bool {
	if !validRequestSegment(segment) {
		return false
	}
	for index := strings.IndexByte(segment, '%'); index >= 0; index = strings.IndexByte(segment, '%') {
		if segment[index:index+3] != "%20" {
			return false
		}
		segment = segment[index+3:]
	}
	return true
}

// splitPath checks the shared whole-path rules: origin form, at most
// MaxPathBytes bytes and MaxDepth "/". It returns the segments after the
// leading "/"; the last is empty for a trailing "/".
func splitPath(raw string) ([]string, bool) {
	if raw == "" || raw[0] != '/' || len(raw) > MaxPathBytes || strings.Count(raw, "/") > MaxDepth {
		return nil, false
	}
	return strings.Split(raw[1:], "/"), true
}

// ValidFilePath reports whether path is a canonical manifest file path.
func ValidFilePath(path string) bool {
	segments, ok := splitPath(path)
	if !ok {
		return false
	}
	for _, segment := range segments {
		if !validFileSegment(segment) {
			return false
		}
	}
	return true
}

// ValidRequestPath reports whether a raw request path (the bytes before the
// first "?") passes §4.3. Only the final segment may be empty.
func ValidRequestPath(raw string) bool {
	segments, ok := splitPath(raw)
	if !ok {
		return false
	}
	for index, segment := range segments {
		if segment == "" && index == len(segments)-1 {
			continue
		}
		if !validRequestSegment(segment) {
			return false
		}
	}
	return true
}

func lastSegment(path string) string { return path[strings.LastIndexByte(path, '/')+1:] }
