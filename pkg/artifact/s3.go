// SPDX-License-Identifier: AGPL-3.0-only

package artifact

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultS3RequestTimeout = 2 * time.Minute
	DefaultS3MaxAttempts    = 3
	DefaultS3MaxObjectBytes = int64(2 << 30)

	maxS3Attempts       = 10
	maxS3ErrorBodyBytes = int64(4 << 10)
	maxS3RetryDelay     = 5 * time.Second
	defaultRetryDelay   = 200 * time.Millisecond
)

// S3ErrorKind is a stable, credential-free classification for an S3-compatible
// failure. Callers should use errors.As rather than matching provider text.
type S3ErrorKind string

const (
	S3ErrorAuthentication S3ErrorKind = "authentication"
	S3ErrorConflict       S3ErrorKind = "conflict"
	S3ErrorInvalidRequest S3ErrorKind = "invalid_request"
	S3ErrorNotFound       S3ErrorKind = "not_found"
	S3ErrorPermission     S3ErrorKind = "permission"
	S3ErrorResponseTooBig S3ErrorKind = "response_too_large"
	S3ErrorThrottled      S3ErrorKind = "throttled"
	S3ErrorTimeout        S3ErrorKind = "timeout"
	S3ErrorTransport      S3ErrorKind = "transport"
	S3ErrorUnavailable    S3ErrorKind = "unavailable"
	S3ErrorUnexpected     S3ErrorKind = "unexpected_status"
)

// S3Error deliberately omits request URLs, response messages, headers, and
// the underlying transport error. Those values can contain provider
// reflections or signed authorization material.
type S3Error struct {
	Operation     string
	Key           string
	Kind          S3ErrorKind
	StatusCode    int
	ServiceCode   string
	Retryable     bool
	BodyTruncated bool
}

func (e *S3Error) Error() string {
	key := safeErrorKey(e.Key)
	if e.StatusCode != 0 {
		serviceCode := ""
		if e.ServiceCode != "" {
			serviceCode = " " + e.ServiceCode
		}
		return fmt.Sprintf("s3 %s %q: HTTP %d%s (%s)", e.Operation, key, e.StatusCode, serviceCode, e.Kind)
	}
	return fmt.Sprintf("s3 %s %q: %s error", e.Operation, key, e.Kind)
}

// IsNotFound reports whether err is a provider-independent missing-object
// response.
func IsNotFound(err error) bool {
	var s3Err *S3Error
	return errors.As(err, &s3Err) && s3Err.Kind == S3ErrorNotFound
}

// IsTemporary reports whether retrying the operation may succeed. S3Store
// already performs its configured bounded retries before returning an error.
func IsTemporary(err error) bool {
	var s3Err *S3Error
	return errors.As(err, &s3Err) && s3Err.Retryable
}

// S3Store implements a provider-neutral path-style SigV4 subset for
// S3-compatible stores. All operations are exact
// object requests; there is no prefix or wildcard deletion API.
type S3Store struct {
	Endpoint       string
	Bucket         string
	Region         string
	AccessKey      string
	SecretKey      string
	Client         *http.Client
	Now            func() time.Time
	RequestTimeout time.Duration
	MaxAttempts    int
	RetryBaseDelay time.Duration
	// RetryJitter selects a delay inside the supplied inclusive equal-jitter
	// bounds. Nil uses a concurrency-safe process random source. Returned
	// values are clamped, which keeps injected test or operator functions safe.
	RetryJitter    func(minimum, maximum time.Duration) time.Duration
	MaxObjectBytes int64
}

// Validate checks local configuration without making a network request.
func (s S3Store) Validate() error {
	if _, err := s.requestSettings(); err != nil {
		return err
	}
	_, err := s.objectURL("configuration-check")
	return err
}

func (s S3Store) Put(ctx context.Context, key string, body []byte, contentType string) error {
	_, err := s.request(ctx, http.MethodPut, "put", key, body, contentType, false, 0)
	return err
}

func (s S3Store) Get(ctx context.Context, key string) ([]byte, error) {
	return s.request(ctx, http.MethodGet, "get", key, nil, "", true, 0)
}

// GetBounded reads one object using the tighter of maximum and the store-wide
// MaxObjectBytes limit. Declared oversize responses are rejected before their
// body is read; undeclared oversize responses consume at most one probe byte
// beyond the returned allocation bound.
func (s S3Store) GetBounded(ctx context.Context, key string, maximum int64) ([]byte, error) {
	if maximum < 1 {
		return nil, errors.New("S3 response limit must be positive")
	}
	return s.request(ctx, http.MethodGet, "get", key, nil, "", true, maximum)
}

// Head verifies that one exact object exists. A missing object returns an
// S3Error for which IsNotFound is true.
func (s S3Store) Head(ctx context.Context, key string) error {
	_, err := s.request(ctx, http.MethodHead, "head", key, nil, "", false, 0)
	return err
}

// Delete removes one exact key. S3 delete is idempotent; providers that return
// a missing-object status are normalized to success as well.
func (s S3Store) Delete(ctx context.Context, key string) error {
	_, err := s.request(ctx, http.MethodDelete, "delete", key, nil, "", false, 0)
	if IsNotFound(err) {
		return nil
	}
	return err
}

type s3RequestSettings struct {
	timeout        time.Duration
	attempts       int
	retryBaseDelay time.Duration
	retryJitter    func(minimum, maximum time.Duration) time.Duration
	maxObjectBytes int64
}

func (s S3Store) requestSettings() (s3RequestSettings, error) {
	if strings.TrimSpace(s.AccessKey) == "" || s.SecretKey == "" {
		return s3RequestSettings{}, errors.New("S3 access key and secret key are required")
	}
	timeout := s.RequestTimeout
	if timeout == 0 {
		timeout = DefaultS3RequestTimeout
	}
	if timeout < 0 {
		return s3RequestSettings{}, errors.New("S3 request timeout must be positive")
	}
	attempts := s.MaxAttempts
	if attempts == 0 {
		attempts = DefaultS3MaxAttempts
	}
	if attempts < 1 || attempts > maxS3Attempts {
		return s3RequestSettings{}, fmt.Errorf("S3 max attempts must be between 1 and %d", maxS3Attempts)
	}
	retryBaseDelay := s.RetryBaseDelay
	if retryBaseDelay == 0 {
		retryBaseDelay = defaultRetryDelay
	}
	if retryBaseDelay < 0 {
		return s3RequestSettings{}, errors.New("S3 retry delay cannot be negative")
	}
	maxObjectBytes := s.MaxObjectBytes
	if maxObjectBytes == 0 {
		maxObjectBytes = DefaultS3MaxObjectBytes
	}
	if maxObjectBytes < 1 {
		return s3RequestSettings{}, errors.New("S3 maximum object size must be positive")
	}
	return s3RequestSettings{
		timeout: timeout, attempts: attempts, retryBaseDelay: retryBaseDelay,
		retryJitter: s.RetryJitter, maxObjectBytes: maxObjectBytes,
	}, nil
}

func (s S3Store) request(ctx context.Context, method, operation, key string, body []byte, contentType string, readBody bool, readLimit int64) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("S3 request context is required")
	}
	settings, err := s.requestSettings()
	if err != nil {
		return nil, err
	}
	target, err := s.objectURL(key)
	if err != nil {
		return nil, err
	}
	client := s.httpClient()
	for attempt := 1; attempt <= settings.attempts; attempt++ {
		attemptCtx, cancel := context.WithTimeout(ctx, settings.timeout)
		req, requestErr := s.signedRequest(attemptCtx, method, target, body, contentType)
		if requestErr != nil {
			cancel()
			return nil, requestErr
		}
		resp, requestErr := client.Do(req)
		if requestErr != nil {
			cancel()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			kind := S3ErrorTransport
			if errors.Is(requestErr, context.DeadlineExceeded) {
				kind = S3ErrorTimeout
			}
			classified := &S3Error{Operation: operation, Key: key, Kind: kind, Retryable: true}
			if attempt == settings.attempts {
				return nil, classified
			}
			if err := waitForRetry(ctx, retryDelay(settings.retryBaseDelay, attempt, "", settings.retryJitter)); err != nil {
				return nil, err
			}
			continue
		}

		if resp.StatusCode/100 == 2 {
			var responseBody []byte
			if readBody {
				maximum := settings.maxObjectBytes
				if readLimit > 0 && readLimit < maximum {
					maximum = readLimit
				}
				if resp.ContentLength > maximum {
					requestErr = errObjectTooLarge
				} else {
					responseBody, requestErr = readBounded(resp.Body, maximum)
				}
			} else {
				_, requestErr = io.Copy(io.Discard, io.LimitReader(resp.Body, maxS3ErrorBodyBytes))
			}
			_ = resp.Body.Close()
			cancel()
			if requestErr != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				kind := S3ErrorTransport
				retryable := true
				if errors.Is(requestErr, errObjectTooLarge) {
					kind = S3ErrorResponseTooBig
					retryable = false
				} else if errors.Is(requestErr, context.DeadlineExceeded) {
					kind = S3ErrorTimeout
				}
				classified := &S3Error{Operation: operation, Key: key, Kind: kind, Retryable: retryable}
				if retryable && attempt < settings.attempts {
					if err := waitForRetry(ctx, retryDelay(settings.retryBaseDelay, attempt, "", settings.retryJitter)); err != nil {
						return nil, err
					}
					continue
				}
				return nil, classified
			}
			return responseBody, nil
		}

		serviceCode, truncated := readS3Error(resp.Body)
		retryAfter := resp.Header.Get("Retry-After")
		_ = resp.Body.Close()
		cancel()
		classified := classifyS3Status(operation, key, resp.StatusCode, serviceCode, truncated)
		if !classified.Retryable || attempt == settings.attempts {
			return nil, classified
		}
		if err := waitForRetry(ctx, retryDelay(settings.retryBaseDelay, attempt, retryAfter, settings.retryJitter)); err != nil {
			return nil, err
		}
	}
	panic("unreachable S3 retry loop")
}

func (s S3Store) signedRequest(ctx context.Context, method string, target *url.URL, body []byte, contentType string) (*http.Request, error) {
	if target == nil {
		return nil, errors.New("S3 signed request target is required")
	}
	if target.Opaque != "" || target.RawQuery != "" || target.ForceQuery || target.Fragment != "" {
		return nil, errors.New("S3 signed request target must be hierarchical and must not contain a query or fragment")
	}
	req, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("construct S3 request")
	}
	if req.URL.Opaque != "" || req.URL.RawQuery != "" || req.URL.ForceQuery {
		return nil, errors.New("constructed S3 request escaped the query-free signing subset")
	}
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	region := strings.TrimSpace(s.Region)
	if region == "" {
		region = "auto"
	}
	amzDate, date := now.Format("20060102T150405Z"), now.Format("20060102")
	payloadHash := sha256Hex(body)
	req.Host = target.Host
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonicalHeaders := "host:" + req.Host + "\n" + "x-amz-content-sha256:" + payloadHash + "\n" + "x-amz-date:" + amzDate + "\n"
	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	// Exact object operations never use queries. objectURL and this signer both
	// enforce that invariant, so the canonical-query line is mechanically empty.
	canonical := method + "\n" + canonicalURI + "\n\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + payloadHash
	scope := date + "/" + region + "/s3/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonical))
	signingKey := hmacSHA([]byte("AWS4"+s.SecretKey), date)
	signingKey = hmacSHA(signingKey, region)
	signingKey = hmacSHA(signingKey, "s3")
	signingKey = hmacSHA(signingKey, "aws4_request")
	signature := hex.EncodeToString(hmacSHA(signingKey, toSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+s.AccessKey+"/"+scope+", SignedHeaders="+signedHeaders+", Signature="+signature)
	return req, nil
}

func (s S3Store) objectURL(key string) (*url.URL, error) {
	if err := validateObjectKey(key); err != nil {
		return nil, err
	}
	endpoint, err := url.Parse(s.Endpoint)
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" || endpoint.Opaque != "" {
		return nil, errors.New("invalid S3 endpoint")
	}
	if endpoint.Scheme != "http" && endpoint.Scheme != "https" {
		return nil, errors.New("S3 endpoint must use HTTP or HTTPS")
	}
	if endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" {
		return nil, errors.New("S3 endpoint must not contain user information, a query, or a fragment")
	}
	if strings.ContainsAny(s.Bucket, "/\\?#") || strings.ContainsAny(s.Bucket, "\r\n\x00") {
		return nil, errors.New("invalid S3 bucket")
	}
	prefix, err := canonicalEscapedPath(endpoint.EscapedPath())
	if err != nil {
		return nil, errors.New("invalid escaped S3 endpoint path")
	}
	prefix = strings.TrimSuffix(prefix, "/")
	rawPath := prefix + "/"
	if s.Bucket != "" {
		rawPath += sigV4URIEncode(s.Bucket, true) + "/"
	}
	rawPath += sigV4URIEncode(key, false)
	decodedPath, err := url.PathUnescape(rawPath)
	if err != nil {
		return nil, errors.New("construct S3 object path")
	}
	endpoint.Path = decodedPath
	endpoint.RawPath = rawPath
	return endpoint, nil
}

func canonicalEscapedPath(escaped string) (string, error) {
	if escaped == "" {
		return "", nil
	}
	segments := strings.Split(escaped, "/")
	for i, segment := range segments {
		decoded, err := url.PathUnescape(segment)
		if err != nil {
			return "", err
		}
		segments[i] = sigV4URIEncode(decoded, true)
	}
	return strings.Join(segments, "/"), nil
}

// sigV4URIEncode implements the AWS rule: encode every byte except RFC 3986
// unreserved bytes, use uppercase hex, encode spaces as %20, and optionally
// preserve object-key slash separators.
func sigV4URIEncode(value string, encodeSlash bool) string {
	const upperHex = "0123456789ABCDEF"
	var encoded strings.Builder
	encoded.Grow(len(value))
	for i := 0; i < len(value); i++ {
		char := value[i]
		if (char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' || char == '.' || char == '_' || char == '~' || (char == '/' && !encodeSlash) {
			encoded.WriteByte(char)
			continue
		}
		encoded.WriteByte('%')
		encoded.WriteByte(upperHex[char>>4])
		encoded.WriteByte(upperHex[char&0x0f])
	}
	return encoded.String()
}

func (s S3Store) httpClient() *http.Client {
	base := s.Client
	if base == nil {
		base = defaultS3HTTPClient
	}
	copy := *base
	copy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return &copy
}

var defaultS3HTTPClient = &http.Client{Transport: &http.Transport{
	Proxy:                 http.ProxyFromEnvironment,
	DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ResponseHeaderTimeout: 30 * time.Second,
	ExpectContinueTimeout: time.Second,
}}

func readS3Error(reader io.Reader) (string, bool) {
	body, err := io.ReadAll(io.LimitReader(reader, maxS3ErrorBodyBytes+1))
	if err != nil {
		return "", false
	}
	truncated := int64(len(body)) > maxS3ErrorBodyBytes
	if truncated {
		body = body[:maxS3ErrorBodyBytes]
	}
	decoder := xml.NewDecoder(bytes.NewReader(body))
	for {
		token, err := decoder.Token()
		if err != nil {
			return "", truncated
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "Code" {
			continue
		}
		var code string
		if decoder.DecodeElement(&code, &start) != nil || !safeServiceCode(code) {
			return "", truncated
		}
		return code, truncated
	}
}

func safeServiceCode(code string) bool {
	if code == "" || len(code) > 64 {
		return false
	}
	for _, char := range code {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '.' || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}

func classifyS3Status(operation, key string, statusCode int, serviceCode string, truncated bool) *S3Error {
	kind := S3ErrorUnexpected
	retryable := false
	switch statusCode {
	case http.StatusBadRequest:
		kind = S3ErrorInvalidRequest
	case http.StatusUnauthorized:
		kind = S3ErrorAuthentication
	case http.StatusForbidden:
		kind = S3ErrorPermission
	case http.StatusNotFound, http.StatusGone:
		kind = S3ErrorNotFound
	case http.StatusConflict:
		kind = S3ErrorConflict
	case http.StatusRequestTimeout:
		kind, retryable = S3ErrorTimeout, true
	case http.StatusTooEarly, http.StatusTooManyRequests:
		kind, retryable = S3ErrorThrottled, true
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		kind, retryable = S3ErrorUnavailable, true
	}
	return &S3Error{Operation: operation, Key: key, Kind: kind, StatusCode: statusCode, ServiceCode: serviceCode, Retryable: retryable, BodyTruncated: truncated}
}

func retryDelay(base time.Duration, attempt int, retryAfter string, jitter func(minimum, maximum time.Duration) time.Duration) time.Duration {
	if seconds, err := strconv.ParseInt(strings.TrimSpace(retryAfter), 10, 64); err == nil && seconds >= 0 {
		if seconds >= int64(maxS3RetryDelay/time.Second) {
			return maxS3RetryDelay
		}
		return time.Duration(seconds) * time.Second
	}
	if at, err := http.ParseTime(retryAfter); err == nil {
		delay := time.Until(at)
		if delay < 0 {
			return 0
		}
		if delay > maxS3RetryDelay {
			return maxS3RetryDelay
		}
		return delay
	}
	delay := base
	if delay > maxS3RetryDelay {
		delay = maxS3RetryDelay
	}
	for i := 1; i < attempt && delay < maxS3RetryDelay; i++ {
		delay *= 2
		if delay > maxS3RetryDelay {
			delay = maxS3RetryDelay
		}
	}
	minimum := delay - delay/2
	if jitter == nil {
		jitter = defaultRetryJitter
	}
	selected := jitter(minimum, delay)
	if selected < minimum {
		return minimum
	}
	if selected > delay {
		return delay
	}
	return selected
}

func defaultRetryJitter(minimum, maximum time.Duration) time.Duration {
	if maximum <= minimum {
		return minimum
	}
	return minimum + time.Duration(mathrand.Int64N(int64(maximum-minimum)+1))
}

func waitForRetry(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func safeErrorKey(key string) string {
	key = strings.Map(func(char rune) rune {
		if char < 0x20 || char == 0x7f {
			return '\ufffd'
		}
		return char
	}, key)
	const maximum = 256
	if len(key) > maximum {
		return key[:maximum] + "..."
	}
	return key
}

func sha256Hex(v []byte) string {
	sum := sha256.Sum256(v)
	return hex.EncodeToString(sum[:])
}

func hmacSHA(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(data))
	return h.Sum(nil)
}
