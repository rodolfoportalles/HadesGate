package proxy

import "time"

// RateLimiter is a fixed-rate token bucket exposed for the administrative API.
// It is safe for concurrent use.
type RateLimiter struct {
	bucket *tokenBucketLimiter
}

// NewRateLimiter allows eventsPerMinute operations per minute with a burst of
// the same size. A non-positive value yields a nil limiter, meaning no limit.
func NewRateLimiter(eventsPerMinute int) *RateLimiter {
	bucket := newTokenBucketLimiter(eventsPerMinute)
	if bucket == nil {
		return nil
	}
	return &RateLimiter{bucket: bucket}
}

// Allow consumes one token when available.
func (l *RateLimiter) Allow() bool {
	if l == nil || l.bucket == nil {
		return true
	}
	return l.bucket.allow(time.Now())
}
