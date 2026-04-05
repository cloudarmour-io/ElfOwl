package kubernetes

import (
	"context"
	"errors"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"golang.org/x/time/rate"
)

func TestIsRBACAPIEnabledFailOpenOnFirstDiscoveryError(t *testing.T) {
	c := &Client{
		discoverServerGroups: func() (*metav1.APIGroupList, error) {
			return nil, errors.New("discovery unavailable")
		},
	}

	if !c.IsRBACAPIEnabled(context.Background()) {
		t.Fatalf("expected fail-open true on first discovery error")
	}
}

func TestIsRBACAPIEnabledUsesMemoOnDiscoveryError(t *testing.T) {
	c := &Client{
		discoverServerGroups: func() (*metav1.APIGroupList, error) {
			return nil, errors.New("discovery unavailable")
		},
		rbacMemo: apiGroupMemo{
			enabled:   false,
			checked:   true,
			checkedAt: time.Now().Add(-rbacAPICacheTTL - time.Second),
		},
	}

	if c.IsRBACAPIEnabled(context.Background()) {
		t.Fatalf("expected memoized false when discovery fails after a prior check")
	}
}

func TestIsRBACAPIEnabledUsesMemoOnRateLimiterError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := &Client{
		discoverServerGroups: func() (*metav1.APIGroupList, error) {
			return &metav1.APIGroupList{
				Groups: []metav1.APIGroup{{Name: "rbac.authorization.k8s.io"}},
			}, nil
		},
		apiLimiter: rate.NewLimiter(rate.Limit(1), 1),
		rbacMemo: apiGroupMemo{
			enabled:   false,
			checked:   true,
			checkedAt: time.Now().Add(-rbacAPICacheTTL - time.Second),
		},
	}

	if c.IsRBACAPIEnabled(ctx) {
		t.Fatalf("expected memoized false when limiter wait fails after a prior check")
	}
}

func TestIsRBACAPIEnabledDetectsGroupAndCaches(t *testing.T) {
	discoveryCalls := 0
	c := &Client{
		discoverServerGroups: func() (*metav1.APIGroupList, error) {
			discoveryCalls++
			return &metav1.APIGroupList{
				Groups: []metav1.APIGroup{{Name: "rbac.authorization.k8s.io"}},
			}, nil
		},
	}

	if !c.IsRBACAPIEnabled(context.Background()) {
		t.Fatalf("expected true when RBAC API group exists")
	}
	if !c.IsRBACAPIEnabled(context.Background()) {
		t.Fatalf("expected cached true on immediate second check")
	}
	if discoveryCalls != 1 {
		t.Fatalf("expected one discovery call due cache, got %d", discoveryCalls)
	}
}
