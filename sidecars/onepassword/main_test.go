package main

import (
	"context"
	"errors"
	"testing"

	onepassword "github.com/1password/onepassword-sdk-go"
)

func TestProviderErrorDetailsClassifiesRecoverableProviderErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code string
	}{
		{"rate limit", &onepassword.RateLimitExceededError{}, "rate_limited"},
		{"deadline", context.DeadlineExceeded, "timeout"},
		{"ordinary request", errors.New("provider detail must stay private"), "request_failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code, _ := providerErrorDetails(test.err)
			if code != test.code {
				t.Fatalf("got %q, want %q", code, test.code)
			}
		})
	}
}

func TestResolveFailureMapsMissingCoordinates(t *testing.T) {
	missing := []onepassword.ResolveReferenceError{
		onepassword.NewResolveReferenceErrorTypeVariantFieldNotFound(),
		onepassword.NewResolveReferenceErrorTypeVariantVaultNotFound(),
		onepassword.NewResolveReferenceErrorTypeVariantItemNotFound(),
		onepassword.NewResolveReferenceErrorTypeVariantNoMatchingSections(),
	}
	for _, providerErr := range missing {
		code, _ := providerErrorDetails(resolveFailure(providerErr))
		if code != "not_found" {
			t.Fatalf("%s mapped to %q", providerErr.Type, code)
		}
	}

	code, _ := providerErrorDetails(resolveFailure(
		onepassword.NewResolveReferenceErrorTypeVariantTooManyItems(),
	))
	if code != "request_failed" {
		t.Fatalf("ambiguous item mapped to %q", code)
	}
}
