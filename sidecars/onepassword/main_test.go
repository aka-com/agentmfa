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

func TestBuildSecretReferenceRequestsFreshTOTPCode(t *testing.T) {
	section := "authentication"
	payload := catalogPayload{
		VaultID: "vault/id", ItemID: "login", SectionID: &section, FieldID: "one-time password",
	}
	got := buildSecretReference(payload, "Totp")
	want := "op://vault%2Fid/login/authentication/one-time%20password?attribute=otp"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestBuildSecretReferenceDoesNotAddOTPAttributeToOrdinaryFields(t *testing.T) {
	payload := catalogPayload{VaultID: "vault", ItemID: "login", FieldID: "password"}
	got := buildSecretReference(payload, "Concealed")
	want := "op://vault/login/password"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestMatchingFieldTypeSupportsLegacyReferences(t *testing.T) {
	section := "authentication"
	fields := []onepassword.ItemField{
		{ID: "otp", SectionID: &section, FieldType: onepassword.ItemFieldTypeTOTP},
	}
	got, ok := matchingFieldType(fields, catalogPayload{FieldID: "otp", SectionID: &section})
	if !ok || got != "Totp" {
		t.Fatalf("got %q, %v; want Totp, true", got, ok)
	}
	if _, ok := matchingFieldType(fields, catalogPayload{FieldID: "otp"}); ok {
		t.Fatal("matched a field from the wrong section")
	}
}
