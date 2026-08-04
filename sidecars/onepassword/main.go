// multitool-onepassword is a deliberately narrow process boundary around the
// official 1Password Go SDK. It speaks newline-delimited JSON on inherited
// pipes; secrets never appear in arguments, environment variables, or logs.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	onepassword "github.com/1password/onepassword-sdk-go"
)

const maxRequestBytes = 1024 * 1024

type request struct {
	ID        uint64          `json:"id"`
	Operation string          `json:"operation"`
	Payload   json.RawMessage `json:"payload"`
}

type response struct {
	ID     uint64         `json:"id"`
	OK     bool           `json:"ok"`
	Result any            `json:"result,omitempty"`
	Error  *protocolError `json:"error,omitempty"`
}

type protocolError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type providerFailure struct {
	code    string
	message string
}

func (e *providerFailure) Error() string { return e.message }

type initializePayload struct {
	Auth struct {
		Method  string `json:"method"`
		Account string `json:"account,omitempty"`
		Token   string `json:"token,omitempty"`
	} `json:"auth"`
}

type catalogPayload struct {
	VaultID   string  `json:"vault_id"`
	ItemID    string  `json:"item_id"`
	SectionID *string `json:"section_id"`
	FieldID   string  `json:"field_id"`
	FieldType string  `json:"field_type,omitempty"`
}

type vaultResult struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	ItemCount uint32 `json:"item_count"`
}

type itemResult struct {
	ID       string  `json:"id"`
	Title    string  `json:"title"`
	Category *string `json:"category,omitempty"`
}

type fieldResult struct {
	ID           string  `json:"id"`
	Title        string  `json:"title"`
	SectionID    *string `json:"section_id,omitempty"`
	SectionTitle *string `json:"section_title,omitempty"`
	FieldType    string  `json:"field_type"`
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), maxRequestBytes)
	encoder := json.NewEncoder(os.Stdout)
	var client *onepassword.Client

	for scanner.Scan() {
		var req request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			writeError(encoder, 0, "invalid_request", "the SDK helper received invalid JSON")
			continue
		}

		if req.Operation == "initialize" {
			if client != nil {
				writeError(encoder, req.ID, "invalid_request", "the SDK helper is already initialized")
				continue
			}
			initialized, err := initialize(req.Payload)
			if err != nil {
				writeProviderError(encoder, req.ID, err)
				continue
			}
			client = initialized
			_ = encoder.Encode(response{ID: req.ID, OK: true, Result: map[string]bool{"initialized": true}})
			continue
		}

		if client == nil {
			writeError(encoder, req.ID, "invalid_request", "the SDK helper is not initialized")
			continue
		}
		result, err := handle(client, req)
		if err != nil {
			writeProviderError(encoder, req.ID, err)
			continue
		}
		_ = encoder.Encode(response{ID: req.ID, OK: true, Result: result})
	}
}

func initialize(raw json.RawMessage) (*onepassword.Client, error) {
	var payload initializePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	options := []onepassword.ClientOption{
		onepassword.WithIntegrationInfo("Multitool", "v0.1.0"),
	}
	switch payload.Auth.Method {
	case "desktop_app":
		if payload.Auth.Account == "" {
			return nil, errors.New("missing account")
		}
		options = append(options, onepassword.WithDesktopAppIntegration(payload.Auth.Account))
	case "service_account":
		if payload.Auth.Token == "" {
			return nil, errors.New("missing token")
		}
		options = append(options, onepassword.WithServiceAccountToken(payload.Auth.Token))
	default:
		return nil, errors.New("unsupported authentication method")
	}
	client, err := onepassword.NewClient(ctx, options...)
	payload.Auth.Token = ""
	return client, err
}

func handle(client *onepassword.Client, req request) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	var payload catalogPayload
	if err := json.Unmarshal(req.Payload, &payload); err != nil {
		return nil, err
	}

	switch req.Operation {
	case "list_vaults":
		vaults, err := client.Vaults().List(ctx)
		if err != nil {
			return nil, err
		}
		result := make([]vaultResult, 0, len(vaults))
		for _, vault := range vaults {
			result = append(result, vaultResult{
				ID:        vault.ID,
				Title:     vault.Title,
				ItemCount: vault.ActiveItemCount,
			})
		}
		return result, nil
	case "list_items":
		if payload.VaultID == "" {
			return nil, errors.New("missing vault id")
		}
		items, err := client.Items().List(ctx, payload.VaultID)
		if err != nil {
			return nil, err
		}
		result := make([]itemResult, 0, len(items))
		for _, item := range items {
			category := string(item.Category)
			result = append(result, itemResult{ID: item.ID, Title: item.Title, Category: &category})
		}
		return result, nil
	case "list_fields":
		item, err := client.Items().Get(ctx, payload.VaultID, payload.ItemID)
		if err != nil {
			return nil, err
		}
		sections := make(map[string]string, len(item.Sections))
		for _, section := range item.Sections {
			sections[section.ID] = section.Title
		}
		result := make([]fieldResult, 0, len(item.Fields))
		for _, field := range item.Fields {
			var sectionTitle *string
			// Unnamed sections have an empty title; omit rather than send "".
			if field.SectionID != nil {
				if title, ok := sections[*field.SectionID]; ok && title != "" {
					copy := title
					sectionTitle = &copy
				}
			}
			result = append(result, fieldResult{
				ID: field.ID, Title: field.Title, SectionID: field.SectionID,
				SectionTitle: sectionTitle, FieldType: string(field.FieldType),
			})
		}
		return result, nil
	case "resolve":
		if payload.VaultID == "" || payload.ItemID == "" || payload.FieldID == "" {
			return nil, errors.New("incomplete secret reference")
		}
		fieldType := payload.FieldType
		if fieldType == "" {
			item, err := client.Items().Get(ctx, payload.VaultID, payload.ItemID)
			if err != nil {
				return nil, err
			}
			var found bool
			fieldType, found = matchingFieldType(item.Fields, payload)
			if !found {
				return nil, &providerFailure{
					code: "not_found", message: "the linked 1Password field no longer exists",
				}
			}
		}
		reference := buildSecretReference(payload, fieldType)
		resolved, err := client.Secrets().ResolveAll(ctx, []string{reference})
		if err != nil {
			return nil, err
		}
		entry, ok := resolved.IndividualResponses[reference]
		if !ok && len(resolved.IndividualResponses) == 1 {
			for _, candidate := range resolved.IndividualResponses {
				entry, ok = candidate, true
			}
		}
		if !ok {
			return nil, &providerFailure{code: "invalid_response", message: "the 1Password SDK omitted the requested field"}
		}
		if entry.Error != nil {
			return nil, resolveFailure(*entry.Error)
		}
		if entry.Content == nil {
			return nil, &providerFailure{code: "invalid_response", message: "the 1Password SDK returned an empty field"}
		}
		return map[string]string{"value": entry.Content.Secret}, nil
	default:
		return nil, fmt.Errorf("unsupported operation")
	}
}

func sameSection(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func matchingFieldType(fields []onepassword.ItemField, payload catalogPayload) (string, bool) {
	for _, field := range fields {
		if field.ID == payload.FieldID && sameSection(field.SectionID, payload.SectionID) {
			return string(field.FieldType), true
		}
	}
	return "", false
}

func isTOTPFieldType(fieldType string) bool {
	normalized := strings.ToLower(strings.TrimSpace(fieldType))
	return normalized == "totp" || normalized == "otp"
}

func buildSecretReference(payload catalogPayload, fieldType string) string {
	parts := []string{payload.VaultID, payload.ItemID}
	if payload.SectionID != nil {
		parts = append(parts, *payload.SectionID)
	}
	parts = append(parts, payload.FieldID)
	for index := range parts {
		parts[index] = url.PathEscape(parts[index])
	}
	reference := "op://" + parts[0]
	for _, part := range parts[1:] {
		reference += "/" + part
	}
	if isTOTPFieldType(fieldType) {
		reference += "?attribute=otp"
	}
	return reference
}

func writeProviderError(encoder *json.Encoder, id uint64, err error) {
	code, message := providerErrorDetails(err)
	writeError(encoder, id, code, message)
}

func providerErrorDetails(err error) (string, string) {
	var failure *providerFailure
	if errors.As(err, &failure) {
		return failure.code, failure.message
	}
	var expired *onepassword.DesktopSessionExpiredError
	if errors.As(err, &expired) {
		return "desktop_session_expired", "unlock 1Password and approve Multitool again"
	}
	var rateLimit *onepassword.RateLimitExceededError
	if errors.As(err, &rateLimit) {
		return "rate_limited", "1Password asked Multitool to retry later"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout", "the 1Password request timed out"
	}
	return "request_failed", "the 1Password request failed"
}

func resolveFailure(err onepassword.ResolveReferenceError) error {
	switch err.Type {
	case onepassword.ResolveReferenceErrorTypeVariantFieldNotFound,
		onepassword.ResolveReferenceErrorTypeVariantVaultNotFound,
		onepassword.ResolveReferenceErrorTypeVariantItemNotFound,
		onepassword.ResolveReferenceErrorTypeVariantNoMatchingSections:
		return &providerFailure{code: "not_found", message: "the linked 1Password field no longer exists"}
	case onepassword.ResolveReferenceErrorTypeVariantUnableToGenerateTOTPCode:
		return &providerFailure{code: "request_failed", message: "1Password could not generate the one-time password"}
	default:
		return &providerFailure{code: "request_failed", message: "the 1Password field could not be resolved"}
	}
}

func writeError(encoder *json.Encoder, id uint64, code, message string) {
	_ = encoder.Encode(response{
		ID: id, OK: false,
		Error: &protocolError{Code: code, Message: message},
	})
}
