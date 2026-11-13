package citadel_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/worlddrknss/citadel/sdk/citadel"
)

func ExampleNew() {
	// Empty fields fall back to CITADEL_URL, CITADEL_ACCESS_KEY_ID and
	// CITADEL_SECRET_ACCESS_KEY.
	c, err := citadel.New(citadel.Config{
		BaseURL:         "https://citadel.example.com",
		AccessKeyID:     "AKIAEXAMPLE",
		SecretAccessKey: "secret",
		Timeout:         10 * time.Second,
		MaxRetries:      5,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(c.BaseURL())
	// Output: https://citadel.example.com
}

func ExampleClient_GetSecret() {
	c, err := citadel.New(citadel.Config{})
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	v, err := c.GetSecret(ctx, citadel.SecretRef{Project: "shop", Env: "prod", Path: "api", Key: "DATABASE_URL"}, nil)
	switch {
	case citadel.IsNotFound(err):
		log.Fatal("no such secret")
	case err != nil:
		log.Fatal(err)
	}
	fmt.Println(len(v.Value) > 0)
}

func ExampleClient_PutSecret() {
	c, err := citadel.New(citadel.Config{})
	if err != nil {
		log.Fatal(err)
	}
	_, err = c.PutSecret(context.Background(), citadel.PutSecretInput{
		Project: "shop", Env: "prod", Path: "api", Key: "DATABASE_URL", Value: "postgres://...",
	})
	if citadel.IsApprovalRequired(err) {
		// prod is protected: changes go through a change request.
		log.Fatal("submit a change request instead")
	}
	var apiErr *citadel.APIError
	if errors.As(err, &apiErr) {
		log.Fatalf("Citadel said %s (%d): %s", apiErr.Code, apiErr.StatusCode, apiErr.Message)
	}
}

func ExampleClient_Encrypt() {
	c, err := citadel.New(citadel.Config{})
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	encCtx := map[string]string{"tenant": "42"}
	out, err := c.Encrypt(ctx, "alias/default", []byte("card number"), encCtx)
	if err != nil {
		log.Fatal(err)
	}
	plaintext, err := c.Decrypt(ctx, "alias/default", out.CiphertextBlob, encCtx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(plaintext))
}

func ExampleClient_IssueWorkloadToken() {
	c, err := citadel.New(citadel.Config{})
	if err != nil {
		log.Fatal(err)
	}
	tok, err := c.IssueWorkloadToken(context.Background(), citadel.WorkloadTokenInput{
		ClientID: "wic-123", Audience: "sts.amazonaws.com", TTL: 15 * time.Minute,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(tok.ExpiresAt.After(time.Now()))
}
