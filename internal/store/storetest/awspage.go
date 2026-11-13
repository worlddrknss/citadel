// Package storetest holds backend-independent conformance checks that the
// memory and Postgres store tests both run, so the two backends are held to
// the same behaviour. It is imported only from tests.
package storetest

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/worlddrknss/citadel/internal/store"
)

const (
	AccountA = "111111111111"
	AccountB = "222222222222"
)

// collect drains a paged listing with the given page size.
func collect[T any](t *testing.T, limit int, page func(after string, limit int) ([]T, bool, error), cursor func(T) string) []T {
	t.Helper()
	var all []T
	after := ""
	for i := 0; ; i++ {
		items, more, err := page(after, limit)
		if err != nil {
			t.Fatalf("page %d: %v", i, err)
		}
		if len(items) > limit {
			t.Fatalf("page %d returned %d items, limit %d", i, len(items), limit)
		}
		all = append(all, items...)
		if !more {
			return all
		}
		if len(items) == 0 {
			t.Fatalf("page %d: more=true with no items", i)
		}
		after = cursor(items[len(items)-1])
		if i > 100 {
			t.Fatal("pagination does not terminate")
		}
	}
}

// AWSPageStore checks cursor pagination, ordering, filtering and tenant
// isolation of store.AWSPageStore. paramsIsolated says whether the backend
// scopes parameters by account (the memory store does not yet).
func AWSPageStore(t *testing.T, st store.Store, paramsIsolated bool) {
	ctxA := store.WithCallerAccount(context.Background(), AccountA)
	ctxB := store.WithCallerAccount(context.Background(), AccountB)

	var keysA []string
	for i := 0; i < 5; i++ {
		k, err := st.CreateKey(ctxA, fmt.Sprintf("key %d", i), "", "")
		if err != nil {
			t.Fatalf("CreateKey: %v", err)
		}
		keysA = append(keysA, k.ID)
	}
	kb, err := st.CreateKey(ctxB, "other tenant", "", "")
	if err != nil {
		t.Fatalf("CreateKey B: %v", err)
	}

	t.Run("ListKeysPage", func(t *testing.T) {
		got := collect(t, 2, func(after string, limit int) ([]store.KMSKey, bool, error) {
			return st.ListKeysPage(ctxA, after, limit)
		}, func(k store.KMSKey) string { return k.ID })
		var ids []string
		for _, k := range got {
			if k.ID == kb.ID {
				t.Fatal("ListKeysPage leaked another account's key")
			}
			if len(k.MasterKeyRaw) != 0 {
				t.Fatal("ListKeysPage loaded key material")
			}
			ids = append(ids, k.ID)
		}
		if _, err := st.ResolveByID(ctxB, keysA[0]); err == nil {
			t.Fatal("account B resolved account A's key")
		}
		if !slices.IsSorted(ids) {
			t.Fatalf("keys not ordered: %v", ids)
		}
		for _, want := range keysA {
			if !slices.Contains(ids, want) {
				t.Fatalf("key %s missing from %v", want, ids)
			}
		}
	})

	t.Run("ListAliasesPage", func(t *testing.T) {
		for i, name := range []string{"alias/p-c", "alias/p-a", "alias/p-b"} {
			if err := st.CreateAlias(ctxA, name, keysA[i%2]); err != nil {
				t.Fatalf("CreateAlias: %v", err)
			}
		}
		if err := st.CreateAlias(ctxB, "alias/p-z", kb.ID); err != nil {
			t.Fatalf("CreateAlias B: %v", err)
		}
		cursor := func(a store.KMSAlias) string { return a.AliasName }
		got := collect(t, 2, func(after string, limit int) ([]store.KMSAlias, bool, error) {
			return st.ListAliasesPage(ctxA, store.AliasPageQuery{After: after, Limit: limit})
		}, cursor)
		var names []string
		for _, a := range got {
			names = append(names, a.AliasName)
		}
		for _, want := range []string{"alias/p-a", "alias/p-b", "alias/p-c"} {
			if !slices.Contains(names, want) {
				t.Fatalf("alias %s missing from %v", want, names)
			}
		}
		if slices.Contains(names, "alias/p-z") || !slices.IsSorted(names) {
			t.Fatalf("aliases = %v", names)
		}
		byKey := collect(t, 10, func(after string, limit int) ([]store.KMSAlias, bool, error) {
			return st.ListAliasesPage(ctxA, store.AliasPageQuery{After: after, Limit: limit, TargetKeyID: keysA[1]})
		}, cursor)
		if len(byKey) != 1 || byKey[0].AliasName != "alias/p-a" {
			t.Fatalf("aliases for key = %+v", byKey)
		}
	})

	t.Run("ListSecretsPage", func(t *testing.T) {
		for _, name := range []string{"pg/s3", "pg/s1", "pg/s4", "pg/s2"} {
			if _, _, err := st.CreateSecret(ctxA, store.CreateSecretRequest{Name: name, KMSKeyID: keysA[0], SecretString: "v"}); err != nil {
				t.Fatalf("CreateSecret: %v", err)
			}
		}
		if _, _, err := st.CreateSecret(ctxB, store.CreateSecretRequest{Name: "pg/other", KMSKeyID: kb.ID, SecretString: "v"}); err != nil {
			t.Fatalf("CreateSecret B: %v", err)
		}
		if err := st.TagSecret(ctxA, "pg/s1", []store.SecretTag{{Key: "team", Value: "x"}}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.DeleteSecret(ctxA, "pg/s4", 7, false); err != nil {
			t.Fatal(err)
		}
		list := func(includeDeleted bool) []store.SecretMetadataRecord {
			return collect(t, 2, func(after string, limit int) ([]store.SecretMetadataRecord, bool, error) {
				return st.ListSecretsPage(ctxA, store.SecretPageQuery{After: after, Limit: limit, IncludeDeleted: includeDeleted})
			}, func(m store.SecretMetadataRecord) string { return m.Name })
		}
		names := func(ms []store.SecretMetadataRecord) []string {
			var out []string
			for _, m := range ms {
				out = append(out, m.Name)
			}
			return out
		}
		live := list(false)
		if got := names(live); !slices.Equal(got, []string{"pg/s1", "pg/s2", "pg/s3"}) {
			t.Fatalf("live secrets = %v", got)
		}
		if len(live[0].Tags) != 1 || live[0].Tags[0].Key != "team" {
			t.Fatalf("tags not loaded: %+v", live[0].Tags)
		}
		if got := names(list(true)); !slices.Equal(got, []string{"pg/s1", "pg/s2", "pg/s3", "pg/s4"}) {
			t.Fatalf("secrets incl. deleted = %v", got)
		}
		desc := collect(t, 2, func(after string, limit int) ([]store.SecretMetadataRecord, bool, error) {
			return st.ListSecretsPage(ctxA, store.SecretPageQuery{After: after, Limit: limit, IncludeDeleted: true, Descending: true})
		}, func(m store.SecretMetadataRecord) string { return m.Name })
		if got := names(desc); !slices.Equal(got, []string{"pg/s4", "pg/s3", "pg/s2", "pg/s1"}) {
			t.Fatalf("descending secrets = %v", got)
		}
	})

	t.Run("ListParametersPage", func(t *testing.T) {
		for _, name := range []string{"/a", "/a/x", "/a/y/z", "/a/w", "/b", "/ab/q"} {
			if _, err := st.PutParameter(ctxA, store.ParameterRecord{Name: name, Type: "String", Value: "v", Tier: "Standard"}, false); err != nil {
				t.Fatalf("PutParameter %s: %v", name, err)
			}
		}
		if paramsIsolated {
			if _, err := st.PutParameter(ctxB, store.ParameterRecord{Name: "/a/other", Type: "String", Value: "v", Tier: "Standard"}, false); err != nil {
				t.Fatal(err)
			}
		}
		list := func(path string, recursive bool) []string {
			recs := collect(t, 2, func(after string, limit int) ([]store.ParameterRecord, bool, error) {
				return st.ListParametersPage(ctxA, store.ParameterPageQuery{Path: path, Recursive: recursive, After: after, Limit: limit})
			}, func(r store.ParameterRecord) string { return r.Name })
			var out []string
			for _, r := range recs {
				out = append(out, r.Name)
			}
			return out
		}
		for _, tc := range []struct {
			path      string
			recursive bool
			want      []string
		}{
			{"/a", false, []string{"/a/w", "/a/x"}},
			{"/a/", true, []string{"/a/w", "/a/x", "/a/y/z"}},
			{"/", false, []string{"/a", "/b"}},
			{"/", true, []string{"/a", "/a/w", "/a/x", "/a/y/z", "/ab/q", "/b"}},
			{"/nope", true, nil},
		} {
			if got := list(tc.path, tc.recursive); !slices.Equal(got, tc.want) {
				t.Errorf("path %q recursive=%v = %v, want %v", tc.path, tc.recursive, got, tc.want)
			}
		}
	})
}
