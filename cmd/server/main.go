// Command server runs Citadel: it loads the configuration, builds the store,
// wires up the HTTP server and serves until told to stop.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/worlddrknss/citadel/internal/arn"
	"github.com/worlddrknss/citadel/internal/config"
	"github.com/worlddrknss/citadel/internal/cryptoutil"
	"github.com/worlddrknss/citadel/internal/server"
	"github.com/worlddrknss/citadel/internal/store"
	"github.com/worlddrknss/citadel/internal/store/memory"
	"github.com/worlddrknss/citadel/internal/store/postgres"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	st, cleanup, err := buildStore(cfg)
	if err != nil {
		log.Fatalf("failed to initialize key store: %v", err)
	}
	defer cleanup()

	s, err := server.New(context.Background(), cfg, st, webDistSub())
	if err != nil {
		log.Fatal(err)
	}
	// Background jobs (session purges...) stop when the server does.
	jobsCtx, stopJobs := context.WithCancel(context.Background())
	s.Start(jobsCtx)
	err = run(cfg, s.Handler())
	stopJobs()
	s.Wait()
	if err != nil {
		log.Fatalf("server exited with error: %v", err)
	}
}

// buildStore returns the configured backend: PostgreSQL when KMS_DB_URL is
// set, otherwise the in-memory store holding the legacy master key. The
// returned func releases it.
func buildStore(cfg config.Config) (store.Store, func(), error) {
	if cfg.DBConnString == "" {
		if len(cfg.LegacyMasterKey) == 0 {
			return nil, nil, errors.New("legacy key is required when KMS_DB_URL is not set")
		}
		legacyKeyID := strings.TrimSpace(cfg.LegacyKeyID)
		if legacyKeyID == "" {
			legacyKeyID = cryptoutil.DeriveDeterministicLegacyKeyID(cfg.LegacyMasterKey)
		}
		region := arn.EffectiveRegion(cfg.AWSRegion)
		accountID := cfg.AWSAccountID
		if !arn.IsValidAccountID(accountID) {
			accountID = arn.GenerateAccountID()
		}
		keyARN := cfg.LegacyKeyARN
		if keyARN == "" {
			keyARN = arn.Build("kms", region, accountID, "key/"+legacyKeyID)
		}
		k := store.KMSKey{
			ID:           legacyKeyID,
			ARN:          keyARN,
			MasterKeyRaw: cfg.LegacyMasterKey,
			Description:  "go-kms key",
			CreatedAt:    time.Now().UTC(),
			Enabled:      true,
		}
		return &memory.Store{DefaultKey: k, AuditHMACKey: cfg.AuditHMACKey, Region: region, AccountID: accountID}, func() {}, nil
	}

	db, err := sql.Open("postgres", cfg.DBConnString)
	if err != nil {
		return nil, nil, fmt.Errorf("open postgres connection: %w", err)
	}
	// Bound the connection pool so idle connections are recycled rather than
	// living for the lifetime of the process. lib/pq keeps per-connection
	// buffers and server-side prepared statements, so unbounded long-lived
	// connections let process memory creep upward over time.
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	db.SetConnMaxIdleTime(5 * time.Minute)
	cleanup := func() {
		_ = db.Close()
	}
	if err := db.Ping(); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("ping postgres: %w", err)
	}
	store, err := postgres.Open(context.Background(), db, postgres.Options{
		WrappingKey:       cfg.WrappingKey,
		LegacyWrappingKey: cfg.LegacyWrappingKey,
		AuditHMACKey:      cfg.AuditHMACKey,
		Region:            cfg.AWSRegion,
		AccountID:         cfg.AWSAccountID,
	})
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return store, cleanup, nil
}

// run serves h on cfg.Addr (TLS when a certificate is configured), plus the
// optional pprof listener, until the listener fails or SIGINT/SIGTERM asks
// for a graceful shutdown.
func run(cfg config.Config, h http.Handler) error {
	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Optional diagnostic profiling server. Disabled unless KMS_PPROF_ADDR is
	// set, and intended to be bound to loopback only (e.g. 127.0.0.1:6060) so
	// the sensitive pprof endpoints are reachable solely via `kubectl
	// port-forward`, never exposed on the service network.
	if pprofAddr := cfg.PprofAddr; pprofAddr != "" {
		pprofMux := http.NewServeMux()
		pprofMux.HandleFunc("/debug/pprof/", pprof.Index)
		pprofMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		pprofMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		pprofMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		pprofMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		pprofServer := &http.Server{
			Addr:              pprofAddr,
			Handler:           pprofMux,
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			log.Printf("%s pprof diagnostics listening on %s", server.AppName, pprofAddr)
			if err := pprofServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("pprof server exited: %v", err)
			}
		}()
	}

	serveErr := make(chan error, 1)
	go func() {
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			log.Printf("%s listening on %s (TLS)", server.AppName, cfg.Addr)
			serveErr <- httpServer.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
			return
		}
		log.Printf("%s listening on %s", server.AppName, cfg.Addr)
		serveErr <- httpServer.ListenAndServe()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case sig := <-sigCh:
		log.Printf("received %s, shutting down gracefully", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Printf("graceful shutdown error: %v", err)
		}
	}
	return nil
}
