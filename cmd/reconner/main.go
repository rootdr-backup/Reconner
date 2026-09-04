// Command reconner starts the self-hosted Reconner web application.
//
// Reconner is intentionally service-only: targets, scans, findings, reports,
// and system settings are managed through the authenticated web interface.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/recon-platform/internal/api"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/scheduler"
	"github.com/recon-platform/internal/websocket"
	"github.com/recon-platform/pkg/logger"
)

const (
	cReset  = "\033[0m"
	cDim    = "\033[2m"
	cYellow = "\033[33m"
	cBlue   = "\033[36m"
	cBold   = "\033[1m"
)

type application struct {
	cfg       *config.Config
	db        *database.DB
	scheduler *scheduler.Scheduler
	handler   *api.Handler
}

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "Reconner no longer exposes command-line operations; start it without arguments and use the web interface.")
		os.Exit(2)
	}
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "reconner: %v\n", err)
		os.Exit(1)
	}
}

func boot() (*application, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	// Preserve the service's established runtime behavior while removing the old
	// command dispatcher. These settings historically lived in a shared bootstrap
	// used by the web service as well as command-line operations; dropping them
	// would silently reduce throughput and re-enable a system-wide memory check
	// that can force needless GC in containers. Process/cgroup-aware memory
	// accounting should replace the unlimited setting in a dedicated change.
	cfg.Limits.MaxMemoryMB = 0
	cfg.Limits.ParallelModules = true
	floor := func(value *int, minimum int) {
		if *value < minimum {
			*value = minimum
		}
	}
	floor(&cfg.Workers.JSAnalysis, 16)
	floor(&cfg.Workers.HTTPProbing, 40)
	floor(&cfg.Workers.SubdomainEnumeration, 25)
	floor(&cfg.Workers.DirectoryDiscovery, 6)
	floor(&cfg.Workers.Nuclei, 6)
	floor(&cfg.Workers.Crawling, 10)

	log := logger.New("error")
	db, err := database.New(cfg.DatabasePath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := database.RunMigrations(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate database: %w", err)
	}

	hub := websocket.NewHub()
	go hub.Run()
	sched := scheduler.New(db, hub, cfg, log)
	sched.Start()
	handler := api.NewHandler(db, hub, sched, cfg, log)

	return &application{
		cfg:       cfg,
		db:        db,
		scheduler: sched,
		handler:   handler,
	}, nil
}

func run() error {
	app, err := boot()
	if err != nil {
		return err
	}
	defer app.db.Close()
	defer app.scheduler.Stop()

	// Resume only work that was deliberately parked during a graceful service
	// shutdown. The scheduler persists completed modules, so a restart repeats at
	// most the module that was in flight.
	if n := app.scheduler.ResumeInterrupted(); n > 0 {
		fmt.Printf("%s  ↻ resumed %d scan(s) interrupted by the last shutdown%s\n", cDim, n, cReset)
	}

	// If no callback URL is configured, best-effort discovery makes the service
	// itself the HTTP OOB listener. Failure leaves OOB disabled rather than
	// guessing a callback address.
	if app.cfg.BlindXSSCallbackURL == "" {
		if base := detectPublicBaseURL(app.cfg.Port); base != "" {
			app.cfg.BlindXSSCallbackURL = base
			fmt.Printf("%s  OOB callback auto-set to %s (blind XSS/SSRF enabled)%s\n", cDim, base, cReset)
		}
	}

	// Raw callbacks (notably JNDI/LDAP) use the same handler instance as the HTTP
	// callback routes, keeping correlation and finding promotion on one runtime.
	if app.cfg.BlindXSSCallbackURL != "" {
		if closer, err := app.handler.StartLog4ShellListener(app.cfg.OOBRawPort); err != nil {
			fmt.Printf("%s  Log4Shell OOB listener not started: %v%s\n", cDim, err, cReset)
		} else {
			defer closer.Close()
			port := app.cfg.OOBRawPort
			if port <= 0 {
				port = 1389
			}
			fmt.Printf("%s  Log4Shell OOB listener on :%d (JNDI/LDAP callbacks)%s\n", cDim, port, cReset)
		}
	}

	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", app.cfg.Host, app.cfg.Port),
		Handler:      app.handler.Router(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fmt.Printf("%s%s▶ Reconner web watchtower running%s — http://%s\n", cBold, cBlue, cReset, srv.Addr)
	fmt.Printf("%s  login: %s / (see admin_password in the configured config.json)%s\n", cDim, app.cfg.AdminUsername, cReset)
	switch {
	case strings.HasPrefix(srv.Addr, "0.0.0.0:") || strings.HasPrefix(srv.Addr, ":"):
		fmt.Printf("%s%s  ⚠ bound to all interfaces — the dashboard is reachable from the network.%s\n", cBold, cBlue, cReset)
		fmt.Printf("%s    Only do this behind a firewall/VPN. For local-only access set \"host\": \"127.0.0.1\".%s\n", cDim, cReset)
	case strings.HasPrefix(srv.Addr, "127.0.0.1:") || strings.HasPrefix(srv.Addr, "localhost:"):
		fmt.Printf("%s  local-only. For remote access, prefer an SSH tunnel or explicitly configure a protected network bind.%s\n", cDim, cReset)
	}

	serverErr := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		if err == http.ErrServerClosed {
			err = nil
		}
		serverErr <- err
	}()

	var listenErr error
	select {
	case <-ctx.Done():
		fmt.Printf("\n%sshutting down…%s\n", cYellow, cReset)
	case listenErr = <-serverErr:
		if listenErr != nil {
			fmt.Printf("\n%sserver stopped unexpectedly: %v%s\n", cYellow, listenErr, cReset)
		}
	}

	// Park active work before the scheduler and database are torn down. This is
	// the only supported resume path now that Reconner has no maintenance CLI.
	if n, parkErr := app.scheduler.SuspendActiveForShutdown(); parkErr != nil {
		if listenErr == nil {
			listenErr = fmt.Errorf("park active scans: %w", parkErr)
		}
	} else if n > 0 {
		fmt.Printf("%s  ⏸ parked %d active scan(s) — they will resume on next start%s\n", cDim, n, cReset)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && listenErr == nil {
		listenErr = fmt.Errorf("shutdown server: %w", err)
	}
	return listenErr
}

// detectPublicBaseURL asks public address-discovery services for the host's
// external IP. It returns empty when the host is offline or the result is not a
// valid IP address.
func detectPublicBaseURL(port int) string {
	client := &http.Client{Timeout: 6 * time.Second}
	for _, endpoint := range []string{"https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"} {
		resp, err := client.Get(endpoint)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		ip := strings.TrimSpace(string(body))
		if net.ParseIP(ip) != nil {
			return fmt.Sprintf("http://%s:%d", ip, port)
		}
	}
	return ""
}
