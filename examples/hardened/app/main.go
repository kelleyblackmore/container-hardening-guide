// helloctr - a deliberately boring HTTP service used to demonstrate container
// hardening. It exists so the hardened image has something real to run.
//
// Design choices that matter for hardening (see docs/03-image-creation-requirements.md):
//
//   - Listens on a NON-PRIVILEGED port (8080 by default)      -> DISA 2.5 / 2.13
//   - Ships its own health check via `-healthcheck`, so the    -> DISA 2.6
//     image needs no curl/wget just to run HEALTHCHECK.
//   - Separate /healthz (liveness) and /readyz (readiness)     -> DISA 3.8 / 3.9
//   - NEVER writes to the filesystem, so the container can run -> DISA 3.7
//     with a read-only root filesystem.
//   - Reads its secret from a file path supplied at RUNTIME    -> DISA 2.9 / 2.18
//     (a mounted Kubernetes Secret), never from a baked-in
//     constant and never from the build args.
//   - Handles SIGTERM so the orchestrator can drain it cleanly.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// ready flips to true once start-up work is finished. Kubernetes will not send
// traffic until /readyz returns 200.
var ready atomic.Bool

func main() {
	// `helloctr -healthcheck` performs a loopback GET /healthz and exits 0/1.
	// This is what the HEALTHCHECK instruction in the Dockerfile invokes, which
	// means the image does not need curl, wget, or a shell to be health-checked.
	healthcheck := flag.Bool("healthcheck", false, "probe the local /healthz endpoint and exit")
	flag.Parse()

	addr := ":" + port()
	if *healthcheck {
		os.Exit(probe(addr))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/readyz", handleReadyz)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Start-up work would go here (warm caches, open pools...). We simulate it
	// so /readyz has something meaningful to gate on.
	go func() {
		time.Sleep(500 * time.Millisecond)
		ready.Store(true)
		log.Printf("ready: serving on %s as uid=%d gid=%d", addr, os.Getuid(), os.Getgid())
	}()

	// SIGTERM is what a container runtime sends on `docker stop` / pod deletion.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-ctx.Done()
	ready.Store(false) // fail readiness first so we are pulled out of the LB
	log.Print("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}

func port() string {
	if p := os.Getenv("PORT"); p != "" {
		return p
	}
	return "8080"
}

// secret is read from a file at request time, not from the image and not from
// an environment variable. In Kubernetes this path is a mounted Secret volume.
// Nothing sensitive is ever printed - we only report whether it was found.
func secretPresent() bool {
	path := os.Getenv("APP_SECRET_FILE")
	if path == "" {
		return false
	}
	b, err := os.ReadFile(path)
	return err == nil && len(strings.TrimSpace(string(b))) > 0
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	host, _ := os.Hostname()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "helloctr\n")
	fmt.Fprintf(w, "host=%s\n", host)
	fmt.Fprintf(w, "uid=%d gid=%d\n", os.Getuid(), os.Getgid())
	fmt.Fprintf(w, "secret_mounted=%t\n", secretPresent())
}

// Liveness: "is this process wedged?" Keep it cheap and dependency-free.
func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "ok")
}

// Readiness: "should this instance receive traffic right now?"
func handleReadyz(w http.ResponseWriter, _ *http.Request) {
	if !ready.Load() {
		http.Error(w, "starting", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "ready")
}

func probe(addr string) int {
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	host, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 1
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + net.JoinHostPort(host, p) + "/healthz")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
