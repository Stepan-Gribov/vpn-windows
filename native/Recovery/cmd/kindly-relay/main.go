package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/KindlyVPN/foundation/transports"
	"www.bamsoftware.com/git/dnstt.git/noise"
)

func main() {
	log.SetOutput(io.Discard)
	configPath := flag.String("config", "", "private relay configuration file")
	keyPrefix := flag.String("generate-key", "", "create PREFIX.key and PREFIX.pub (exclusive creation)")
	flag.Parse()
	if *keyPrefix != "" {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			fail("key generation failed")
		}
		writeKey(*keyPrefix+".key", key, 0600)
		writeKey(*keyPrefix+".pub", noise.PubkeyFromPrivkey(key), 0644)
		return
	}
	var cfg struct {
		Type           string                       `json:"type"`
		Listen         string                       `json:"listen"`
		Path           string                       `json:"path"`
		Target         string                       `json:"target"`
		PrivateKeyFile string                       `json:"private_key_file"`
		TLSCert        string                       `json:"tls_cert"`
		TLSKey         string                       `json:"tls_key"`
		Conference     *transports.ConferenceConfig `json:"conference,omitempty"`
		BootstrapDNS   []string                     `json:"bootstrap_dns,omitempty"`
	}
	f, err := os.Open(*configPath)
	if err != nil {
		fail("cannot open relay configuration")
	}
	d := json.NewDecoder(io.LimitReader(f, transports.MaxConfigBytes+1))
	d.DisallowUnknownFields()
	if d.Decode(&cfg) != nil {
		fail("invalid relay configuration")
	}
	f.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer cancel()
	if cfg.Type == "conference" {
		if cfg.Conference == nil {
			fail("missing conference configuration")
		}
		if transports.RunConferenceServer(ctx, *cfg.Conference, cfg.BootstrapDNS) != nil && ctx.Err() == nil {
			fail("conference relay stopped")
		}
		return
	}
	if cfg.Type != "https" || cfg.TLSCert == "" || cfg.TLSKey == "" || cfg.Path == "" || cfg.Path[0] != '/' {
		fail("HTTPS relay requires TLS certificate, key, and route path")
	}
	keyFile, err := os.Open(cfg.PrivateKeyFile)
	if err != nil {
		fail("cannot open private key")
	}
	key, err := noise.ReadKey(keyFile)
	keyFile.Close()
	if err != nil {
		fail("invalid private key")
	}
	handler, err := transports.RelayHandler(key, cfg.Target)
	if err != nil {
		fail("invalid relay target")
	}
	mux := http.NewServeMux()
	mux.Handle(cfg.Path, handler)
	server := &http.Server{Addr: cfg.Listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024}
	go func() { <-ctx.Done(); server.Close() }()
	if err := server.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey); err != nil && err != http.ErrServerClosed {
		fail("HTTPS relay stopped")
	}
}

func writeKey(path string, key []byte, mode os.FileMode) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		fail("key output already exists or cannot be created")
	}
	_, err = fmt.Fprintln(f, hex.EncodeToString(key))
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		fail("key write failed")
	}
}
func fail(message string) { fmt.Fprintln(os.Stderr, message); os.Exit(1) }
