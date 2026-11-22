package libXray

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"www.bamsoftware.com/git/dnstt.git/noise"

	"golang.org/x/crypto/ssh"
)

func TestManagedDNSConfigurationAndCancellation(t *testing.T) {
	for _, mode := range []string{"socks5", "ssh"} {
		t.Run(mode, func(t *testing.T) {
			cfg := managedDNSConfig{Domain: "t.example.test", Resolver: "127.0.0.1:9", PublicKey: strings.Repeat("01", 32), TunnelType: mode, Username: "test", Password: "secret", HostKey: "SHA256:example"}
			carrier, err := cfg.carrier()
			if err != nil {
				t.Fatal(err)
			}
			want := "127.0.0.1:9002"
			if mode == "ssh" {
				want = "127.0.0.1:9003"
			}
			if carrier.Listen != want {
				t.Fatal(carrier.Listen)
			}
			raw, _ := json.Marshal(map[string]any{"provider": "managed_dns", "managed_dns": cfg})
			if code := KindlyTurnStart(string(raw)); code != 0 {
				t.Fatalf("start %d", code)
			}
			time.Sleep(20 * time.Millisecond)
			if strings.Contains(KindlyTurnStatus(), `"ready":true`) {
				t.Fatal("unreachable DNS reported ready")
			}
			started := time.Now()
			KindlyTurnStop()
			if time.Since(started) > time.Second {
				t.Fatal("DNS shutdown blocked")
			}
			if strings.Contains(KindlyTurnStatus(), `"running":true`) {
				t.Fatal("DNS still running")
			}
		})
	}
}

func TestManagedDNSPinsSSHHostKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	cfg := managedDNSConfig{Username: "test", Password: "secret", HostKey: ssh.FingerprintSHA256(key)}
	client, err := cfg.sshConfig()
	if err != nil {
		t.Fatal(err)
	}
	if err := client.HostKeyCallback("ignored", nil, key); err != nil {
		t.Fatal(err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	otherKey, _ := ssh.NewPublicKey(other)
	if client.HostKeyCallback("ignored", nil, otherKey) == nil {
		t.Fatal("untrusted SSH host accepted")
	}
	cfg.PrivateKey = "not a key"
	if _, err := cfg.sshConfig(); err == nil {
		t.Fatal("bad private key accepted")
	}
	cfg.TunnelType = "slipstream"
	if _, err := cfg.carrier(); err == nil {
		t.Fatal("unsupported transport accepted")
	}
}

func TestManagedSOCKSParsesDestinationWithoutLocalDNS(t *testing.T) {
	for _, tc := range []struct {
		request []byte
		want    string
	}{
		{[]byte{5, 1, 0, 3, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 1, 187}, "example:443"},
		{[]byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80}, "127.0.0.1:80"},
	} {
		client, server := net.Pipe()
		client.SetDeadline(time.Now().Add(time.Second))
		server.SetDeadline(time.Now().Add(time.Second))
		result := make(chan string, 1)
		go func() {
			defer server.Close()
			target, err := managedSOCKSTarget(server)
			if err != nil {
				result <- "error"
			} else {
				result <- target
			}
		}()
		client.Write([]byte{5, 1, 0})
		var reply [2]byte
		if _, err := io.ReadFull(client, reply[:]); err != nil {
			t.Fatal(err)
		}
		if reply != [2]byte{5, 0} {
			t.Fatal(reply)
		}
		client.Write(tc.request)
		if got := <-result; got != tc.want {
			t.Fatalf("got %q want %q", got, tc.want)
		}
		client.Close()
	}
}

// Exercises the app-facing runtime against the bundled upstream DNSTT server,
// with SOCKS and SSH upstreams, including bytes through Xray's SOCKS endpoint.
func TestManagedDNSRoundTrip(t *testing.T) {
	dir := t.TempDir()
	// The Windows test host deliberately has no Go SDK. Accept a fixture
	// cross-compiled from the pinned local source, rather than installing one.
	binary := os.Getenv("TNDTUN_TEST_DNSTT_SERVER")
	if binary == "" {
		if testing.Short() {
			t.Skip("requires a prebuilt DNSTT fixture or local Go compiler")
		}
		module, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "www.bamsoftware.com/git/dnstt.git").Output()
		if err != nil {
			t.Fatal(err)
		}
		binary = filepath.Join(dir, "dnstt-server")
		build := exec.Command("go", "build", "-o", binary, "./dnstt-server")
		build.Dir = strings.TrimSpace(string(module))
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("DNSTT server build: %v %s", err, out)
		}
	}
	for _, mode := range []string{"socks5", "ssh"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			upstream, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer upstream.Close()
			_, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			signer, err := ssh.NewSignerFromKey(private)
			if err != nil {
				t.Fatal(err)
			}
			sshConfig := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
				if c.User() == "test" && string(p) == "secret" {
					return nil, nil
				}
				return nil, fmt.Errorf("denied")
			}}
			sshConfig.AddHostKey(signer)
			go func() {
				for {
					conn, err := upstream.Accept()
					if err != nil {
						return
					}
					go func() {
						defer conn.Close()
						stop := context.AfterFunc(ctx, func() { conn.Close() })
						defer stop()
						if mode == "socks5" {
							if _, err := managedSOCKSTarget(conn); err != nil {
								return
							}
							conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
							io.Copy(conn, conn)
							return
						}
						server, channels, requests, err := ssh.NewServerConn(conn, sshConfig)
						if err != nil {
							return
						}
						defer server.Close()
						go ssh.DiscardRequests(requests)
						for channel := range channels {
							if channel.ChannelType() != "direct-tcpip" {
								channel.Reject(ssh.UnknownChannelType, "unsupported")
								continue
							}
							ch, req, err := channel.Accept()
							if err != nil {
								continue
							}
							go ssh.DiscardRequests(req)
							go func() { defer ch.Close(); io.Copy(ch, ch) }()
						}
					}()
				}
			}()
			key := make([]byte, 32)
			rand.Read(key)
			keyPath := filepath.Join(dir, "server-"+mode+".key")
			os.WriteFile(keyPath, []byte(hex.EncodeToString(key)), 0600)
			reservation, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := reservation.LocalAddr().String()
			reservation.Close()
			command := exec.CommandContext(ctx, binary, "-udp", address, "-privkey-file", keyPath, "t.example.test", upstream.Addr().String())
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cancel(); command.Wait() }()
			time.Sleep(150 * time.Millisecond)
			config := managedDNSConfig{Domain: "t.example.test", Resolver: address, PublicKey: hex.EncodeToString(noise.PubkeyFromPrivkey(key)), TunnelType: mode, Username: "test", Password: "secret", HostKey: ssh.FingerprintSHA256(signer.PublicKey())}
			raw, _ := json.Marshal(map[string]any{"provider": "managed_dns", "managed_dns": config})
			if code := KindlyTurnStart(string(raw)); code != 0 {
				t.Fatalf("start=%d", code)
			}
			defer KindlyTurnStop()
			ready := false
			for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
				var status kindlyTurnStatus
				json.Unmarshal([]byte(KindlyTurnStatus()), &status)
				if status.Ready {
					ready = true
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if !ready {
				t.Fatal("DNS/SSH did not authenticate", KindlyTurnStatus())
			}
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
				var status kindlyTurnStatus
				json.Unmarshal([]byte(KindlyTurnStatus()), &status)
				if status.ConnectedStreams == 4 {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			var pooled kindlyTurnStatus
			json.Unmarshal([]byte(KindlyTurnStatus()), &pooled)
			if pooled.ConnectedStreams != 4 {
				t.Fatalf("DNS/SSH pool did not establish four lanes: %s", KindlyTurnStatus())
			}
			dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:9002", nil, &net.Dialer{Timeout: 3 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			connection, err := dialer.Dial("tcp", "echo.test:443")
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			connection.SetDeadline(time.Now().Add(5 * time.Second))
			payload := []byte(strings.Repeat("dns-tunnel-round-trip", 40))
			if _, err := connection.Write(payload); err != nil {
				t.Fatal(err)
			}
			received := make([]byte, len(payload))
			if _, err := io.ReadFull(connection, received); err != nil {
				t.Fatal(err)
			}
			if string(received) != string(payload) {
				t.Fatal("payload mismatch")
			}
			var parallel sync.WaitGroup
			for lane := 0; lane < 8; lane++ {
				parallel.Add(1)
				go func() {
					defer parallel.Done()
					conn, err := dialer.Dial("tcp", "echo.test:443")
					if err != nil {
						t.Error(err)
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(10 * time.Second))
					data := []byte(strings.Repeat("parallel DNS data ", 256))
					wrote := make(chan error, 1)
					go func() { _, err := conn.Write(data); wrote <- err }()
					got := make([]byte, len(data))
					if _, err := io.ReadFull(conn, got); err != nil {
						t.Error(err)
					}
					if err := <-wrote; err != nil {
						t.Error(err)
					}
					if string(got) != string(data) {
						t.Error("parallel payload changed")
					}
				}()
			}
			parallel.Wait()
			started := time.Now()
			KindlyTurnStop()
			if time.Since(started) > time.Second {
				t.Fatal("active stream shutdown blocked")
			}
		})
	}
}
