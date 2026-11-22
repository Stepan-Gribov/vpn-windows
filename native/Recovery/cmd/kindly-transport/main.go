package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/KindlyVPN/foundation/transports"
)

func main() {
	// Provider library logs can contain room URLs. This process exposes only
	// structured, redacted transport events on stdout.
	log.SetOutput(io.Discard)
	// Secrets arrive over stdin, never process arguments or diagnostic output.
	managed := len(os.Args) == 2 && os.Args[1] == "--managed"
	reader := bufio.NewReaderSize(os.Stdin, transports.MaxConfigBytes+2)
	raw, err := readConfiguration(reader, managed)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration read failed")
		os.Exit(2)
	}
	cfg, err := transports.ParseConfig(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if len(os.Args) == 2 && os.Args[1] == "--check" {
		fmt.Println("Configuration valid")
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	if managed {
		// Desktop retains the pipe after sending one compact JSON line. EOF also
		// stops the helper if the GUI crashes, without platform-specific PID races.
		go func() { io.Copy(io.Discard, reader); stop() }()
	}
	encoder := json.NewEncoder(os.Stdout)
	err = transports.Run(ctx, cfg, func(status transports.Status) { encoder.Encode(status) })
	if err != nil && ctx.Err() == nil {
		fmt.Fprintln(os.Stderr, "recovery routes unavailable")
		os.Exit(1)
	}
}

func readConfiguration(reader *bufio.Reader, managed bool) ([]byte, error) {
	if !managed {
		return io.ReadAll(io.LimitReader(reader, transports.MaxConfigBytes+1))
	}
	line, err := reader.ReadSlice('\n')
	return bytes.TrimSuffix(line, []byte{'\n'}), err
}
