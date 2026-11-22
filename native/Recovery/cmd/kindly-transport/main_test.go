package main

import (
	"bufio"
	"io"
	"strings"
	"testing"
)

func TestManagedConfigurationKeepsLifetimePipe(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader("{\"version\":1}\nlifetime"), 64*1024+2)
	raw, err := readConfiguration(r, true)
	if err != nil || string(raw) != "{\"version\":1}" {
		t.Fatalf("framing: %q %v", raw, err)
	}
	rest, _ := io.ReadAll(r)
	if string(rest) != "lifetime" {
		t.Fatal("consumed lifetime pipe")
	}
}

func TestManagedConfigurationRequiresBoundedCompleteLine(t *testing.T) {
	for _, input := range []string{"{}", strings.Repeat("x", 64*1024+3) + "\n"} {
		_, err := readConfiguration(bufio.NewReaderSize(strings.NewReader(input), 64*1024+2), true)
		if err == nil {
			t.Fatal("accepted unterminated or oversized line")
		}
	}
}
