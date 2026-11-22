package libXray

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGeneratedIOSConfigurations(t *testing.T) {
	directory := os.Getenv("KINDLYVPN_CONFIG_FIXTURES")
	if directory == "" {
		t.Skip("Run Scripts/verify-parity.sh --native to generate Swift configurations")
	}
	files, err := filepath.Glob(filepath.Join(directory, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("No configuration fixtures: %v", err)
	}
	for _, path := range files {
		t.Run(filepath.Base(path), func(t *testing.T) {
			request, err := json.Marshal(runXrayRequest{ConfigPath: path, DatDir: os.Getenv("KINDLYVPN_GEO_DIR")})
			if err != nil {
				t.Fatal(err)
			}
			raw, err := base64.StdEncoding.DecodeString(TestXray(base64.StdEncoding.EncodeToString(request)))
			if err != nil {
				t.Fatal(err)
			}
			var response callResponse
			if err := json.Unmarshal(raw, &response); err != nil {
				t.Fatal(err)
			}
			if !response.Success {
				t.Fatalf("Native Xray rejected iOS configuration: %s", response.Error)
			}
		})
	}
}
