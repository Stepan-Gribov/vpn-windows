// native-check verifies that the Windows transport stack loads without starting
// a tunnel, opening a driver, modifying routes, or reading user configuration.
package main

import (
	"encoding/json"
	"os"
	"runtime"

	libXray "kindlyvpn/native"
)

func main() {
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{
		"platform":     runtime.GOOS,
		"architecture": runtime.GOARCH,
		"go_version":   runtime.Version(),
		"xray_version": libXray.XrayVersion(),
		"vpn_started":  false,
		"purpose":      "native transport load check; not the finished TnDtun application",
	}); err != nil {
		os.Exit(1)
	}
}
