//go:build !conference

package transports

import (
	"context"
	"errors"
)

const ConferenceAvailable = false

func openConference(context.Context, ConferenceConfig, []string) (session, error) {
	return nil, errors.New("conference support requires a build with -tags conference")
}
func RunConferenceServer(context.Context, ConferenceConfig, []string) error {
	return errors.New("conference support requires a build with -tags conference")
}
