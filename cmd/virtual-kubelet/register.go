package main

import (
	"github.com/virtual-kubelet/virtual-kubelet/cmd/virtual-kubelet/internal/provider"
	"github.com/virtual-kubelet/virtual-kubelet/cmd/virtual-kubelet/internal/provider/mock"
)

func registerMock(s *provider.Store) {
	s.Register("mock", func(cfg provider.InitConfig) (provider.Provider, error) { //nolint:errcheck
		return mock.NewMockProvider(
			cfg.ConfigPath,
			cfg.NodeName,
			cfg.OperatingSystem,
			cfg.InternalIP,
			cfg.DaemonPort,
		)
	})

	s.RegisterAPIServer("mock", func() (*provider.OverlayAPIServerConfig, error) { //nolint:errcheck
		return &provider.OverlayAPIServerConfig{
			CertPath: "/root/virtual-kubelet/hack/skaffold/virtual-kubelet/vkubelet-mock-0-crt.pem",
			KeyPath:  "/root/virtual-kubelet/hack/skaffold/virtual-kubelet/vkubelet-mock-0-key.pem",
		}, nil

	})
}
