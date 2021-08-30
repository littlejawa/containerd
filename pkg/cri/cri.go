/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package cri

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/pkg/cri/sbserver"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/plugin"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
	"k8s.io/klog/v2"

	criconfig "github.com/containerd/containerd/pkg/cri/config"
	"github.com/containerd/containerd/pkg/cri/constants"
	"github.com/containerd/containerd/pkg/cri/server"
	cristore "github.com/containerd/containerd/pkg/cri/store/service"
)

// Register CRI service plugin
func init() {
	config := criconfig.DefaultConfig()
	plugin.Register(&plugin.Registration{
		Type:   plugin.GRPCPlugin,
		ID:     "cri",
		Config: &config,
		Requires: []plugin.Type{
			plugin.EventPlugin,
			plugin.CRIPlugin,
			plugin.CRIServicePlugin,
		},
		InitFn: initCRIService,
	})
}

func initCRIService(ic *plugin.InitContext) (interface{}, error) {
	ic.Meta.Platforms = []imagespec.Platform{platforms.DefaultSpec()}
	ic.Meta.Exports = map[string]string{"CRIVersion": constants.CRIVersion, "CRIVersionAlpha": constants.CRIVersionAlpha}
	ctx := ic.Context
	pluginConfig := ic.Config.(*criconfig.PluginConfig)
	if err := criconfig.ValidatePluginConfig(ctx, pluginConfig); err != nil {
		return nil, fmt.Errorf("invalid plugin config: %w", err)
	}

	c := criconfig.Config{
		PluginConfig:       *pluginConfig,
		ContainerdRootDir:  filepath.Dir(ic.Root),
		ContainerdEndpoint: ic.Address,
		RootDir:            ic.Root,
		StateDir:           ic.State,
	}
	log.G(ctx).Infof("Start cri plugin with config %+v", c)

	if err := setGLogLevel(); err != nil {
		return nil, fmt.Errorf("failed to set glog level: %w", err)
	}

	criStore, err := getCRIStore(ic)
	if err != nil {
		return nil, fmt.Errorf("failed to get CRI store services: %w", err)
	}
	criPlugins, err := getCRIPlugin(ic)
	if err != nil && !errors.Is(err, errdefs.ErrNotFound) {
		return nil, fmt.Errorf("failed to get CRI plugin: %w", err)
	}

	log.G(ctx).Info("Connect containerd service")
	client, err := containerd.New(
		"",
		containerd.WithDefaultNamespace(constants.K8sContainerdNamespace),
		containerd.WithDefaultPlatform(platforms.Default()),
		containerd.WithInMemoryServices(ic),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create containerd client: %w", err)
	}

	var manager server.CRIService
	if os.Getenv("ENABLE_CRI_SANDBOXES") != "" {
		log.G(ctx).Info("using experimental CRI Sandbox server - unset ENABLE_CRI_SANDBOXES to disable")
		manager, err = sbserver.NewCRIManager(c, client, criStore)
	} else {
		log.G(ctx).Info("using legacy CRI server")
		manager, err = server.NewCRIManager(c, client, criStore, criPlugins)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create CRI service: %w", err)
	}

	go func() {
		if err := manager.Run(); err != nil {
			log.G(ctx).WithError(err).Fatal("Failed to run CRI manager")
		}
		// TODO(random-liu): Whether and how we can stop containerd.
	}()
	return manager, nil
}

func getCRIStore(ic *plugin.InitContext) (*cristore.Store, error) {
	plugins, err := ic.GetByType(plugin.CRIServicePlugin)
	if err != nil {
		return nil, fmt.Errorf("failed to get cri store: %w", err)
	}
	p := plugins[cristore.CRIStoreService]
	if p == nil {
		return nil, fmt.Errorf("cri service store not found")
	}
	i, err := p.Instance()
	if err != nil {
		return nil, fmt.Errorf("failed to get instance of cri service store: %w", err)
	}
	return i.(*cristore.Store), nil
}

// getCRIPlugin get cri services from plugin context
func getCRIPlugin(ic *plugin.InitContext) (map[string]server.CRIPlugin, error) {
	criPlugins := map[string]server.CRIPlugin{}
	plugins, err := ic.GetByType(plugin.CRIPlugin)
	if err != nil {
		return criPlugins, fmt.Errorf("failed to get cri plugin: %w", err)
	}
	for k, v := range plugins {
		i, err := v.Instance()
		if err != nil {
			return nil, fmt.Errorf("failed to get instance of service %q: %w", k, err)
		}
		// plugin.Registration.ID as key
		criPlugins[k] = i.(server.CRIPlugin)
	}
	return criPlugins, nil
}

// Set glog level.
func setGLogLevel() error {
	l := logrus.GetLevel()
	fs := flag.NewFlagSet("klog", flag.PanicOnError)
	klog.InitFlags(fs)
	if err := fs.Set("logtostderr", "true"); err != nil {
		return err
	}
	switch l {
	case logrus.TraceLevel:
		return fs.Set("v", "5")
	case logrus.DebugLevel:
		return fs.Set("v", "4")
	case logrus.InfoLevel:
		return fs.Set("v", "2")
	// glog doesn't support following filters. Defaults to v=0.
	case logrus.WarnLevel:
	case logrus.ErrorLevel:
	case logrus.FatalLevel:
	case logrus.PanicLevel:
	}
	return nil
}
