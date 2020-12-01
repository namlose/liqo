package auth_service

import (
	configv1alpha1 "github.com/liqotech/liqo/apis/config/v1alpha1"
	"github.com/liqotech/liqo/pkg/clusterConfig"
)

func (authService *AuthServiceCtrl) GetAuthServiceConfig(kubeconfigPath string) error {
	waitFirst := make(chan bool)
	isFirst := true
	go clusterConfig.WatchConfiguration(func(configuration *configv1alpha1.ClusterConfig) {
		authService.handleConfiguration(configuration.Spec.AuthConfig)
		if isFirst {
			waitFirst <- true
			isFirst = false
		}
	}, nil, kubeconfigPath)
	<-waitFirst
	close(waitFirst)

	return nil
}

func (authService *AuthServiceCtrl) handleConfiguration(config configv1alpha1.AuthConfig) {
	authService.configMutex.Lock()
	defer authService.configMutex.Unlock()
	authService.config = config
}

func (authService *AuthServiceCtrl) GetConfig() configv1alpha1.AuthConfig {
	authService.configMutex.RLock()
	defer authService.configMutex.RUnlock()
	return authService.config
}
