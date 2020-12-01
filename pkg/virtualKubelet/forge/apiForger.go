package forge

import (
	"errors"
	"github.com/liqotech/liqo/pkg/virtualKubelet/namespacesMapping"
	"github.com/liqotech/liqo/pkg/virtualKubelet/options"
	"github.com/liqotech/liqo/pkg/virtualKubelet/options/types"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1beta1 "k8s.io/api/discovery/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
)

func ForeignToHomeStatus(foreignObj, homeObj runtime.Object) (runtime.Object, error) {
	switch foreignObj.(type) {
	case *corev1.Pod:
		return forger.podStatusForeignToHome(foreignObj, homeObj), nil
	}

	return nil, errors.New("unknown received api")
}

func ForeignToHome(foreignObj, homeObj runtime.Object, reflectionType string) (runtime.Object, error) {
	switch foreignObj.(type) {
	case *corev1.Pod:
		return forger.podForeignToHome(foreignObj, homeObj, reflectionType)
	}

	return nil, errors.New("unknown received api")
}

func HomeToForeign(homeObj, foreignObj runtime.Object, reflectionType string) (runtime.Object, error) {
	switch homeObj.(type) {
	case *corev1.ConfigMap:
		return forger.configmapHomeToForeign(homeObj.(*corev1.ConfigMap), foreignObj.(*corev1.ConfigMap))
	case *discoveryv1beta1.EndpointSlice:
		return forger.endpointsliceHomeToForeign(homeObj.(*discoveryv1beta1.EndpointSlice), foreignObj.(*discoveryv1beta1.EndpointSlice))
	case *corev1.Pod:
		return forger.podHomeToForeign(homeObj, foreignObj, reflectionType)
	case *corev1.Service:
		return forger.serviceHomeToForeign(homeObj.(*corev1.Service), foreignObj.(*corev1.Service))
	}

	return nil, errors.New("unknown received api")
}

func ReplicasetFromPod(pod *corev1.Pod) *appsv1.ReplicaSet {
	return forger.replicasetFromPod(pod)
}

type apiForger struct {
	nattingTable namespacesMapping.NamespaceNatter

	localRemappedPodCidr  options.ReadOnlyOption
	remoteRemappedPodCidr options.ReadOnlyOption
	virtualNodeName       options.ReadOnlyOption
}

var forger apiForger

func InitForger(nattingTable namespacesMapping.NamespaceNatter, opts ...options.ReadOnlyOption) {
	forger.nattingTable = nattingTable

	for _, opt := range opts {
		switch opt.Key() {
		case types.LocalRemappedPodCIDR:
			forger.localRemappedPodCidr = opt
		case types.RemoteRemappedPodCIDR:
			forger.remoteRemappedPodCidr = opt
		case types.VirtualNodeName:
			forger.virtualNodeName = opt
		}
	}
}
