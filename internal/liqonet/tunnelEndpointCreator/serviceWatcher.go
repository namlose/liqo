package tunnelEndpointCreator

import (
	"context"
	netv1alpha1 "github.com/liqotech/liqo/apis/net/v1alpha1"
	"github.com/liqotech/liqo/internal/crdReplicator"
	"github.com/liqotech/liqo/pkg/liqonet/tunnel/wireguard"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"strconv"
	"strings"
)

var (
	serviceResource      = "services"
	serviceLabelKey      = "net.liqo.io/tunnelEndpoint"
	serviceLabelValue    = "true"
	serviceAnnotationKey = "net.liqo.io/gatewayNodeIP"
)

func (tec *TunnelEndpointCreator) StartServiceWatcher() {
	chacheChan := make(chan struct{})
	started := tec.Manager.GetCache().WaitForCacheSync(chacheChan)
	if !started {
		klog.Errorf("unable to sync caches")
		return
	}

	dynFactory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(tec.DynClient, 0, tec.Namespace, setServiceFilteringLabel)
	go tec.Watcher(dynFactory, corev1.SchemeGroupVersion.WithResource(serviceResource), cache.ResourceEventHandlerFuncs{
		AddFunc:    tec.serviceHandlerAdd,
		UpdateFunc: tec.serviceHandlerUpdate,
	}, tec.secretClusterStopChan)
}

func (tec *TunnelEndpointCreator) serviceHandlerAdd(obj interface{}) {
	tec.Mutex.Lock()
	defer tec.Mutex.Unlock()
	var endpointIP, endpointPort string
	objUnstruct, ok := obj.(*unstructured.Unstructured)
	if !ok {
		klog.Errorf("an error occurred while converting interface to unstructured object")
		return
	}
	s := &corev1.Service{}
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(objUnstruct.Object, s)
	if err != nil {
		klog.Errorf("an error occurred while converting resource %s of type %s to typed object: %s", objUnstruct.GetName(), objUnstruct.GetKind(), err)
		return
	}

	if s.Spec.Type != corev1.ServiceTypeNodePort && s.Spec.Type != corev1.ServiceTypeLoadBalancer {
		klog.Errorf("the service %s in namespace %s is of type %s, only types of %s and %s are accepted", s.GetName(), s.GetNamespace(), s.Spec.Type, corev1.ServiceTypeLoadBalancer, corev1.ServiceTypeNodePort)
		return
	}

	//first we check the service's type
	if s.Spec.Type == corev1.ServiceTypeNodePort {
		//check if the node's IP where the gatewayPod is running has been set
		nodeIP, found := s.GetAnnotations()[serviceAnnotationKey]
		if !found {
			klog.Infof("the node IP where the gatewayPod is running not set yet as an annotation for service %s in namespace %s", s.GetName(), s.GetNamespace())
			return
		}
		endpointIP = nodeIP
		//check if the nodePort for wireguard has been set
		for _, port := range s.Spec.Ports {
			if port.Name == wireguard.DriverName {
				if port.NodePort == 0 {
					klog.Infof("the nodePort for service %s in namespace %s not set yet", s.GetName(), s.GetNamespace())
					return
				}
				endpointPort = strconv.Itoa(int(port.NodePort))
			} else {
				klog.Infof("the service %s of type nodePort with label %s set to %s does not have a port named %s", s.Name, serviceLabelKey, serviceLabelValue, wireguard.DriverName)
				return
			}
		}
	}
	if s.Spec.Type == corev1.ServiceTypeLoadBalancer {
		//check if the ingress IP has been set
		if len(s.Status.LoadBalancer.Ingress) == 0 {
			klog.Infof("ingress IPs has not been set for service %s in namespace %s of type %s", s.GetName(), s.GetNamespace())
			return
		}
		endpointIP = s.Status.LoadBalancer.Ingress[0].IP

		for _, port := range s.Spec.Ports {
			if port.Name == wireguard.DriverName {
				if port.Port == 0 {
					klog.Infof("the nodePort for service %s in namespace %s not set yet", s.GetName(), s.GetNamespace())
					return
				}
				endpointPort = strconv.Itoa(int(port.Port))
			} else {
				klog.Infof("the service %s of type loadBalancer with label %s set to %s does not have a port named %s", s.Name, serviceLabelKey, serviceLabelValue, wireguard.DriverName)
				return
			}
		}
	}
	if endpointIP != tec.EndpointIP || endpointPort != tec.EndpointPort {
		tec.EndpointPort = endpointPort
		tec.EndpointIP = endpointIP
		if !tec.svcConfigured{
			tec.WaitConfig.Done()
			klog.Infof("called done on waitgroup")
			tec.svcConfigured = true
		}
		netConfigs := &netv1alpha1.NetworkConfigList{}
		labels := client.MatchingLabels{crdReplicator.LocalLabelSelector: "true"}
		err = tec.Client.List(context.Background(), netConfigs, labels)
		if err != nil {
			klog.Errorf("unable to retrieve the existing resources of type %s in order to update the publicKey for the vpn backend: %v", netv1alpha1.NetworkConfigGroupResource.String(), err)
			return
		}
		for _, nc := range netConfigs.Items {
			retryError := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				var netConfig netv1alpha1.NetworkConfig
				err := tec.Get(context.Background(), client.ObjectKey{
					Name: nc.GetName(),
				}, &netConfig)
				if err != nil {
					klog.Errorf("an error occurred while retrieving resource of type %s named %s: %v", netv1alpha1.NetworkConfigGroupResource.String(), nc.GetName(), err)
					return err
				}
				netConfig.Spec.BackendConfig[wireguard.ListeningPort] = endpointPort
				netConfig.Spec.EndpointIP = endpointIP
				err = tec.Update(context.Background(), &netConfig)
				return err
			})
			if retryError != nil {
				klog.Errorf("an error occurred while updating spec of networkConfig resource %s: %s", nc.GetName(), retryError)
			}
		}
		return
	}
	return
}

func (tec *TunnelEndpointCreator) serviceHandlerUpdate(oldObj interface{}, newObj interface{}) {
	tec.serviceHandlerAdd(newObj)
}

func setServiceFilteringLabel(options *metav1.ListOptions) {
	if options.LabelSelector == "" {
		newLabelSelector := []string{serviceLabelKey, "=", serviceLabelValue}
		options.LabelSelector = strings.Join(newLabelSelector, "")
	} else {
		newLabelSelector := []string{options.LabelSelector, serviceLabelKey, "=", serviceLabelValue}
		options.LabelSelector = strings.Join(newLabelSelector, "")
	}
}
