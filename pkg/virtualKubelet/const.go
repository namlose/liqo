package virtualKubelet

type ContextKey string

const (
	VirtualNodePrefix       = "liqo-"
	VirtualKubeletPrefix    = "virtual-kubelet-"
	VirtualKubeletSecPrefix = "vk-kubeconfig-secret-"
	AdvertisementPrefix     = "advertisement-"
	ReflectedpodKey         = "virtualkubelet.liqo.io/source-pod"
)
