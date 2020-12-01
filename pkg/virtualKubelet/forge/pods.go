package forge

import (
	"github.com/liqotech/liqo/pkg/virtualKubelet"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"strings"
)

const affinitySelector = "virtual-node"

func (f *apiForger) podForeignToHome(foreignObj, homeObj runtime.Object, reflectionType string) (*corev1.Pod, error) {
	var isNewObject bool

	if homeObj == nil {
		isNewObject = true

		homeObj = &corev1.Pod{
			TypeMeta:   metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{},
			Spec:       corev1.PodSpec{},
		}
	}

	foreignPod := foreignObj.(*corev1.Pod)
	homePod := homeObj.(*corev1.Pod)

	foreignNamespace, err := f.nattingTable.DeNatNamespace(foreignPod.Namespace)
	if err != nil {
		return nil, err
	}

	f.forgeHomeMeta(&foreignPod.ObjectMeta, &homePod.ObjectMeta, foreignNamespace, reflectionType)
	delete(homePod.Labels, virtualKubelet.ReflectedpodKey)

	if isNewObject {
		homePod.Spec = f.forgePodSpec(foreignPod.Spec)
	}

	return homePod, nil
}

func (f *apiForger) podStatusForeignToHome(foreignObj, homeObj runtime.Object) *corev1.Pod {
	homePod := homeObj.(*corev1.Pod)
	foreignPod := foreignObj.(*corev1.Pod)

	homePod.Status = foreignPod.Status
	if homePod.Status.PodIP != "" {
		newIp := ChangePodIp(f.remoteRemappedPodCidr.Value().ToString(), foreignPod.Status.PodIP)
		homePod.Status.PodIP = newIp
		homePod.Status.PodIPs[0].IP = newIp
	}

	return homePod
}

func (f *apiForger) podHomeToForeign(homeObj, foreignObj runtime.Object, reflectionType string) (*corev1.Pod, error) {
	var isNewObject bool
	var homePod, foreignPod *corev1.Pod

	if foreignObj == nil {
		isNewObject = true

		foreignPod = &corev1.Pod{
			TypeMeta:   metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{},
			Spec:       corev1.PodSpec{},
		}
	} else {
		foreignPod = foreignObj.(*corev1.Pod)
	}

	homePod = homeObj.(*corev1.Pod)

	foreignNamespace, err := f.nattingTable.NatNamespace(homePod.Namespace, true)
	if err != nil {
		return nil, err
	}

	f.forgeForeignMeta(&homePod.ObjectMeta, &foreignPod.ObjectMeta, foreignNamespace, reflectionType)

	if isNewObject {
		foreignPod.Spec = f.forgePodSpec(homePod.Spec)
		foreignPod.Spec.Affinity = forgeAffinity()
	}

	return foreignPod, nil
}

func (f *apiForger) forgePodSpec(inputPodSpec corev1.PodSpec) corev1.PodSpec {
	outputPodSpec := corev1.PodSpec{}

	outputPodSpec.Volumes = forgeVolumes(inputPodSpec.Volumes)
	outputPodSpec.InitContainers = forgeContainers(inputPodSpec.InitContainers, outputPodSpec.Volumes)
	outputPodSpec.Containers = forgeContainers(inputPodSpec.Containers, outputPodSpec.Volumes)

	return outputPodSpec
}

func forgeContainers(inputContainers []corev1.Container, inputVolumes []corev1.Volume) []corev1.Container {
	containers := make([]corev1.Container, 0)

	for _, container := range inputContainers {
		volumeMounts := filterVolumeMounts(inputVolumes, container.VolumeMounts)
		containers = append(containers, translateContainer(container, volumeMounts))
	}

	return containers
}

func translateContainer(container corev1.Container, volumes []corev1.VolumeMount) corev1.Container {
	return corev1.Container{
		Name:            container.Name,
		Image:           container.Image,
		Command:         container.Command,
		Args:            container.Args,
		WorkingDir:      container.WorkingDir,
		Ports:           container.Ports,
		Env:             container.Env,
		Resources:       container.Resources,
		LivenessProbe:   container.LivenessProbe,
		ReadinessProbe:  container.ReadinessProbe,
		StartupProbe:    container.StartupProbe,
		SecurityContext: container.SecurityContext,
		VolumeMounts:    volumes,
	}
}

func forgeVolumes(volumesIn []corev1.Volume) []corev1.Volume {
	volumesOut := make([]corev1.Volume, 0)
	for _, v := range volumesIn {
		if v.ConfigMap != nil || v.EmptyDir != nil || v.DownwardAPI != nil {
			volumesOut = append(volumesOut, v)
		}
		// copy all volumes of type Secret except for the default token
		if v.Secret != nil && !strings.Contains(v.Secret.SecretName, "default-token") {
			volumesOut = append(volumesOut, v)
		}
	}
	return volumesOut
}

// remove from volumeMountsIn all the volumeMounts with name not contained in volumes
func filterVolumeMounts(volumes []corev1.Volume, volumeMountsIn []corev1.VolumeMount) []corev1.VolumeMount {
	volumeMounts := make([]corev1.VolumeMount, 0)
	for _, vm := range volumeMountsIn {
		for _, v := range volumes {
			if vm.Name == v.Name {
				volumeMounts = append(volumeMounts, vm)
			}
		}
	}
	return volumeMounts
}

func ChangePodIp(newPodCidr string, oldPodIp string) (newPodIp string) {
	if newPodCidr == "" {
		return oldPodIp
	}
	//the last two slices are the suffix of the newPodIp
	oldPodIpTokenized := strings.Split(oldPodIp, ".")
	newPodCidrTokenized := strings.Split(newPodCidr, "/")
	//the first two slices are the prefix of the newPodIP
	ipFromPodCidrTokenized := strings.Split(newPodCidrTokenized[0], ".")
	//used to build the new IP
	var newPodIpBuilder strings.Builder
	for i, s := range ipFromPodCidrTokenized {
		if i < 2 {
			newPodIpBuilder.WriteString(s)
			newPodIpBuilder.WriteString(".")
		}
	}
	for i, s := range oldPodIpTokenized {
		if i > 1 && i < 4 {
			newPodIpBuilder.WriteString(s)
			newPodIpBuilder.WriteString(".")
		}
	}
	return strings.TrimSuffix(newPodIpBuilder.String(), ".")
}

func forgeAffinity() *corev1.Affinity {
	return &corev1.Affinity{
		NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{
					{
						MatchExpressions: []corev1.NodeSelectorRequirement{
							{
								Key:      "type",
								Operator: corev1.NodeSelectorOpNotIn,
								Values:   []string{affinitySelector},
							},
						},
					},
				},
			},
		},
	}
}
