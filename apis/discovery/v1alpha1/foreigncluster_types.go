/*


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

package v1alpha1

import (
	advtypes "github.com/liqotech/liqo/apis/sharing/v1alpha1"
	"github.com/liqotech/liqo/pkg/crdClient"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

type DiscoveryType string

const (
	LanDiscovery             DiscoveryType = "LAN"
	WanDiscovery             DiscoveryType = "WAN"
	ManualDiscovery          DiscoveryType = "Manual"
	IncomingPeeringDiscovery DiscoveryType = "IncomingPeering"
)

type TrustMode string

const (
	TrustModeUnknown   TrustMode = "Unknown"
	TrustModeTrusted   TrustMode = "Trusted"
	TrustModeUntrusted TrustMode = "Untrusted"
)

type AuthStatus string

const (
	AuthStatusPending      AuthStatus = "Pending"
	AuthStatusAccepted     AuthStatus = "Accepted"
	AuthStatusRefused      AuthStatus = "Refused"
	AuthStatusEmptyRefused AuthStatus = "EmptyRefused"
)

const (
	LastUpdateAnnotation string = "LastUpdate"
)

// ForeignClusterSpec defines the desired state of ForeignCluster
type ForeignClusterSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Foreign Cluster Identity
	ClusterIdentity ClusterIdentity `json:"clusterIdentity"`
	// Namespace where Liqo is deployed
	Namespace string `json:"namespace"`
	// Enable join process to foreign cluster
	Join bool `json:"join"`
	// URL where to contact foreign API server
	ApiUrl string `json:"apiUrl"`
	// How this ForeignCluster has been discovered
	DiscoveryType DiscoveryType `json:"discoveryType"`
	// URL where to contact foreign Auth service
	AuthUrl string `json:"authUrl"`
}

type ClusterIdentity struct {
	// Foreign Cluster ID, this is a unique identifier of that cluster
	ClusterID string `json:"clusterID"`
	// Foreign Cluster Name to be shown in GUIs
	ClusterName string `json:"clusterName,omitempty"`
}

// ForeignClusterStatus defines the observed state of ForeignCluster
type ForeignClusterStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	Outgoing Outgoing `json:"outgoing,omitempty"`
	Incoming Incoming `json:"incoming,omitempty"`
	// If discoveryType is LAN and this counter reach 0 value, this FC will be removed
	Ttl uint32 `json:"ttl,omitempty"`
	// +kubebuilder:validation:Enum="Unknown";"Trusted";"Untrusted"
	// +kubebuilder:default="Unknown"
	// Indicates if this remote cluster is trusted or not
	TrustMode TrustMode `json:"trustMode,omitempty"`
	// It stores most important network statuses
	Network Network `json:"network,omitempty"`
	// Authentication status
	// +kubebuilder:validation:Enum="Pending";"Accepted";"Refused";"EmptyRefused"
	// +kubebuilder:default="Pending"
	AuthStatus AuthStatus `json:"authStatus,omitempty"`
}

type ResourceLink struct {
	// Indicates if the resource is available
	Available bool `json:"available"`
	// Object Reference to the resource
	Reference *v1.ObjectReference `json:"reference,omitempty"`
}

type Network struct {
	// Local NetworkConfig link
	LocalNetworkConfig ResourceLink `json:"localNetworkConfig"`
	// Remote NetworkConfig link
	RemoteNetworkConfig ResourceLink `json:"remoteNetworkConfig"`
	// TunnelEndpoint link
	TunnelEndpoint ResourceLink `json:"tunnelEndpoint"`
}

type Outgoing struct {
	// Indicates if peering request has been created and this remote cluster is sharing its resources to us
	Joined bool `json:"joined"`
	// Name of created PR
	RemotePeeringRequestName string `json:"remote-peering-request-name,omitempty"`
	// Object Reference to retrieved CaData Secret
	CaDataRef *v1.ObjectReference `json:"caDataRef,omitempty"`
	// Object Reference to obtained role
	RoleRef *v1.ObjectReference `json:"roleRef,omitempty"`
	// Object Reference to created Advertisement CR
	Advertisement *v1.ObjectReference `json:"advertisement,omitempty"`
	// Indicates if related identity is available
	AvailableIdentity bool `json:"availableIdentity,omitempty"`
	// Object reference to related identity
	IdentityRef *v1.ObjectReference `json:"identityRef,omitempty"`
	// Advertisement status
	AdvertisementStatus advtypes.AdvPhase `json:"advertisementStatus,omitempty"`
}

type Incoming struct {
	// Indicates if peering request has been created and this remote cluster is using our local resources
	Joined bool `json:"joined"`
	// Object Reference to created PeeringRequest CR
	PeeringRequest *v1.ObjectReference `json:"peeringRequest,omitempty"`
	// Indicates if related identity is available
	AvailableIdentity bool `json:"availableIdentity,omitempty"`
	// Object reference to related identity
	IdentityRef *v1.ObjectReference `json:"identityRef,omitempty"`
	// Status of Advertisement created from this PeeringRequest
	AdvertisementStatus advtypes.AdvPhase `json:"advertisementStatus,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster

// ForeignCluster is the Schema for the foreignclusters API
type ForeignCluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ForeignClusterSpec   `json:"spec,omitempty"`
	Status ForeignClusterStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ForeignClusterList contains a list of ForeignCluster
type ForeignClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ForeignCluster `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ForeignCluster{}, &ForeignClusterList{})

	if err := AddToScheme(scheme.Scheme); err != nil {
		panic(err)
	}
	crdClient.AddToRegistry("foreignclusters", &ForeignCluster{}, &ForeignClusterList{}, nil, schema.GroupResource{
		Group:    GroupVersion.Group,
		Resource: "foreignclusters",
	})
}
