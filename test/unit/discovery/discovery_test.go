package discovery

import (
	policyv1 "github.com/liqoTech/liqo/api/cluster-config/v1"
	v1 "github.com/liqoTech/liqo/api/discovery/v1"
	peering_request_operator "github.com/liqoTech/liqo/internal/peering-request-operator"
	"github.com/liqoTech/liqo/pkg/crdClient"
	"gotest.tools/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
	"os"
	ctrl "sigs.k8s.io/controller-runtime"
	"strings"
	"testing"
	"time"
)

var clientCluster *Cluster
var serverCluster *Cluster
var stopChan <-chan struct{}

func setUp() {
	stopChan = ctrl.SetupSignalHandler()

	clientCluster = getClientCluster()
	serverCluster = getServerCluster()

	clientCluster.fcReconciler.ForeignConfig = serverCluster.cfg

	SetupDNSServer()
}

func tearDown() {
	err := clientCluster.env.Stop()
	if err != nil {
		klog.Error(err, err.Error())
		os.Exit(1)
	}
	err = serverCluster.env.Stop()
	if err != nil {
		klog.Error(err, err.Error())
		os.Exit(1)
	}
}

func TestMain(m *testing.M) {
	setUp()
	defer tearDown()

	// wait cache starting
	time.Sleep(1 * time.Second)

	os.Exit(m.Run())
}

func TestDiscovery(t *testing.T) {
	t.Run("testClient", testClient)
	t.Run("testDiscoveryConfig", testDiscoveryConfig)
	t.Run("testPRConfig", testPRConfig)
	t.Run("testJoin", testJoin)
	t.Run("testDisjoin", testDisjoin)
}

// ------
// tests if environment is correctly set and creation of ForeignCluster with disabled AutoJoin
func testClient(t *testing.T) {
	tmp, err := clientCluster.client.Resource("foreignclusters").List(metav1.ListOptions{})
	assert.NilError(t, err)
	fcs, ok := tmp.(*v1.ForeignClusterList)
	assert.Equal(t, ok, true)
	assert.Equal(t, len(fcs.Items), 0)

	// create new ForeignCluster with disabled AutoJoin
	fc := &v1.ForeignCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: "fc-test",
		},
		Spec: v1.ForeignClusterSpec{
			ClusterID: "test-cluster",
			Namespace: "default",
			Join:      false,
			ApiUrl:    serverCluster.cfg.Host,
		},
	}
	_, err = clientCluster.client.Resource("foreignclusters").Create(fc, metav1.CreateOptions{})
	assert.NilError(t, err, "Error during ForeignCluster creation")

	tmp, err = clientCluster.client.Resource("foreignclusters").List(metav1.ListOptions{})
	assert.NilError(t, err)
	fcs, ok = tmp.(*v1.ForeignClusterList)
	assert.Equal(t, ok, true)
	assert.Equal(t, len(fcs.Items), 1, "Number of ForeignCluster on clientCluster is different to 1")

	tmp, err = serverCluster.client.Resource("foreignclusters").List(metav1.ListOptions{})
	assert.NilError(t, err)
	fcs, ok = tmp.(*v1.ForeignClusterList)
	assert.Equal(t, ok, true)
	assert.Equal(t, len(fcs.Items), 0, "Number of ForeignCluster on serverCluster is different to 0, is it crated in wrong cluster?!?")

	tmp, err = serverCluster.client.Resource("peeringrequests").List(metav1.ListOptions{})
	assert.NilError(t, err)
	prs, ok := tmp.(*v1.PeeringRequestList)
	assert.Equal(t, ok, true)
	assert.Equal(t, len(prs.Items), 0, "Peering Request has been created even if join flag was false")

	tmp, err = clientCluster.client.Resource("peeringrequests").List(metav1.ListOptions{})
	assert.NilError(t, err)
	prs, ok = tmp.(*v1.PeeringRequestList)
	assert.Equal(t, ok, true)
	assert.Equal(t, len(prs.Items), 0, "Peering Request has been created in client cluster")
}

// ------
// tests if discovery controller is able to load it's configs from ClusterConfigs
func testDiscoveryConfig(t *testing.T) {
	policyConfig := *clientCluster.cfg
	policyConfig.GroupVersion = &policyv1.GroupVersion
	client, err := crdClient.NewFromConfig(&policyConfig)
	assert.NilError(t, err, "Can't get CRDClient")
	err = clientCluster.discoveryCtrl.GetDiscoveryConfig(client)
	assert.NilError(t, err, "DiscoveryCtrl can't load settings")

	tmp, err := client.Resource("clusterconfigs").Get("configuration", metav1.GetOptions{})
	assert.NilError(t, err, "Can't get configurations")
	cc := tmp.(*policyv1.ClusterConfig)
	cc.Spec.DiscoveryConfig.EnableAdvertisement = false
	cc.Spec.DiscoveryConfig.EnableDiscovery = false
	tmp, err = client.Resource("clusterconfigs").Update("configuration", cc, metav1.UpdateOptions{})
	assert.NilError(t, err, "Can't update configurations")
	cc = tmp.(*policyv1.ClusterConfig)

	time.Sleep(1 * time.Second)
	assert.Equal(t, *clientCluster.discoveryCtrl.Config, cc.Spec.DiscoveryConfig)

	cc.Spec.DiscoveryConfig.EnableAdvertisement = true
	cc.Spec.DiscoveryConfig.EnableDiscovery = true
	tmp, err = client.Resource("clusterconfigs").Update("configuration", cc, metav1.UpdateOptions{})
	assert.NilError(t, err, "Can't update configurations")
	cc = tmp.(*policyv1.ClusterConfig)

	time.Sleep(1 * time.Second)
	assert.Equal(t, *clientCluster.discoveryCtrl.Config, cc.Spec.DiscoveryConfig)
}

// ------
// tests if peering request operator is able to load it's configs from configmap
func testPRConfig(t *testing.T) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "peering-request-operator-cm",
		},
		Data: map[string]string{
			"allowAll": "true",
		},
	}
	_, err := clientCluster.client.Client().CoreV1().ConfigMaps("default").Create(cm)
	assert.NilError(t, err, "Unable to create ConfigMaps")
	_, err = peering_request_operator.GetConfig(clientCluster.client, "default")
	assert.NilError(t, err, "PeeringRequest operator can't load settings from ConfigMap")
}

// ------
// tests if enabling Join flag a PeeringRequest and Broadcaster deployment are created on foreign cluster
func testJoin(t *testing.T) {
	tmp, err := clientCluster.client.Resource("foreignclusters").Get("fc-test", metav1.GetOptions{})
	assert.NilError(t, err, "Error retrieving ForeignCluster")
	fc, ok := tmp.(*v1.ForeignCluster)
	assert.Equal(t, ok, true)

	fc.Spec.Join = true
	_, err = clientCluster.client.Resource("foreignclusters").Update(fc.Name, fc, metav1.UpdateOptions{})
	assert.NilError(t, err, "I can't set Join flag to true")

	// wait reconciliation
	time.Sleep(1 * time.Second)

	tmp, err = clientCluster.client.Resource("foreignclusters").Get("fc-test", metav1.GetOptions{})
	assert.NilError(t, err, "Error retrieving ForeignCluster")
	fc, ok = tmp.(*v1.ForeignCluster)
	assert.Equal(t, ok, true)
	assert.Equal(t, fc.Status.Joined, true, "Status Joined is not true")
	assert.Assert(t, fc.Status.PeeringRequestName != "", "Peering Request name can not be empty")

	tmp, err = clientCluster.client.Resource("peeringrequests").List(metav1.ListOptions{})
	assert.NilError(t, err)
	prs, ok := tmp.(*v1.PeeringRequestList)
	assert.Equal(t, ok, true)
	assert.Equal(t, len(prs.Items), 0, "Peering Request has been created on home cluster")

	tmp, err = serverCluster.client.Resource("peeringrequests").List(metav1.ListOptions{})
	assert.NilError(t, err)
	prs, ok = tmp.(*v1.PeeringRequestList)
	assert.Equal(t, ok, true)
	assert.Equal(t, len(prs.Items), 1, "Peering Request has not been created on foreign cluster")

	deploys, err := serverCluster.client.Client().AppsV1().Deployments("default").List(metav1.ListOptions{})
	assert.NilError(t, err)
	assert.Assert(t, len(deploys.Items) > 0, "Broadcaster deployment has not been created on foreign cluster")
	assert.Assert(t, func() bool {
		for _, deploy := range deploys.Items {
			if strings.Contains(deploy.Spec.Template.Spec.Containers[0].Image, "broadcaster") {
				return true
			}
		}
		return false
	}(), "No deployment found with broadcaster image")
}

// ------
// tests if disabling Join flag PeeringRequest is deleted from foreign cluster
func testDisjoin(t *testing.T) {
	tmp, err := clientCluster.client.Resource("foreignclusters").Get("fc-test", metav1.GetOptions{})
	assert.NilError(t, err, "Error retrieving ForeignCluster")
	fc, ok := tmp.(*v1.ForeignCluster)
	assert.Equal(t, ok, true)
	assert.Equal(t, fc.Spec.Join, true, "Foreign Cluster is not in join spec")
	assert.Equal(t, fc.Status.Joined, true, "Foreign Cluster is not joined")

	fc.Spec.Join = false
	_, err = clientCluster.client.Resource("foreignclusters").Update(fc.Name, fc, metav1.UpdateOptions{})
	assert.NilError(t, err, "I can't set Join flag to false")

	// wait reconciliation
	time.Sleep(1 * time.Second)

	tmp, err = clientCluster.client.Resource("foreignclusters").Get("fc-test", metav1.GetOptions{})
	assert.NilError(t, err, "Error retrieving ForeignCluster")
	fc, ok = tmp.(*v1.ForeignCluster)
	assert.Equal(t, ok, true)
	assert.Equal(t, fc.Status.Joined, false, "Status Joined is true")
	assert.Assert(t, fc.Status.PeeringRequestName == "", "Peering Request name has to be empty")

	tmp, err = serverCluster.client.Resource("peeringrequests").List(metav1.ListOptions{})
	assert.NilError(t, err, "Error listing PeeringRequests")
	prs, ok := tmp.(*v1.PeeringRequestList)
	assert.Equal(t, ok, true)
	assert.Equal(t, len(prs.Items), 0, "Peering Request has not been deleted on foreign cluster")
}