package provider

import (
	"context"
	"github.com/liqotech/liqo/internal/virtualKubelet/node"
	"github.com/liqotech/liqo/pkg/virtualKubelet/forge"
	"github.com/liqotech/liqo/pkg/virtualKubelet/namespacesMapping"
	"github.com/liqotech/liqo/pkg/virtualKubelet/namespacesMapping/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

var _ = Describe("Pods", func() {
	var (
		provider              node.PodLifecycleHandler
		namespaceMapper       namespacesMapping.MapperController
		namespaceNattingTable *test.MockNamespaceMapper
		foreignClient         kubernetes.Interface
	)

	BeforeEach(func() {
		foreignClient = fake.NewSimpleClientset()
		namespaceNattingTable = &test.MockNamespaceMapper{Cache: map[string]string{}}
		namespaceNattingTable.Cache["homeNamespace"] = "homeNamespace-natted"
		namespaceMapper = test.NewMockNamespaceMapperController(namespaceNattingTable)
		provider = &LiqoProvider{
			namespaceMapper: namespaceMapper,
			foreignClient:   foreignClient,
		}
	})

	Context("with legit input pod", func() {
		var (
			pod *corev1.Pod
		)

		When("writing functions", func() {

			BeforeEach(func() {
				pod = &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "testObject",
						Namespace: "homeNamespace",
					},
				}

				forge.InitForger(namespaceMapper)
			})

			It("create pod", func() {
				err := provider.CreatePod(context.TODO(), pod)
				Expect(err).NotTo(HaveOccurred())
				rs, err := foreignClient.AppsV1().ReplicaSets("homeNamespace-natted").Get(context.TODO(), "testObject", metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				Expect(rs.Name).To(Equal(pod.Name))
				Expect(rs.Namespace).To(Equal("homeNamespace-natted"))
			})

			It("update pod", func() {
				err := provider.UpdatePod(context.TODO(), pod)
				Expect(err).NotTo(HaveOccurred())
			})

			Describe("delete pod", func() {
				var replicaset *appsv1.ReplicaSet

				BeforeEach(func() {
					replicaset = &appsv1.ReplicaSet{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "testObject",
							Namespace: "homeNamespace-natted",
						},
					}
				})

				It("with corresponding replicaset existing", func() {
					_, _ = foreignClient.AppsV1().ReplicaSets("homeNamespace-natted").Create(context.TODO(), replicaset, metav1.CreateOptions{})
					err := provider.DeletePod(context.TODO(), pod)
					Expect(err).NotTo(HaveOccurred())
				})

				It("without corresponding replicaset existing", func() {
					err := provider.DeletePod(context.TODO(), pod)
					Expect(err).To(HaveOccurred())
				})
			})
		})
	})

	Context("with nil input pod", func() {

		It("create pod", func() {
			err := provider.CreatePod(context.TODO(), nil)
			Expect(err).To(HaveOccurred())
		})

		It("update pod", func() {
			err := provider.UpdatePod(context.TODO(), nil)
			Expect(err).To(HaveOccurred())
		})

		It("delete pod", func() {
			err := provider.CreatePod(context.TODO(), nil)
			Expect(err).To(HaveOccurred())
		})
	})
})
