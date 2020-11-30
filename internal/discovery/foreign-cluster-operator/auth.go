package foreign_cluster_operator

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	discoveryv1alpha1 "github.com/liqotech/liqo/apis/discovery/v1alpha1"
	"github.com/liqotech/liqo/pkg/auth"
	"github.com/liqotech/liqo/pkg/crdClient"
	"github.com/liqotech/liqo/pkg/kubeconfig"
	"io/ioutil"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	client_scheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/klog"
	"net/http"
	"strings"
)

func (r *ForeignClusterReconciler) getRemoteClient(fc *discoveryv1alpha1.ForeignCluster, gv *schema.GroupVersion) (*crdClient.CRDClient, error) {
	if fc.Status.Outgoing.RoleRef != nil {
		roleSecret, err := r.crdClient.Client().CoreV1().Secrets(r.Namespace).Get(context.TODO(), fc.Status.Outgoing.RoleRef.Name, metav1.GetOptions{})
		if err != nil {
			klog.Error(err)
			// delete reference, in this way at next iteration it will be reloaded
			fc.Status.Outgoing.RoleRef = nil
			_, err2 := r.Update(fc)
			if err2 != nil {
				klog.Error(err2)
			}
			return nil, err
		}

		config, err := kubeconfig.LoadFromSecret(roleSecret)
		if err != nil {
			klog.Error(err)
			return nil, err
		}
		config.ContentConfig.GroupVersion = gv
		config.APIPath = "/apis"
		config.NegotiatedSerializer = client_scheme.Codecs.WithoutConversion()
		config.UserAgent = rest.DefaultKubernetesUserAgent()

		return crdClient.NewFromConfig(config)
	}

	if fc.Status.AuthStatus == discoveryv1alpha1.AuthStatusAccepted {
		// TODO: handle this possibility
		err := errors.New("auth status is accepted but there is no role ref")
		klog.Error(err)
		return nil, err
	}

	// not existing role
	if fc.Status.AuthStatus == discoveryv1alpha1.AuthStatusPending || (fc.Status.AuthStatus == discoveryv1alpha1.AuthStatusEmptyRefused && r.getAuthToken(fc) != "") {
		kubeconfigStr, err := r.askRemoteRole(fc)
		if err != nil {
			klog.Error(err)
			return nil, err
		}
		if kubeconfigStr == "" {
			return nil, nil
		}
		roleSecret, err := kubeconfig.CreateSecret(r.crdClient.Client(), r.Namespace, kubeconfigStr, map[string]string{
			"cluster-id":       fc.Spec.ClusterIdentity.ClusterID,
			"liqo-remote-role": "",
		})
		if err != nil {
			klog.Error(err)
			return nil, err
		}

		// set ref in the FC
		fc.Status.Outgoing.RoleRef = &v1.ObjectReference{
			Name:      roleSecret.Name,
			Namespace: roleSecret.Namespace,
			UID:       roleSecret.UID,
		}

		config, err := kubeconfig.LoadFromSecret(roleSecret)
		if err != nil {
			klog.Error(err)
			return nil, err
		}
		config.ContentConfig.GroupVersion = gv
		config.APIPath = "/apis"
		config.NegotiatedSerializer = client_scheme.Codecs.WithoutConversion()
		config.UserAgent = rest.DefaultKubernetesUserAgent()

		return crdClient.NewFromConfig(config)
	}

	return nil, errors.New("no available role")
}

func (r *ForeignClusterReconciler) getAuthToken(fc *discoveryv1alpha1.ForeignCluster) string {
	tokenSecrets, err := r.crdClient.Client().CoreV1().Secrets(r.Namespace).List(context.TODO(), metav1.ListOptions{
		LabelSelector: strings.Join(
			[]string{
				strings.Join([]string{"cluster-id", fc.Spec.ClusterIdentity.ClusterID}, "="),
				"liqo-auth-token",
			},
			",",
		),
	})
	if err != nil {
		klog.Error(err)
		return ""
	}

	for _, tokenSecret := range tokenSecrets.Items {
		if tokenB64, found := tokenSecret.Data["token"]; found {
			tokenBytes, err := base64.StdEncoding.DecodeString(string(tokenB64))
			if err != nil {
				klog.Error(err)
				continue
			}
			return string(tokenBytes)
		}
	}
	return ""
}

func (r *ForeignClusterReconciler) askRemoteRole(fc *discoveryv1alpha1.ForeignCluster) (string, error) {
	token := r.getAuthToken(fc)

	roleRequest := auth.RoleRequest{
		ClusterID: r.DiscoveryCtrl.ClusterId.GetClusterID(),
		Token:     token,
	}
	jsonRequest, err := json.Marshal(roleRequest)
	if err != nil {
		klog.Error(err)
		return "", err
	}

	// TODO: only if untrusted
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Post(fmt.Sprintf("%s/role", fc.Spec.AuthUrl), "text/plain", bytes.NewBuffer(jsonRequest))
	if err != nil {
		klog.Error(err)
		return "", err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		klog.Error(err)
		return "", err
	}
	switch resp.StatusCode {
	case http.StatusCreated:
		fc.Status.AuthStatus = discoveryv1alpha1.AuthStatusAccepted
		klog.Info("Role Created")
		return string(body), nil
	case http.StatusForbidden:
		if token == "" {
			fc.Status.AuthStatus = discoveryv1alpha1.AuthStatusEmptyRefused
		} else {
			fc.Status.AuthStatus = discoveryv1alpha1.AuthStatusRefused
		}
		klog.Info(string(body))
		return "", nil
	default:
		klog.Info(body)
		return "", errors.New(string(body))
	}
}
