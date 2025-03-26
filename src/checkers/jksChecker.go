package checkers

import (
	"context"
	"fmt"
	"time"

	"github.com/arturkiwa/cert-exporter/src/exporters"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type JKSChecker struct {
	pollingPeriod  time.Duration
	labelSelector  string
	annotationKey  string
	namespaces      []string
	kubeconfigPath string
	exporter *exporters.JKSExporter
}

func NewJKSChecker(
	pollingPeriod time.Duration,
	labelSelector string,
	annotationKey string,
	namespaces []string,
	kubeconfigPath string,
	exporter *exporters.JKSExporter,
) *JKSChecker {
	return &JKSChecker{
		pollingPeriod:  pollingPeriod,
		labelSelector:  labelSelector,
		annotationKey:  annotationKey,
		namespaces:      namespaces,
		kubeconfigPath: kubeconfigPath,
		exporter:        exporter,
	}
}

func (c *JKSChecker) Run(ctx context.Context) {
	clientset, err := getClient(c.kubeconfigPath)
	if err != nil {
		fmt.Printf("failed to create k8s client: %v\n", err)
		return
	}

	ticker := time.NewTicker(c.pollingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.exporter.ResetMetrics()
			c.checkSecrets(ctx, clientset)
		}
	}
}

func (c *JKSChecker) checkSecrets(ctx context.Context, clientset *kubernetes.Clientset) {
	for _, ns := range c.namespaces {
		secrets, err := clientset.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{
			LabelSelector: c.labelSelector,
		})
		if err != nil {
			fmt.Printf("failed to list secrets in ns %s: %v\n", ns, err)
			continue
		}

		for _, secret := range secrets.Items {
			jks, ok := secret.Data["keystore.jks"]
			if !ok {
				continue
			}

			passwordSecretName := secret.Annotations[c.annotationKey]
			if passwordSecretName == "" {
				fmt.Printf("secret %s/%s missing annotation %s\n", ns, secret.Name, c.annotationKey)
				continue
			}

			passwordSecret, err := clientset.CoreV1().Secrets(ns).Get(ctx, passwordSecretName, metav1.GetOptions{})
			if err != nil {
				fmt.Printf("failed to get password secret %s/%s: %v\n", ns, passwordSecretName, err)
				continue
			}

			password := string(passwordSecret.Data["password"])
			err = c.exporter.ExportMetrics(jks, password, "keystore.jks", secret.Name, ns)
			if err != nil {
				fmt.Printf("failed to export metrics from secret %s/%s: %v\n", ns, secret.Name, err)
			}
		}
	}
}

func getClient(kubeconfigPath string) (*kubernetes.Clientset, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(config)
}

