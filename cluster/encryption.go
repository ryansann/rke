package cluster

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	ghodssyaml "github.com/ghodss/yaml"
	normantypes "github.com/rancher/norman/types"
	"github.com/rancher/rke/k8s"
	"github.com/rancher/rke/log"
	"github.com/rancher/rke/services"
	"github.com/rancher/rke/templates"
	v3 "github.com/rancher/rke/types"
	"github.com/rancher/rke/util"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	apiserverconfig "k8s.io/apiserver/pkg/apis/config"
	apiserverconfigv1 "k8s.io/apiserver/pkg/apis/config/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
	sigsyaml "sigs.k8s.io/yaml"
)

const (
	EncryptionProviderFilePath = "/etc/kubernetes/ssl/encryption.yaml"
)

type encryptionKey struct {
	Name   string
	Secret string
}
type keyList struct {
	KeyList []*encryptionKey
}

func ReconcileEncryptionProviderConfig(ctx context.Context, kubeCluster, currentCluster *Cluster) error {
	if len(kubeCluster.ControlPlaneHosts) == 0 {
		return nil
	}
	// New or existing cluster deployment with encryption enabled. We will rewrite the secrets after deploying the addons.
	if (currentCluster == nil || !currentCluster.IsEncryptionEnabled()) &&
		kubeCluster.IsEncryptionEnabled() {
		kubeCluster.EncryptionConfig.RewriteSecrets = true
		logrus.Debugf("Encryption is enabled in the new spec; have to rewrite secrets")
		return nil
	}
	// encryption is disabled
	if !kubeCluster.IsEncryptionEnabled() && !currentCluster.IsEncryptionEnabled() {
		logrus.Debugf("Encryption is disabled in both current and new spec; no action is required")
		return nil
	}

	// disable encryption
	if !kubeCluster.IsEncryptionEnabled() && currentCluster.IsEncryptionEnabled() {
		logrus.Debugf("Encryption is enabled in the current spec and disabled in the new spec")
		return kubeCluster.DisableSecretsEncryption(ctx, currentCluster, currentCluster.IsEncryptionCustomConfig())
	}

	// encryption configuration updated
	if kubeCluster.IsEncryptionEnabled() && currentCluster.IsEncryptionEnabled() &&
		kubeCluster.EncryptionConfig.EncryptionProviderFile != currentCluster.EncryptionConfig.EncryptionProviderFile {
		kubeCluster.EncryptionConfig.RewriteSecrets = true
		log.Infof(ctx, "[%s] Encryption provider config has changed;"+
			" reconciling cluster's encryption provider configuration", services.ControlRole)
		return services.RestartKubeAPIWithHealthcheck(ctx, kubeCluster.ControlPlaneHosts,
			kubeCluster.LocalConnDialerFactory, kubeCluster.Certificates)
	}

	return nil
}

func (c *Cluster) DisableSecretsEncryption(ctx context.Context, currentCluster *Cluster, custom bool) error {
	log.Infof(ctx, "[%s] Disabling Secrets Encryption..", services.ControlRole)

	if len(c.ControlPlaneHosts) == 0 {
		return nil
	}
	var err error
	if custom {
		c.EncryptionConfig.EncryptionProviderFile, err = currentCluster.generateDisabledCustomEncryptionProviderFile()
	} else {
		c.EncryptionConfig.EncryptionProviderFile, err = currentCluster.generateDisabledEncryptionProviderFile()
	}

	if err != nil {
		return err
	}
	logrus.Debugf("[%s] Deploying Identity first Encryption Provider Configuration", services.ControlRole)
	if err := c.DeployEncryptionProviderFile(ctx); err != nil {
		return err
	}
	if err := services.RestartKubeAPIWithHealthcheck(ctx, c.ControlPlaneHosts, c.LocalConnDialerFactory,
		c.Certificates); err != nil {
		return err
	}
	if err := c.RewriteSecrets(ctx); err != nil {
		return err
	}
	// KubeAPI will be restarted for the last time during controlplane redeployment, since the
	// Configuration file is now empty, the Process Plan will change.
	c.EncryptionConfig.EncryptionProviderFile = ""
	if err := c.DeployEncryptionProviderFile(ctx); err != nil {
		return err
	}
	log.Infof(ctx, "[%s] Secrets Encryption is disabled successfully", services.ControlRole)
	return nil
}

const (
	rewriteSecretsOperation = "rewrite-secrets"
	secretBatchSize         = 100
)

// RewriteSecrets does the following:
// - retrieves all cluster secrets in batches with size of <secretBatchSize>
// - triggers rewrites with new encryption key for each secrets over a channel to workers which perform the rewrite
// - logs progress of rewrite operation
// NOTE: For large sets of secrets, the continue token used to retrieve secrets in batches will likely expire.
// The expiration time is equivalent to the etcd compaction interval, which defaults to 5 minutes.
// This is fine for our purposes as we are only concerned with rewriting secrets that exist when this operation begins.
func (c *Cluster) RewriteSecrets(ctx context.Context) error {
	k8sClient, cliErr := k8s.NewClient(c.LocalKubeConfigPath, c.K8sWrapTransport)
	if cliErr != nil {
		return fmt.Errorf("failed to initialize new kubernetes client: %v", cliErr)
	}

	rewrites := make(chan interface{}, secretBatchSize)
	go func() {
		defer close(rewrites) // exiting this go routine triggers workers to exit

		retryErr := func(err error) bool { // all returned errors can be retried
			return true
		}

		var continueToken string
		var secrets []v1.Secret
		for {
			err := retry.OnError(retry.DefaultRetry, retryErr, func() error {
				l, err := k8sClient.CoreV1().Secrets("").List(context.TODO(), metav1.ListOptions{
					Limit:    secretBatchSize, // keep the per request secrets batch size small to avoid client timeouts
					Continue: continueToken,
				})
				if err != nil && !isExpiredTokenErr(err) {
					return err
				}

				secrets = append(secrets, l.Items...)
				continueToken = l.Continue

				return nil
			})
			if err != nil {
				cliErr = err // outer client error
				break
			}

			// send this batch to workers for rewrite
			for _, s := range secrets {
				if strings.HasPrefix(s.Name, "default-token") {
					logrus.Debugf("default-token secret: %+v", s)
				}
				rewrites <- s
			}
			secrets = nil // reset secrets since they've been sent to workers

			// if there's no continue token, we've retrieved all secrets
			if continueToken == "" {
				break
			}
		}

		logrus.Debugf("[%v] All secrets retrieved and sent for rewrite", rewriteSecretsOperation)
	}()

	// NOTE: since we retrieve secrets in batches, we don't know total number of secrets up front.
	// Telling the user how many we've rewritten is the best we can do
	done := make(chan struct{}, SyncWorkers)
	defer close(done)
	go func() {
		var rewritten int
		for range done {
			rewritten++
			if rewritten%50 == 0 { // log a message every 50 secrets
				log.Infof(ctx, "[%s] %v secrets rewritten", rewriteSecretsOperation, rewritten)
			}
		}
	}()

	// spawn workers to perform secret rewrites
	var errgrp errgroup.Group
	for w := 0; w < SyncWorkers; w++ {
		errgrp.Go(func() error {
			var errList []error
			for secret := range rewrites {
				s := secret.(v1.Secret)
				err := rewriteSecret(k8sClient, &s)
				if err != nil {
					errList = append(errList, err)
				}
				done <- struct{}{}
			}
			return util.ErrList(errList)
		})
	}
	if err := errgrp.Wait(); err != nil {
		logrus.Errorf("[%v] error: %v", rewriteSecretsOperation, err)
		return err // worker error from rewrites
	}

	if cliErr != nil {
		log.Infof(ctx, "[%s] Operation encountered error: %v", rewriteSecretsOperation, cliErr)
	} else {
		log.Infof(ctx, "[%s] Operation completed", rewriteSecretsOperation)
	}

	return cliErr // client error from retrieving secrets
}

func (c *Cluster) RotateEncryptionKey(ctx context.Context, fullState *FullState) error {
	// generate new key
	newKey, err := generateEncryptionKey()
	if err != nil {
		return err
	}

	oldKey, err := c.extractActiveKey(c.EncryptionConfig.EncryptionProviderFile)
	if err != nil {
		return err
	}

	logrus.Debug("adding new encryption key, provider config: [newKey, oldKey]")

	// Ensure encryption is done with newKey
	err = c.updateEncryptionProvider(ctx, []*encryptionKey{newKey, oldKey}, fullState)
	if err != nil {
		return err
	}

	// rewrite secrets via updates to secrets
	if err := c.RewriteSecrets(ctx); err != nil {
		// in the case of an error during rewrite, the cluster will need to be restored, so redeploy the initial encryption provider config
		_ = c.updateEncryptionProvider(ctx, []*encryptionKey{oldKey}, fullState)
		return err
	}

	// At this point, all secrets have been rewritten using the newKey, so we remove the old one.
	logrus.Debug("removing old encryption key, provider config: [newKey]")

	err = c.updateEncryptionProvider(ctx, []*encryptionKey{newKey}, fullState)
	if err != nil {
		return err
	}

	return nil
}

func (c *Cluster) updateEncryptionProvider(ctx context.Context, keys []*encryptionKey, fullState *FullState) error {
	providerConfig, err := providerFileFromKeyList(keyList{KeyList: keys})
	if err != nil {
		return err
	}

	c.EncryptionConfig.EncryptionProviderFile = providerConfig
	if err := c.DeployEncryptionProviderFile(ctx); err != nil {
		return err
	}

	// commit to state as soon as possible
	logrus.Debugf("[%s] Updating cluster state", services.ControlRole)
	if err := c.UpdateClusterCurrentState(ctx, fullState); err != nil {
		return err
	}
	if err := services.RestartKubeAPIWithHealthcheck(ctx, c.ControlPlaneHosts, c.LocalConnDialerFactory, c.Certificates); err != nil {
		return err
	}

	return nil
}

func (c *Cluster) DeployEncryptionProviderFile(ctx context.Context) error {
	logrus.Debugf("[%s] Deploying Encryption Provider Configuration file on Control Plane nodes..", services.ControlRole)
	logrus.Tracef("Deploying encryption provider file: %s", c.EncryptionConfig.EncryptionProviderFile)
	return deployFile(ctx, c.ControlPlaneHosts, c.SystemImages.Alpine, c.PrivateRegistriesMap, EncryptionProviderFilePath, c.EncryptionConfig.EncryptionProviderFile)
}

// ReconcileDesiredStateEncryptionConfig We do the rotation outside of the cluster reconcile logic. When we are done,
// DesiredState needs to be updated to reflect the "new" configuration
func (c *Cluster) ReconcileDesiredStateEncryptionConfig(ctx context.Context, fullState *FullState) error {
	fullState.DesiredState.EncryptionConfig = c.EncryptionConfig.EncryptionProviderFile
	return fullState.WriteStateFile(ctx, c.StateFilePath)
}

func (c *Cluster) IsEncryptionEnabled() bool {
	if c == nil {
		return false
	}
	if c.Services.KubeAPI.SecretsEncryptionConfig != nil &&
		c.Services.KubeAPI.SecretsEncryptionConfig.Enabled {
		return true
	}
	return false
}

func (c *Cluster) IsEncryptionCustomConfig() bool {
	if c.IsEncryptionEnabled() &&
		c.Services.KubeAPI.SecretsEncryptionConfig.CustomConfig != nil {
		return true
	}
	return false
}

func (c *Cluster) getEncryptionProviderFile() (string, error) {
	if c.EncryptionConfig.EncryptionProviderFile != "" {
		return c.EncryptionConfig.EncryptionProviderFile, nil
	}
	key, err := generateEncryptionKey()
	if err != nil {
		return "", err
	}
	c.EncryptionConfig.EncryptionProviderFile, err = providerFileFromKeyList(keyList{KeyList: []*encryptionKey{key}})
	return c.EncryptionConfig.EncryptionProviderFile, err
}

func (c *Cluster) extractActiveKey(s string) (*encryptionKey, error) {
	config := apiserverconfig.EncryptionConfiguration{}
	if err := k8s.DecodeYamlResource(&config, c.EncryptionConfig.EncryptionProviderFile); err != nil {
		return nil, err
	}
	resource := config.Resources[0]
	provider := resource.Providers[0]
	return &encryptionKey{
		Name:   provider.AESCBC.Keys[0].Name,
		Secret: provider.AESCBC.Keys[0].Secret,
	}, nil
}

func (c *Cluster) generateDisabledCustomEncryptionProviderFile() (string, error) {
	config := apiserverconfigv1.EncryptionConfiguration{}
	if err := k8s.DecodeYamlResource(&config, c.EncryptionConfig.EncryptionProviderFile); err != nil {
		return "", err
	}

	// 1. Prepend custom config providers with ignore provider
	updatedProviders := []apiserverconfigv1.ProviderConfiguration{{
		Identity: &apiserverconfigv1.IdentityConfiguration{},
	}}

	for _, provider := range config.Resources[0].Providers {
		if provider.Identity != nil {
			continue
		}
		updatedProviders = append(updatedProviders, provider)
	}

	config.Resources[0].Providers = updatedProviders

	// 2. Generate custom config file
	jsonConfig, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	yamlConfig, err := sigsyaml.JSONToYAML(jsonConfig)
	if err != nil {
		return "", nil
	}

	return string(yamlConfig), nil
}

func (c *Cluster) generateDisabledEncryptionProviderFile() (string, error) {
	key, err := c.extractActiveKey(c.EncryptionConfig.EncryptionProviderFile)
	if err != nil {
		return "", err
	}
	return disabledProviderFileFromKey(key)
}

const (
	errExpiredToken = "The provided continue parameter is too old"
)

// isExpiredTokenErr returns true if the error passed in is due to a continue token expiring
func isExpiredTokenErr(err error) bool {
	if strings.Contains(err.Error(), errExpiredToken) {
		return true
	}
	return false
}

func rewriteSecret(k8sClient *kubernetes.Clientset, secret *v1.Secret) error {
	var err error
	if err = k8s.UpdateSecret(k8sClient, secret); err == nil {
		return nil
	}
	if apierrors.IsConflict(err) {
		secret, err = k8s.GetSecret(k8sClient, secret.Name, secret.Namespace)
		if err != nil {
			//if apierrors.IsNotFound(err) {
			//	return nil
			//}
			return err
		}
		err = k8s.UpdateSecret(k8sClient, secret)
	}
	return err
}

func generateEncryptionKey() (*encryptionKey, error) {
	// TODO: do this in a better way
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return &encryptionKey{
		Name:   normantypes.GenerateName("key"),
		Secret: base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%X", buf))),
	}, nil
}

func isEncryptionEnabled(rkeConfig *v3.RancherKubernetesEngineConfig) bool {
	if rkeConfig.Services.KubeAPI.SecretsEncryptionConfig != nil &&
		rkeConfig.Services.KubeAPI.SecretsEncryptionConfig.Enabled {
		return true
	}
	return false
}

func isEncryptionCustomConfig(rkeConfig *v3.RancherKubernetesEngineConfig) bool {
	if isEncryptionEnabled(rkeConfig) &&
		rkeConfig.Services.KubeAPI.SecretsEncryptionConfig.CustomConfig != nil {
		return true
	}
	return false
}

func providerFileFromKeyList(keyList interface{}) (string, error) {
	return templates.CompileTemplateFromMap(templates.MultiKeyEncryptionProviderFile, keyList)
}

func disabledProviderFileFromKey(keyList interface{}) (string, error) {
	return templates.CompileTemplateFromMap(templates.DisabledEncryptionProviderFile, keyList)
}

func (c *Cluster) readEncryptionCustomConfig() (string, error) {
	// directly marshalling apiserverconfig.EncryptionConfiguration to yaml breaks things because TypeMeta
	// is nested and all fields don't have tags. apiserverconfigv1 has json tags only. So we do this as a work around.

	out := apiserverconfigv1.EncryptionConfiguration{}
	err := apiserverconfigv1.Convert_config_EncryptionConfiguration_To_v1_EncryptionConfiguration(
		c.RancherKubernetesEngineConfig.Services.KubeAPI.SecretsEncryptionConfig.CustomConfig, &out, nil)
	if err != nil {
		return "", err
	}
	jsonConfig, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	yamlConfig, err := sigsyaml.JSONToYAML(jsonConfig)
	if err != nil {
		return "", nil
	}

	return templates.CompileTemplateFromMap(templates.CustomEncryptionProviderFile,
		struct{ CustomConfig string }{CustomConfig: string(yamlConfig)})
}

func resolveCustomEncryptionConfig(clusterFile string) (string, *apiserverconfig.EncryptionConfiguration, error) {
	var err error
	var r map[string]interface{}
	err = ghodssyaml.Unmarshal([]byte(clusterFile), &r)
	if err != nil {
		return clusterFile, nil, fmt.Errorf("error unmarshalling: %v", err)
	}
	services, ok := r["services"].(map[string]interface{})
	if services == nil || !ok {
		return clusterFile, nil, nil
	}
	kubeapi, ok := services["kube-api"].(map[string]interface{})
	if kubeapi == nil || !ok {
		return clusterFile, nil, nil
	}
	sec, ok := kubeapi["secrets_encryption_config"].(map[string]interface{})
	if sec == nil || !ok {
		return clusterFile, nil, nil
	}
	customConfig, ok := sec["custom_config"].(map[string]interface{})

	if ok && customConfig != nil {
		delete(sec, "custom_config")
		newClusterFile, err := ghodssyaml.Marshal(r)
		c, err := parseCustomConfig(customConfig)
		return string(newClusterFile), c, err
	}
	return clusterFile, nil, nil
}

func parseCustomConfig(customConfig map[string]interface{}) (*apiserverconfig.EncryptionConfiguration, error) {
	var err error

	data, err := json.Marshal(customConfig)
	if err != nil {
		return nil, fmt.Errorf("error marshalling: %v", err)
	}
	scheme := runtime.NewScheme()
	err = apiserverconfig.AddToScheme(scheme)
	if err != nil {
		return nil, fmt.Errorf("error adding to scheme: %v", err)
	}
	err = apiserverconfigv1.AddToScheme(scheme)
	if err != nil {
		return nil, fmt.Errorf("error adding to scheme: %v", err)
	}
	codecs := serializer.NewCodecFactory(scheme)
	decoder := codecs.UniversalDecoder()
	decodedObj, objType, err := decoder.Decode(data, nil, nil)

	if err != nil {
		return nil, fmt.Errorf("error decoding data: %v", err)
	}

	decodedConfig, ok := decodedObj.(*apiserverconfig.EncryptionConfiguration)
	if !ok {
		return nil, fmt.Errorf("unexpected type: %T", objType)
	}
	return decodedConfig, nil
}
