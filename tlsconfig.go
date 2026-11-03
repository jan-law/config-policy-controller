// Copyright (c) 2026 Red Hat, Inc.
// Copyright Contributors to the Open Cluster Management project

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	openshifttls "github.com/openshift/controller-runtime-common/pkg/tls"
	libgocrypto "github.com/openshift/library-go/pkg/crypto"
	authorizationv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	sdktls "open-cluster-management.io/sdk-go/pkg/tls"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"open-cluster-management.io/config-policy-controller/pkg/common"
)

// resolveEffectiveTLSConfig determines the TLS configuration for the metrics and webhook servers.
// Each setting is resolved in order of precedence:
//  1. The --tls-min-version, --tls-cipher-suites, and --tls-groups flags.
//  2. When no flags are set, the ocm-tls-profile ConfigMap supplies the minimum version and cipher
//     suites. A background watcher restarts the process when the ConfigMap data changes.
//  3. The APIServer TLS profile supplies groups when --tls-groups is unset.
//     The returned watchAPIServer flag indicates whether to watch for profile changes,
//     and the returned profile spec seeds that watcher.
//  4. Go's TLS defaults apply to settings not supplied by the flags, ConfigMap, or profile.
func resolveEffectiveTLSConfig(
	ctx context.Context, cfg *rest.Config, minVersion, cipherSuites, groups string,
) (tlsOptsFunc func(*tls.Config), watchAPIServer bool, resolvedSpec configv1.TLSProfileSpec, err error) {
	flagCfg, err := sdktls.ConfigFromFlags(minVersion, cipherSuites)
	if err != nil {
		return nil, false, configv1.TLSProfileSpec{}, err
	}

	var configMapTLS *sdktls.TLSConfig

	if flagCfg == nil {
		configMapTLS, err = resolveOCMTLSConfigMap(ctx, cfg)
		if err != nil {
			log.Error(err, "Failed to resolve the ocm-tls-profile ConfigMap; using defaults")
		}
	}

	// Pick the min version and cipher suites source from highest to lowest priority.
	tlsSource := sdktls.GetDefaultTLSConfig()
	if flagCfg != nil {
		tlsSource = flagCfg
	} else if configMapTLS != nil {
		tlsSource = configMapTLS
	}

	opts := []func(*tls.Config){sdktls.ConfigToFunc(tlsSource)}

	groupCurves, unsupportedGroups := libgocrypto.TLSGroupsToCurveIDs(splitTLSGroups(groups))

	if len(unsupportedGroups) > 0 {
		return nil, false, configv1.TLSProfileSpec{}, fmt.Errorf(
			"invalid --tls-groups values: %v", unsupportedGroups)
	}

	spec, _, watchable := readAPIServerTLSProfileSpec(ctx, cfg)

	curves := groupCurves

	if len(curves) == 0 {
		curves, unsupportedGroups = libgocrypto.TLSGroupsToCurveIDs(spec.Groups)

		if len(unsupportedGroups) > 0 {
			log.Info("Some TLS groups are not supported and will be ignored", "groups", unsupportedGroups)
		}
	}

	if len(curves) > 0 {
		opts = append(opts, func(tlsConf *tls.Config) {
			tlsConf.CurvePreferences = curves
		})
	}

	tlsOptsFunc = func(tlsConf *tls.Config) {
		for _, opt := range opts {
			opt(tlsConf)
		}
	}

	appliedTLS := &tls.Config{}
	tlsOptsFunc(appliedTLS)

	log.Info("Resolved TLS configuration",
		"minVersion", sdktls.VersionToString(appliedTLS.MinVersion),
		"cipherSuites", sdktls.CipherSuitesToString(appliedTLS.CipherSuites),
		"tlsGroups", curvePreferencesToString(appliedTLS.CurvePreferences))

	// APIServer watcher handles profile groups. ConfigMap watcher handles min version and ciphers.
	watchAPIServer = watchable && len(groupCurves) == 0

	return tlsOptsFunc, watchAPIServer, spec, nil
}

func resolveOCMTLSConfigMap(ctx context.Context, cfg *rest.Config) (*sdktls.TLSConfig, error) {
	if cfg == nil {
		return nil, nil
	}

	namespace, err := common.GetOperatorNamespace()
	if err != nil {
		if errors.Is(err, common.ErrNoNamespace) || errors.Is(err, common.ErrRunLocal) {
			log.Info("Not running in a cluster; skipping the ocm-tls-profile ConfigMap watch")
		} else {
			log.Error(err, "Failed to get operator namespace; skipping the ocm-tls-profile ConfigMap watch")
		}

		return nil, nil
	}

	return startTLSConfigMapWatcher(ctx, kubernetes.NewForConfigOrDie(cfg), namespace)
}

// startTLSConfigMapWatcher checks permission to watch the ocm-tls-profile ConfigMap and starts the
// watcher, returning the TLS configuration active at startup. If RBAC denies list/watch, returns an error instead of
// starting the watcher so the caller falls back to defaults
func startTLSConfigMapWatcher(
	ctx context.Context, kubeClient kubernetes.Interface, namespace string,
) (*sdktls.TLSConfig, error) {
	allowed, err := canWatchTLSProfileConfigMap(ctx, kubeClient, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to check permission to watch the %s ConfigMap: %w",
			sdktls.ConfigMapName, err)
	}

	if !allowed {
		return nil, fmt.Errorf("missing permission to list/watch the %s ConfigMap in namespace %s",
			sdktls.ConfigMapName, namespace)
	}

	onConfigMapChange := func() {
		log.Info("TLS configuration changed; exiting so the pod restarts with the new settings")
		os.Exit(0)
	}

	return sdktls.StartTLSConfigMapWatcher(ctx, kubeClient, namespace, onConfigMapChange)
}

func canWatchTLSProfileConfigMap(ctx context.Context, kubeClient kubernetes.Interface, namespace string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	for _, verb := range []string{"list", "watch"} {
		review := &authorizationv1.SelfSubjectAccessReview{
			Spec: authorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: namespace,
					Verb:      verb,
					Resource:  "configmaps",
					Name:      sdktls.ConfigMapName,
				},
			},
		}

		result, err := kubeClient.AuthorizationV1().SelfSubjectAccessReviews().Create(
			ctx, review, metav1.CreateOptions{})
		if err != nil {
			return false, fmt.Errorf("failed to check %s permission on the %s ConfigMap: %w",
				verb, sdktls.ConfigMapName, err)
		}

		if !result.Status.Allowed {
			return false, nil
		}
	}

	return true, nil
}

// curvePreferencesToString returns the human-readable names of the TLS curves
func curvePreferencesToString(curves []tls.CurveID) []string {
	names := make([]string, 0, len(curves))

	for _, curve := range curves {
		names = append(names, curve.String())
	}

	return names
}

// splitTLSGroups splits the comma-separated --tls-groups value into group names.
func splitTLSGroups(groups string) []configv1.TLSGroup {
	var parsed []configv1.TLSGroup

	for group := range strings.SplitSeq(groups, ",") {
		group = strings.TrimSpace(group)
		if group != "" {
			parsed = append(parsed, configv1.TLSGroup(group))
		}
	}

	return parsed
}

// readAPIServerTLSProfileSpec builds a client for the given rest.Config and fetches the
// APIServer's resolved TLS profile spec. Errors here are just logged: failures should
// be handled by using defaults.
func readAPIServerTLSProfileSpec(
	ctx context.Context, cfg *rest.Config,
) (spec configv1.TLSProfileSpec, found, watchable bool) {
	if cfg == nil {
		return configv1.TLSProfileSpec{}, false, false
	}

	apiServerClient, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		log.Error(err, "Failed to create a client for the APIServer resource")

		return configv1.TLSProfileSpec{}, false, false
	}

	return fetchAPIServerTLSProfileSpec(ctx, apiServerClient)
}

// fetchAPIServerTLSProfileSpec returns the resolved profile spec when found. watchable is false
// only when the CRD/resource definitively doesn't exist; it stays true on other errors (e.g. RBAC,
// connectivity) since those might be transient and the drift watcher can recover once they clear.
func fetchAPIServerTLSProfileSpec(
	ctx context.Context, apiServerClient client.Client,
) (spec configv1.TLSProfileSpec, found, watchable bool) {
	spec, err := openshifttls.FetchAPIServerTLSProfile(ctx, apiServerClient)
	switch {
	case err == nil:
		return spec, true, true
	case meta.IsNoMatchError(err) || apierrors.IsNotFound(err):
		log.Info("The APIServer TLS Profile is not served by this cluster; using Go TLS defaults")

		return configv1.TLSProfileSpec{}, false, false
	default:
		log.Error(err, "Failed to read the APIServer TLS Profile; "+
			"will keep watching it in case this was transient")

		return configv1.TLSProfileSpec{}, false, true
	}
}

// setupAPIServerTLSWatcher registers a controller that restarts the process when the APIServer
// TLS security profile is present and changes
func setupAPIServerTLSWatcher(mgr ctrl.Manager, initialSpec configv1.TLSProfileSpec) error {
	watcher := &openshifttls.SecurityProfileWatcher{
		Client:                mgr.GetClient(),
		InitialTLSProfileSpec: initialSpec,
		OnProfileChange: func(_ context.Context, old, current configv1.TLSProfileSpec) {
			if slices.Equal(old.Groups, current.Groups) {
				return
			}

			log.Info("The APIServer TLS security profile changed; " +
				"exiting to apply the new settings")

			os.Exit(0)
		},
	}

	return watcher.SetupWithManager(mgr)
}
