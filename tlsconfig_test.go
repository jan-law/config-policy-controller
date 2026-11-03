// Copyright (c) 2026 Red Hat, Inc.
// Copyright Contributors to the Open Cluster Management project

package main

import (
	"crypto/tls"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	openshifttls "github.com/openshift/controller-runtime-common/pkg/tls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	testclient "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	sdktls "open-cluster-management.io/sdk-go/pkg/tls"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// allowSelfSubjectAccessReviews makes a fake clientset report every SelfSubjectAccessReview as
// allowed. Without this, the fake client's default "create" reaction just stores and echoes back
// the submitted object, leaving Status.Allowed at its false zero value - indistinguishable from a
// real permission denial.
func allowSelfSubjectAccessReviews(client *testclient.Clientset) {
	client.PrependReactor("create", "selfsubjectaccessreviews",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			//nolint:forcetypeassert
			review := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview)
			review.Status.Allowed = true

			return true, review, nil
		},
	)
}

// newAPIServerClient returns a fake client serving the APIServer TLS profile.
func newAPIServerClient(t *testing.T, profileType configv1.TLSProfileType) client.Client {
	t.Helper()

	s := runtime.NewScheme()
	require.NoError(t, configv1.Install(s))

	return fakeclient.NewClientBuilder().
		WithScheme(s).
		WithObjects(&configv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: openshifttls.APIServerName},
			Spec: configv1.APIServerSpec{
				TLSSecurityProfile: &configv1.TLSSecurityProfile{Type: profileType},
			},
		}).
		Build()
}

func TestResolveTLSConfigFlagsTakePrecedence(t *testing.T) {
	wantVersion, err := sdktls.ParseTLSVersion("VersionTLS13")
	require.NoError(t, err)

	tlsOptsFunc, watchAPIServer, spec, err := resolveEffectiveTLSConfig(
		t.Context(), nil, "VersionTLS13", "", "X25519")

	require.NoError(t, err)
	assert.False(t, watchAPIServer, "group flag means no APIServer watcher")
	assert.Equal(t, configv1.TLSProfileSpec{}, spec)

	got := &tls.Config{} //nolint:gosec // test-only, never used to actually serve traffic
	tlsOptsFunc(got)

	assert.Equal(t, wantVersion, got.MinVersion)
	assert.Equal(t, []tls.CurveID{tls.X25519}, got.CurvePreferences)
}

func TestResolveTLSConfigInvalidFlagsReturnsError(t *testing.T) {
	tlsOptsFunc, watchAPIServer, spec, err := resolveEffectiveTLSConfig(
		t.Context(), nil, "", "", "not-a-group")

	require.Error(t, err)
	assert.Nil(t, tlsOptsFunc)
	assert.False(t, watchAPIServer)
	assert.Equal(t, configv1.TLSProfileSpec{}, spec)
}

func TestResolveTLSConfigNoFlagsNoClusterUsesDefaults(t *testing.T) {
	tlsOptsFunc, watchAPIServer, spec, err := resolveEffectiveTLSConfig(t.Context(), nil, "", "", "")

	require.NoError(t, err)
	assert.False(t, watchAPIServer)
	assert.Equal(t, configv1.TLSProfileSpec{}, spec)

	got := &tls.Config{} //nolint:gosec // test-only, never used to actually serve traffic
	tlsOptsFunc(got)

	assert.Equal(t, sdktls.GetDefaultTLSConfig().MinVersion, got.MinVersion)
}

// TestResolveTLSConfigReadsConfigMapAndAPIServerProfile covers both inputs at the helper level.
// resolveEffectiveTLSConfig cannot inject clients: it builds them from a *rest.Config and resolves
// its namespace from the in-cluster service account file, so the ConfigMap path is unreachable in
// a unit test. The APIServer half uses the same fetch and conversion path as production.
func TestResolveTLSConfigReadsConfigMapAndAPIServerProfile(t *testing.T) {
	kubeClient := testclient.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sdktls.ConfigMapName,
			Namespace: "addon-ns",
		},
		Data: map[string]string{
			sdktls.ConfigMapKeyMinVersion: "VersionTLS13",
		},
	})
	allowSelfSubjectAccessReviews(kubeClient)

	configMapCfg, err := startTLSConfigMapWatcher(t.Context(), kubeClient, "addon-ns")
	require.NoError(t, err)
	require.NotNil(t, configMapCfg)

	wantVersion, err := sdktls.ParseTLSVersion("VersionTLS13")
	require.NoError(t, err)
	assert.Equal(t, wantVersion, configMapCfg.MinVersion)

	spec, found, watchable := fetchAPIServerTLSProfileSpec(
		t.Context(), newAPIServerClient(t, configv1.TLSProfileModernType))

	require.True(t, found)
	assert.True(t, watchable)
	assert.Equal(t, configv1.TLSProfiles[configv1.TLSProfileModernType].Groups, spec.Groups)
}

func TestResolveTLSConfigDefaultsWhenConfigMapAbsent(t *testing.T) {
	kubeClient := testclient.NewSimpleClientset()
	allowSelfSubjectAccessReviews(kubeClient)

	configMapCfg, err := startTLSConfigMapWatcher(t.Context(), kubeClient, "addon-ns")

	require.NoError(t, err)
	require.NotNil(t, configMapCfg)
	assert.Equal(t, sdktls.GetDefaultTLSConfig().MinVersion, configMapCfg.MinVersion)
}

func TestResolveTLSConfigMissingConfigMapPermissionReturnsError(t *testing.T) {
	// No allowSelfSubjectAccessReviews call: the fake client's default reaction leaves
	// Status.Allowed at its false zero value, simulating denied RBAC.
	kubeClient := testclient.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sdktls.ConfigMapName,
			Namespace: "addon-ns",
		},
	})

	_, err := startTLSConfigMapWatcher(t.Context(), kubeClient, "addon-ns")
	assert.Error(t, err)
}
