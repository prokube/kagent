// Copyright 2026 The kagent Authors
// SPDX-License-Identifier: Apache-2.0

package v1alpha3

// RuntimeEnvVar configures one literal runtime environment variable.
type RuntimeEnvVar struct {
	// +kubebuilder:validation:MinLength=1
	// +required
	Name string `json:"name"`

	// Value is a literal value, including an empty string.
	// +required
	Value string `json:"value"`

	// Deferred until secret-backed environment injection is supported.
	// CredentialRef *corev1.SecretKeySelector `json:"credentialRef,omitempty"`
}

// RuntimeSnapshotPolicy configures storage for Substrate snapshots.
type RuntimeSnapshotPolicy struct {
	// Location is the snapshot storage location used by Substrate.
	// +kubebuilder:validation:Pattern=`^[^[:space:]]+$`
	// +required
	Location string `json:"location"`
}

// RuntimeSubstratePolicy contains the Substrate policy shared by all runtime variants.
//
// +kubebuilder:validation:XValidation:rule="self.workerPoolRef.name.size() > 0",message="workerPoolRef name must not be empty"
type RuntimeSubstratePolicy struct {
	// WorkerPoolRef references a WorkerPool. An omitted namespace means the
	// resource's namespace. Another namespace must be listed in the
	// controller's substrate.workerPoolNamespaces setting.
	// +required
	WorkerPoolRef ObjectReference `json:"workerPoolRef"`

	// SnapshotPolicy configures runtime snapshot storage.
	// +required
	SnapshotPolicy RuntimeSnapshotPolicy `json:"snapshotPolicy"`
}
