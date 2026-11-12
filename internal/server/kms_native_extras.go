package server

import "github.com/worlddrknss/citadel/internal/store"

// Fields the console reads on GET /v1/kms/keys and /v1/kms/keys/detail.

type nativeKMSRotationSummary struct {
	Enabled            bool `json:"enabled"`
	RotationPeriodDays int  `json:"rotationPeriodDays,omitempty"`
}

type nativeKMSUsedBy struct {
	Secrets    int `json:"secrets"`
	Parameters int `json:"parameters"`
}

// nativeKMSKeyExtras is embedded in the list and detail projections.
type nativeKMSKeyExtras struct {
	Managed  bool                      `json:"managed"`
	Rotation *nativeKMSRotationSummary `json:"rotation,omitempty"`
	Origin   string                    `json:"origin"`
}

func kmsKeyExtras(k store.KMSKey) nativeKMSKeyExtras {
	ex := nativeKMSKeyExtras{Managed: k.Managed, Origin: keyOrigin(k)}
	if k.IsSymmetric() {
		ex.Rotation = &nativeKMSRotationSummary{Enabled: k.RotationEnabled}
		if k.RotationEnabled {
			ex.Rotation.RotationPeriodDays = k.RotationPeriodDays
		}
	}
	return ex
}
