package middlewares

import "crypto/ecdsa"

const (
	WorkloadTokenHeader     = "Workload-Identity-Token"
	PoPTokenHeader          = "PoP-Token"
	WorkloadTokenContextKey = "wlToken"
)

type Authority interface {
	GetJWTPublicKey() *ecdsa.PublicKey
}
