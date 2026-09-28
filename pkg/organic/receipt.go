// SPDX-License-Identifier: AGPL-3.0-only

package organic

// ReceiptErrorAttribution is the frozen attribution of every receipt v4
// error_code ("none" for a deactivation race).
var ReceiptErrorAttribution = map[string]string{
	"artifact_fetch_failed":    "miner",
	"artifact_verify_failed":   "miner",
	"image_load_failed":        "miner",
	"image_identity_mismatch":  "miner",
	"container_create_failed":  "miner",
	"container_exited":         "application",
	"health_timeout":           "application",
	"health_unexpected_status": "application",
	"health_marker_missing":    "application",
	"resource_exhausted":       "miner",
	"deactivated":              "none",
	"internal":                 "miner",
}
