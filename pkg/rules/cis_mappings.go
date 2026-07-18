// ANCHOR: CIS Kubernetes v1.8 control rule definitions - Dec 26, 2025
// ANCHOR: Backward compatibility re-export - Feature: rule separation - Jul 18, 2026
// This file re-exports CIS controls from the compliance package for backward compatibility.
// New code should import directly from pkg/rules/compliance for dual-mode rule support.

package rules

import "github.com/udyansh/elf-owl/pkg/rules/compliance"

// CISControls is a backward-compatible re-export of CIS Kubernetes v1.8 controls.
// Deprecated: Import from pkg/rules/compliance directly.
var CISControls = compliance.CISControls
