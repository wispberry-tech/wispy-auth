package referrals

import (
	"github.com/wispberry-tech/wispy-auth/core"
)

// Storage extends the core.Storage interface with referral-specific methods
// This allows the referrals extension to work with any storage backend
// that implements both core functionality and referral operations
type Storage interface {
	core.Storage // Embed all core storage methods

	// Referral Code operations
	CreateReferralCode(code *ReferralCode) error
	GetReferralCodeByID(id uint) (*ReferralCode, error)
	GetReferralCodeByCode(code string) (*ReferralCode, error)
	GetReferralCodesByUser(userID uint) ([]*ReferralCode, error)
	UpdateReferralCode(code *ReferralCode) error
	DeactivateReferralCode(codeID uint) error
	IncrementReferralCodeUse(codeID uint) error

	// Referral Relationship operations
	CreateReferralRelationship(relationship *ReferralRelationship) error
	GetReferralRelationshipsByReferrer(referrerUserID uint) ([]*ReferralRelationship, error)
	GetReferralRelationshipsByReferred(referredUserID uint) ([]*ReferralRelationship, error)
	GetReferralRelationshipByUsers(referrerUserID, referredUserID uint) (*ReferralRelationship, error)

	// Referral Statistics
	GetReferralStats(userID uint) (*ReferralStats, error)
	GetTopReferrers(limit int) ([]*ReferralStats, error)

	// Validation and constraints
	ValidateReferralCode(code string) (*ReferralCode, error)
	CheckCodeAvailability(code string) (bool, error)
	CountActiveReferralCodes(userID uint) (int, error)
}