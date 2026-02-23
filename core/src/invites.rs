//! # Accord Invite System
//!
//! Private invite-only system with expiration controls and quality gates.
//! No public server discovery - all access through direct invites.

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Invite configuration with expiration and access controls
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Invite {
    pub invite_code: String,
    pub server_id: Uuid,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub max_uses: Option<u32>,
    pub current_uses: u32,
    pub invite_type: InviteType,
    pub access_level: AccessLevel,
    pub quality_gates: QualityGates,
    pub custom_message: Option<String>,
}

/// Types of invites with different behaviors
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InviteType {
    /// Standard server invite
    Server,
    /// Invite to specific channel
    Channel { channel_id: Uuid },
    /// Temporary invite (user removed when invite expires)
    Temporary,
    /// One-time invite (deleted after first use)
    OneTime,
}

/// Access level granted by invite
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AccessLevel {
    /// Basic member access
    Member,
    /// Moderator privileges
    Moderator,
    /// Admin privileges (can create invites)
    Admin,
    /// Custom role assignment
    CustomRole { role_ids: Vec<String> },
}

/// Quality control gates for invite acceptance
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct QualityGates {
    /// Require account age minimum
    pub min_account_age_days: Option<u32>,
    /// Require verification (email, phone, etc.)
    pub require_verification: bool,
    /// Require approval from invite creator
    pub require_approval: bool,
    /// Require existing members' referral
    pub require_referral: Option<u32>, // Minimum number of existing member endorsements
    /// Custom verification questions
    pub verification_questions: Vec<VerificationQuestion>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationQuestion {
    pub question: String,
    pub expected_type: AnswerType,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AnswerType {
    Text,
    MultipleChoice { options: Vec<String> },
    Boolean,
}

/// Invite usage record for tracking and auditing
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InviteUsage {
    pub usage_id: Uuid,
    pub invite_code: String,
    pub user_id: Uuid,
    pub used_at: DateTime<Utc>,
    pub user_info: UserInfo,
    pub approval_status: ApprovalStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserInfo {
    pub username: String,
    pub account_created: DateTime<Utc>,
    pub verification_status: VerificationStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VerificationStatus {
    Unverified,
    EmailVerified,
    PhoneVerified,
    FullyVerified,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected { reason: String },
    AutoApproved,
}

/// Invite validation result
#[derive(Debug, Clone)]
pub enum InviteValidation {
    Valid,
    Expired,
    MaxUsesReached,
    QualityGatesFailed { reasons: Vec<String> },
    RequiresApproval { pending_id: Uuid },
    NotFound,
    Revoked,
}

/// Pending join request awaiting approval
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PendingJoin {
    pub request_id: Uuid,
    pub invite_code: String,
    pub user_id: Uuid,
    pub user_info: UserInfo,
    pub requested_at: DateTime<Utc>,
    pub verification_answers: HashMap<String, String>,
}

/// Invite manager handling creation, validation, and usage tracking
pub struct InviteManager {
    invites: HashMap<String, Invite>,
    usage_history: Vec<InviteUsage>,
    pending_joins: HashMap<Uuid, PendingJoin>,
}

impl Default for InviteManager {
    fn default() -> Self {
        Self::new()
    }
}

impl InviteManager {
    pub fn new() -> Self {
        Self {
            invites: HashMap::new(),
            usage_history: Vec::new(),
            pending_joins: HashMap::new(),
        }
    }

    /// Create a new invite with specified configuration
    pub fn create_invite(
        &mut self,
        server_id: Uuid,
        creator_id: Uuid,
        invite_config: InviteConfig,
    ) -> Result<String> {
        let invite_code = self.generate_invite_code();

        let expires_at = invite_config
            .expiry_duration
            .map(|duration| Utc::now() + duration);

        let invite = Invite {
            invite_code: invite_code.clone(),
            server_id,
            created_by: creator_id,
            created_at: Utc::now(),
            expires_at,
            max_uses: invite_config.max_uses,
            current_uses: 0,
            invite_type: invite_config.invite_type,
            access_level: invite_config.access_level,
            quality_gates: invite_config.quality_gates,
            custom_message: invite_config.custom_message,
        };

        self.invites.insert(invite_code.clone(), invite);
        Ok(invite_code)
    }

    /// Validate an invite and check quality gates
    pub fn validate_invite(&self, invite_code: &str, user_info: &UserInfo) -> InviteValidation {
        let invite = match self.invites.get(invite_code) {
            Some(invite) => invite,
            None => return InviteValidation::NotFound,
        };

        // Check expiration
        if let Some(expires_at) = invite.expires_at {
            if Utc::now() > expires_at {
                return InviteValidation::Expired;
            }
        }

        // Check max uses
        if let Some(max_uses) = invite.max_uses {
            if invite.current_uses >= max_uses {
                return InviteValidation::MaxUsesReached;
            }
        }

        // Check quality gates
        let mut failed_reasons = Vec::new();

        // Account age check
        if let Some(min_age_days) = invite.quality_gates.min_account_age_days {
            let account_age = Utc::now().signed_duration_since(user_info.account_created);
            if account_age.num_days() < min_age_days as i64 {
                failed_reasons.push(format!(
                    "Account must be at least {} days old",
                    min_age_days
                ));
            }
        }

        // Verification requirement
        if invite.quality_gates.require_verification
            && user_info.verification_status == VerificationStatus::Unverified
        {
            failed_reasons.push("Account verification required".to_string());
        }

        if !failed_reasons.is_empty() {
            return InviteValidation::QualityGatesFailed {
                reasons: failed_reasons,
            };
        }

        // Check if approval is required
        if invite.quality_gates.require_approval {
            // Would create pending join request
            return InviteValidation::RequiresApproval {
                pending_id: Uuid::new_v4(),
            };
        }

        InviteValidation::Valid
    }

    /// Use an invite (increment usage counter)
    pub fn use_invite(
        &mut self,
        invite_code: &str,
        user_id: Uuid,
        user_info: UserInfo,
    ) -> Result<InviteUsage> {
        self.use_invite_internal(invite_code, user_id, user_info, false)
    }

    /// Internal method to use invite with optional approval bypass
    fn use_invite_internal(
        &mut self,
        invite_code: &str,
        user_id: Uuid,
        user_info: UserInfo,
        bypass_approval: bool,
    ) -> Result<InviteUsage> {
        // Validate before getting mutable reference, but allow bypassing approval requirement
        let validation = self.validate_invite(invite_code, &user_info);
        match validation {
            InviteValidation::Valid => {}
            InviteValidation::RequiresApproval { .. } if bypass_approval => {}
            _ => return Err(anyhow::anyhow!("Invite validation failed")),
        }

        let invite = self
            .invites
            .get_mut(invite_code)
            .ok_or_else(|| anyhow::anyhow!("Invite not found"))?;

        invite.current_uses += 1;

        let usage = InviteUsage {
            usage_id: Uuid::new_v4(),
            invite_code: invite_code.to_string(),
            user_id,
            used_at: Utc::now(),
            user_info,
            approval_status: if bypass_approval {
                ApprovalStatus::Approved
            } else {
                ApprovalStatus::AutoApproved
            },
        };

        self.usage_history.push(usage.clone());

        // Handle one-time invites
        if matches!(invite.invite_type, InviteType::OneTime) {
            self.revoke_invite(invite_code)?;
        }

        Ok(usage)
    }

    /// Create a pending join request for approval
    pub fn create_pending_join(
        &mut self,
        invite_code: &str,
        user_id: Uuid,
        user_info: UserInfo,
        verification_answers: HashMap<String, String>,
    ) -> Result<Uuid> {
        let invite = self
            .invites
            .get(invite_code)
            .ok_or_else(|| anyhow::anyhow!("Invite not found"))?;

        if !invite.quality_gates.require_approval {
            return Err(anyhow::anyhow!("This invite does not require approval"));
        }

        let request_id = Uuid::new_v4();
        let pending_join = PendingJoin {
            request_id,
            invite_code: invite_code.to_string(),
            user_id,
            user_info,
            requested_at: Utc::now(),
            verification_answers,
        };

        self.pending_joins.insert(request_id, pending_join);
        Ok(request_id)
    }

    /// Approve a pending join request
    pub fn approve_pending_join(
        &mut self,
        request_id: Uuid,
        approver_id: Uuid,
    ) -> Result<InviteUsage> {
        let pending_join = self
            .pending_joins
            .remove(&request_id)
            .ok_or_else(|| anyhow::anyhow!("Pending join request not found"))?;

        let invite = self
            .invites
            .get(&pending_join.invite_code)
            .ok_or_else(|| anyhow::anyhow!("Associated invite not found"))?;

        // Verify approver has permission (invite creator or admin)
        if invite.created_by != approver_id {
            // In a real implementation, would check if approver is admin
            return Err(anyhow::anyhow!("No permission to approve this request"));
        }

        // Use the invite with approval bypass
        let usage = self.use_invite_internal(
            &pending_join.invite_code,
            pending_join.user_id,
            pending_join.user_info,
            true, // bypass approval requirement
        )?;

        Ok(usage)
    }

    /// Reject a pending join request
    pub fn reject_pending_join(&mut self, request_id: Uuid, reason: String) -> Result<()> {
        let pending_join = self
            .pending_joins
            .remove(&request_id)
            .ok_or_else(|| anyhow::anyhow!("Pending join request not found"))?;

        // Record the rejection
        let usage = InviteUsage {
            usage_id: Uuid::new_v4(),
            invite_code: pending_join.invite_code,
            user_id: pending_join.user_id,
            used_at: Utc::now(),
            user_info: pending_join.user_info,
            approval_status: ApprovalStatus::Rejected { reason },
        };

        self.usage_history.push(usage);
        Ok(())
    }

    /// Revoke an invite (prevent further usage)
    pub fn revoke_invite(&mut self, invite_code: &str) -> Result<()> {
        self.invites
            .remove(invite_code)
            .ok_or_else(|| anyhow::anyhow!("Invite not found"))?;
        Ok(())
    }

    /// Get invite information (for display to potential users)
    pub fn get_invite_info(&self, invite_code: &str) -> Option<InviteInfo> {
        let invite = self.invites.get(invite_code)?;

        Some(InviteInfo {
            server_id: invite.server_id,
            expires_at: invite.expires_at,
            invite_type: invite.invite_type.clone(),
            custom_message: invite.custom_message.clone(),
            requires_approval: invite.quality_gates.require_approval,
            verification_questions: invite.quality_gates.verification_questions.clone(),
        })
    }

    /// Get pending join requests for a server (for admin approval)
    pub fn get_pending_joins(&self, server_id: Uuid) -> Vec<&PendingJoin> {
        self.pending_joins
            .values()
            .filter(|pending| {
                self.invites
                    .get(&pending.invite_code)
                    .is_some_and(|invite| invite.server_id == server_id)
            })
            .collect()
    }

    /// Get invite usage statistics
    pub fn get_invite_usage(&self, invite_code: &str) -> Vec<&InviteUsage> {
        self.usage_history
            .iter()
            .filter(|usage| usage.invite_code == invite_code)
            .collect()
    }

    /// Generate a unique invite code
    fn generate_invite_code(&self) -> String {
        use rand::{thread_rng, Rng};
        const CHARSET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";

        loop {
            let mut rng = thread_rng();
            let code: String = (0..8)
                .map(|_| {
                    let idx = rng.gen_range(0..CHARSET.len());
                    CHARSET[idx] as char
                })
                .collect();

            if !self.invites.contains_key(&code) {
                return code;
            }
        }
    }

    /// Clean up expired invites and old usage records
    pub fn cleanup_expired(&mut self) {
        let now = Utc::now();

        // Remove expired invites
        self.invites
            .retain(|_, invite| invite.expires_at.is_none_or(|expires| expires > now));

        // Remove old pending joins (older than 7 days)
        let week_ago = now - Duration::days(7);
        self.pending_joins
            .retain(|_, pending| pending.requested_at > week_ago);
    }
}

/// Configuration for creating new invites
#[derive(Debug, Clone)]
pub struct InviteConfig {
    pub expiry_duration: Option<Duration>,
    pub max_uses: Option<u32>,
    pub invite_type: InviteType,
    pub access_level: AccessLevel,
    pub quality_gates: QualityGates,
    pub custom_message: Option<String>,
}

/// Public information about an invite (safe to show before acceptance)
#[derive(Debug, Clone)]
pub struct InviteInfo {
    pub server_id: Uuid,
    pub expires_at: Option<DateTime<Utc>>,
    pub invite_type: InviteType,
    pub custom_message: Option<String>,
    pub requires_approval: bool,
    pub verification_questions: Vec<VerificationQuestion>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invite_creation() {
        let mut manager = InviteManager::new();

        let config = InviteConfig {
            expiry_duration: Some(Duration::days(7)),
            max_uses: Some(10),
            invite_type: InviteType::Server,
            access_level: AccessLevel::Member,
            quality_gates: QualityGates::default(),
            custom_message: Some("Welcome to our server!".to_string()),
        };

        let invite_code = manager
            .create_invite(Uuid::new_v4(), Uuid::new_v4(), config)
            .unwrap();

        assert_eq!(invite_code.len(), 8);
        assert!(manager.invites.contains_key(&invite_code));
    }

    #[test]
    fn test_invite_validation() {
        let mut manager = InviteManager::new();

        let quality_gates = QualityGates {
            min_account_age_days: Some(30),
            ..Default::default()
        };

        let config = InviteConfig {
            expiry_duration: Some(Duration::days(1)),
            max_uses: Some(1),
            invite_type: InviteType::Server,
            access_level: AccessLevel::Member,
            quality_gates,
            custom_message: None,
        };

        let invite_code = manager
            .create_invite(Uuid::new_v4(), Uuid::new_v4(), config)
            .unwrap();

        // Test with new account (should fail age requirement)
        let new_user = UserInfo {
            username: "newuser".to_string(),
            account_created: Utc::now(),
            verification_status: VerificationStatus::Unverified,
        };

        let validation = manager.validate_invite(&invite_code, &new_user);
        assert!(matches!(
            validation,
            InviteValidation::QualityGatesFailed { .. }
        ));

        // Test with old account (should pass)
        let old_user = UserInfo {
            username: "olduser".to_string(),
            account_created: Utc::now() - Duration::days(60),
            verification_status: VerificationStatus::EmailVerified,
        };

        let validation = manager.validate_invite(&invite_code, &old_user);
        assert!(matches!(validation, InviteValidation::Valid));
    }

    #[test]
    fn test_approval_workflow() {
        let mut manager = InviteManager::new();

        let quality_gates = QualityGates {
            require_approval: true,
            ..Default::default()
        };

        let config = InviteConfig {
            expiry_duration: None,
            max_uses: None,
            invite_type: InviteType::Server,
            access_level: AccessLevel::Member,
            quality_gates,
            custom_message: None,
        };

        let creator_id = Uuid::new_v4();
        let invite_code = manager
            .create_invite(Uuid::new_v4(), creator_id, config)
            .unwrap();

        let user_info = UserInfo {
            username: "testuser".to_string(),
            account_created: Utc::now() - Duration::days(10),
            verification_status: VerificationStatus::EmailVerified,
        };

        // Should require approval
        let validation = manager.validate_invite(&invite_code, &user_info);
        assert!(matches!(
            validation,
            InviteValidation::RequiresApproval { .. }
        ));

        // Create pending join
        let request_id = manager
            .create_pending_join(
                &invite_code,
                Uuid::new_v4(),
                user_info.clone(),
                HashMap::new(),
            )
            .unwrap();

        // Approve the request
        let usage = manager
            .approve_pending_join(request_id, creator_id)
            .unwrap();
        assert!(matches!(usage.approval_status, ApprovalStatus::Approved));
    }
}
