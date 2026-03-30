use serde::{Deserialize, Serialize};

use crate::error::ForgeError;

/// Key lifecycle state machine: Staged -> Active -> Draining -> Retired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyState {
    Staged,
    Active,
    Draining,
    Retired,
}

impl KeyState {
    pub fn can_transition_to(self, target: KeyState) -> bool {
        matches!(
            (self, target),
            (KeyState::Staged, KeyState::Active)
                | (KeyState::Active, KeyState::Draining)
                | (KeyState::Draining, KeyState::Retired)
        )
    }

    pub fn transition_to(self, target: KeyState) -> Result<KeyState, ForgeError> {
        if self.can_transition_to(target) {
            Ok(target)
        } else {
            Err(ForgeError::InvalidStateTransition {
                from: self,
                to: target,
            })
        }
    }
}

impl std::fmt::Display for KeyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyState::Staged => write!(f, "Staged"),
            KeyState::Active => write!(f, "Active"),
            KeyState::Draining => write!(f, "Draining"),
            KeyState::Retired => write!(f, "Retired"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_transitions() {
        assert!(KeyState::Staged.can_transition_to(KeyState::Active));
        assert!(KeyState::Active.can_transition_to(KeyState::Draining));
        assert!(KeyState::Draining.can_transition_to(KeyState::Retired));
    }

    #[test]
    fn invalid_transitions() {
        assert!(!KeyState::Staged.can_transition_to(KeyState::Draining));
        assert!(!KeyState::Staged.can_transition_to(KeyState::Retired));
        assert!(!KeyState::Active.can_transition_to(KeyState::Retired));
        assert!(!KeyState::Active.can_transition_to(KeyState::Staged));
        assert!(!KeyState::Draining.can_transition_to(KeyState::Active));
        assert!(!KeyState::Retired.can_transition_to(KeyState::Draining));
        assert!(!KeyState::Active.can_transition_to(KeyState::Active));
    }

    #[test]
    fn transition_to_ok() {
        let state = KeyState::Staged.transition_to(KeyState::Active).unwrap();
        assert_eq!(state, KeyState::Active);
    }

    #[test]
    fn transition_to_err() {
        let err = KeyState::Staged
            .transition_to(KeyState::Retired)
            .unwrap_err();
        assert!(matches!(
            err,
            ForgeError::InvalidStateTransition {
                from: KeyState::Staged,
                to: KeyState::Retired,
            }
        ));
    }
}
