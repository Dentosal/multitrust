#![deny(unused_must_use)]

mod error;

use core::fmt;
use std::collections::HashMap;

use chrono::prelude::*;
use petgraph::graphmap::DiGraphMap;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sodiumoxide::{
    crypto::sign::{
        sign_detached, verify_detached, PublicKey, SecretKey, Signature, SIGNATUREBYTES,
    },
    hex,
};

pub use error::Error;

/// Unique identifier for an external identity in URI format, for example...
/// - user account: "https://github.con/Dentosal"
/// - personal profile: "https://linkedin.com/in/hannes-karppila"
/// - personal website: "https://dento.fi"
/// - email address: "mailto:john.smith@example.org"
/// - phone number: "tel:+3581234567890"
/// - government-assigned ID: "govid:fi:1234567-8"
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Identity(String);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(pub PublicKey);

impl fmt::Debug for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Target {
    /// A user of this systen, identified by public key.
    /// Relation to an user means trust in their judgement.
    User(UserId),
    /// Assertion of identity on some external service.
    Identity(Identity),
    /// Resource to measure trust of, identified by URI.
    /// TODO: prefix or regex matching for these as well?
    /// TODO: if not, then hash these for privacy?
    Resource(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Relation {
    /// A user of this systen, identified by public key.
    pub from: UserId,
    /// The target of the relation.
    pub to: Target,
}

/// A signable statement of trust.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Statement {
    pub relation: Relation,
    pub weight: Weight,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
pub struct Weight(f32);

impl Weight {
    pub fn new(value: f32) -> Self {
        assert!(
            (0.0..=1.0).contains(&value),
            "Weight must be between 0.0 and 1.0, got {value}"
        );
        Self(value)
    }

    pub fn value(self) -> f32 {
        self.0
    }

    pub fn min(self, other: Self) -> Self {
        Self(self.0.min(other.0))
    }

    pub fn max(self, other: Self) -> Self {
        Self(self.0.max(other.0))
    }

    /// Chained friends-of-friends
    pub fn chain(self, other: Self) -> Self {
        Self(self.0 * other.0)
    }
}

impl Eq for Weight {}

impl PartialOrd for Weight {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Weight {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.partial_cmp(&other.0).unwrap()
    }
}

/// A statement signed by a user.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signed<T, const VERIFIED: bool> {
    body: T,
    author: UserId,
    #[serde_as(as = "[_; 64]")]
    signature: [u8; SIGNATUREBYTES],
}

impl<T> Signed<T, true>
where
    T: serde::Serialize,
{
    pub fn new(body: T, secret_key: &SecretKey) -> Self {
        let signature = sign_detached(&serde_json::to_vec(&body).unwrap(), secret_key);
        Self {
            body,
            author: UserId(secret_key.public_key()),
            signature: signature.to_bytes(),
        }
    }

    pub fn author(&self) -> UserId {
        self.author
    }

    pub fn body(&self) -> &T {
        &self.body
    }
}

impl<T> Signed<T, false>
where
    T: serde::Serialize,
{
    #[must_use = "You should verify the signature before using the statement"]
    pub fn verify(self) -> Result<Signed<T, true>, Error> {
        let ok = verify_detached(
            &Signature::from_bytes(&self.signature).map_err(|_| Error::InvalidSignature)?,
            &serde_json::to_vec(&self.body).unwrap(),
            &self.author.0,
        );

        if ok {
            Ok(Signed {
                body: self.body,
                author: self.author,
                signature: self.signature,
            })
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

pub struct App {
    /// Your keypair for signing statements.
    secret_key: SecretKey,
    /// The statements of the database. The rest of the data is derived from these in event-sourced fashion.
    statements: Vec<Signed<Statement, true>>,
    /// Cached fields
    cache: Cached,
    /// Settings
    settings: Settings,
}

#[derive(Debug)]
struct Cached {
    /// Trust graph between users
    user_trust_graph: DiGraphMap<UserId, Weight>,
    /// Trust score of each user
    user_trust: HashMap<UserId, Weight>,
    /// For each identity, the highest trust score
    identity_max: HashMap<Identity, (UserId, Weight)>,
}

impl Cached {
    fn new(you: UserId) -> Self {
        let mut s = Self {
            user_trust_graph: DiGraphMap::new(),
            user_trust: HashMap::new(),
            identity_max: HashMap::new(),
        };
        s.user_trust.insert(you, Weight::new(1.0));
        s
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// Multiplier on how much you trust your own judgement, compared to others.
    pub self_confidence: f32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            self_confidence: 5.0,
        }
    }
}

impl Settings {
    pub fn validate(&self) -> Result<(), Error> {
        if self.self_confidence < 1.0 || !self.self_confidence.is_finite() {
            return Err(Error::Settings(
                "self_confidence must be at least 1.0".to_owned(),
            ));
        }
        Ok(())
    }
}

#[test]
fn default_settings_are_valid() {
    assert!(Settings::default().validate().is_ok());
}

impl App {
    pub fn new(secret_key: SecretKey) -> Self {
        let you = secret_key.public_key();
        let cache = Cached::new(UserId(you));
        Self {
            secret_key,
            statements: Vec::new(),
            cache,
            settings: Settings::default(),
        }
    }

    pub fn user(&self) -> UserId {
        UserId(self.secret_key.public_key())
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    pub fn set_settings(&mut self, settings: Settings) -> Result<(), Error> {
        settings.validate()?;
        self.settings = settings;
        Ok(())
    }

    pub fn statements(&self) -> &[Signed<Statement, true>] {
        &self.statements
    }

    pub fn import(&mut self, statement: Signed<Statement, false>) -> Result<(), Error> {
        let statement = statement.verify()?;
        self.import_signed(statement)?;
        Ok(())
    }

    pub fn import_signed(&mut self, statement: Signed<Statement, true>) -> Result<(), Error> {
        if statement.author() != self.user() && statement.author() != statement.body().relation.from
        {
            return Err(Error::UntrustedMessage);
        }

        self.statements.push(statement.clone());
        // Update cache
        let body = statement.body();
        let trust = self
            .cache
            .user_trust
            .get(&body.relation.from)
            .copied()
            .unwrap_or_default()
            .chain(body.weight);
        match body.relation.to {
            Target::User(to) => {
                self.cache
                    .user_trust_graph
                    .add_edge(body.relation.from, to, body.weight);

                let old = self.cache.user_trust.get(&to).copied().unwrap_or_default();
                if trust > old {
                    self.cache.user_trust.insert(to, trust);
                }
            }
            Target::Identity(ref id) => {
                let replace = self
                    .cache
                    .identity_max
                    .get(id)
                    .map(|(_, old)| *old < trust)
                    .unwrap_or(true);
                if replace {
                    self.cache
                        .identity_max
                        .insert(id.clone(), (body.relation.from, body.weight));
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Compute trust score for a resource using trust-weighted average from all users who have rated it.
    pub fn evaluate_resource_score(&self, resource: &str) -> Weight {
        let mut score = 0.0;
        let mut count = 0.0;
        for statement in &self.statements {
            let body = statement.body();
            let Target::Resource(ref res) = body.relation.to else {
                continue;
            };
            if res != resource {
                continue;
            }

            // Your direct judgement always overrides others
            if body.relation.from == self.user() {
                score += self.settings.self_confidence * body.weight.value();
                count += self.settings.self_confidence;
                continue;
            }

            let weight = self.cache.user_trust[&body.relation.from];
            score += weight.chain(body.weight).value();
            count += 1.0;
        }

        if count < 0.0001 {
            return Weight::new(0.0);
        }

        Weight::new(score / count)
    }

    pub fn user_identities(&self, user: UserId, treshold: Weight) -> Vec<(Identity, Weight)> {
        let mut identities = HashMap::<Identity, Weight>::new();
        for statement in &self.statements {
            let body = statement.body();
            if body.relation.from != user {
                continue;
            }
            let Target::Identity(id) = body.relation.to.clone() else {
                continue;
            };

            if let Some(id_max) = self.cache.identity_max.get(&id) {
                if id_max.0 != user {
                    continue;
                }
            }

            let trust = self
                .cache
                .user_trust
                .get(&body.relation.from)
                .copied()
                .unwrap_or_default()
                .chain(body.weight);
            if trust < treshold {
                continue;
            }
            let score = identities.entry(id).or_default();
            *score = (*score).max(trust);
        }

        let mut identities: Vec<_> = identities.into_iter().collect();
        identities.sort();
        identities.reverse();
        identities
    }
}

#[cfg(test)]
mod tests {
    use sodiumoxide::crypto::sign::gen_keypair;

    use super::*;

    #[test]
    fn test_evaluate_scores() {
        let (_you, you_sk) = gen_keypair();
        let mut app = App::new(you_sk.clone());

        let (user1, user1_sk) = gen_keypair();
        let (user2, user2_sk) = gen_keypair();
        let user1 = UserId(user1);
        let user2 = UserId(user2);

        let resource1 = Target::Resource("resource1".to_owned());
        let resource2 = Target::Resource("resource2".to_owned());
        let resource3 = Target::Resource("resource3".to_owned());

        // Direct trust
        app.import_signed(Signed::new(
            Statement {
                relation: Relation {
                    from: app.user(),
                    to: resource1.clone(),
                },
                weight: Weight::new(0.9),
                timestamp: Utc::now(),
            },
            &you_sk,
        ))
        .unwrap();
        assert_eq!(app.evaluate_resource_score("resource1").value(), 0.9);

        // Trust from through user1
        app.import_signed(Signed::new(
            Statement {
                relation: Relation {
                    from: app.user(),
                    to: Target::User(user1),
                },
                weight: Weight::new(0.7),
                timestamp: Utc::now(),
            },
            &you_sk,
        ))
        .unwrap();
        assert_eq!(app.cache.user_trust[&user1], Weight::new(0.7));
        app.import_signed(Signed::new(
            Statement {
                relation: Relation {
                    from: user1,
                    to: resource2.clone(),
                },
                weight: Weight::new(0.5),
                timestamp: Utc::now(),
            },
            &user1_sk,
        ))
        .unwrap();
        assert_eq!(app.evaluate_resource_score("resource2").value(), 0.7 * 0.5);

        // Trust from through two-user chain
        app.import_signed(Signed::new(
            Statement {
                relation: Relation {
                    from: user1,
                    to: Target::User(user2),
                },
                weight: Weight::new(0.9),
                timestamp: Utc::now(),
            },
            &user1_sk,
        ))
        .unwrap();
        assert_eq!(app.cache.user_trust[&user2], Weight::new(0.7 * 0.9));

        app.import_signed(Signed::new(
            Statement {
                relation: Relation {
                    from: user2,
                    to: resource3.clone(),
                },
                weight: Weight::new(0.4),
                timestamp: Utc::now(),
            },
            &user2_sk,
        ))
        .unwrap();

        assert_eq!(
            app.evaluate_resource_score("resource3").value(),
            0.7 * 0.9 * 0.4
        );

        // Now we shorten the chain so that user1 trusts the resource3 directly
        app.import_signed(Signed::new(
            Statement {
                relation: Relation {
                    from: user1,
                    to: resource3.clone(),
                },
                weight: Weight::new(0.8),
                timestamp: Utc::now(),
            },
            &user1_sk,
        ))
        .unwrap();
        assert_eq!(
            app.evaluate_resource_score("resource3").value(),
            (0.7 * 0.8 + 0.7 * 0.9 * 0.4) * 0.5
        );
    }

    #[test]
    fn test_user_identities() {
        let (_you, you_sk) = gen_keypair();
        let mut app = App::new(you_sk.clone());

        let (user1, user1_sk) = gen_keypair();
        let (user2, user2_sk) = gen_keypair();
        let user1 = UserId(user1);
        let user2 = UserId(user2);

        let identity1 = Identity("identity1".to_owned());
        let identity2 = Identity("identity2".to_owned());

        // Direct trust
        app.import_signed(Signed::new(
            Statement {
                relation: Relation {
                    from: app.user(),
                    to: Target::Identity(identity1.clone()),
                },
                weight: Weight::new(1.0),
                timestamp: Utc::now(),
            },
            &you_sk,
        ))
        .unwrap();
        app.import_signed(Signed::new(
            Statement {
                relation: Relation {
                    from: app.user(),
                    to: Target::Identity(identity1.clone()),
                },
                weight: Weight::new(0.5),
                timestamp: Utc::now(),
            },
            &you_sk,
        ))
        .unwrap();
        assert_eq!(
            app.user_identities(app.user(), Weight::new(0.001)),
            vec![(identity1.clone(), Weight::new(1.0))]
        );

        // Two users competing for the same identity, but we trust user1 more
        app.import_signed(Signed::new(
            Statement {
                relation: Relation {
                    from: app.user(),
                    to: Target::User(user1),
                },
                weight: Weight::new(0.7),
                timestamp: Utc::now(),
            },
            &you_sk,
        ))
        .unwrap();
        app.import_signed(Signed::new(
            Statement {
                relation: Relation {
                    from: app.user(),
                    to: Target::User(user2),
                },
                weight: Weight::new(0.4),
                timestamp: Utc::now(),
            },
            &you_sk,
        ))
        .unwrap();
        app.import_signed(Signed::new(
            Statement {
                relation: Relation {
                    from: user1,
                    to: Target::Identity(identity2.clone()),
                },
                weight: Weight::new(1.0),
                timestamp: Utc::now(),
            },
            &user1_sk,
        ))
        .unwrap();
        app.import_signed(Signed::new(
            Statement {
                relation: Relation {
                    from: user2,
                    to: Target::Identity(identity2.clone()),
                },
                weight: Weight::new(1.0),
                timestamp: Utc::now(),
            },
            &user2_sk,
        ))
        .unwrap();
        assert_eq!(
            app.user_identities(user1, Weight::new(0.001)),
            vec![(identity2.clone(), Weight::new(0.7))]
        );
        assert_eq!(app.user_identities(user2, Weight::new(0.001)), vec![]);
    }
}
