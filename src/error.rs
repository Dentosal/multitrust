#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    InvalidSignature,
    UntrustedMessage,
    InvalidMessage,
    Settings(String),
}
