use pkgcrypto::crypto as crypto;
use crypto::error::CryptoError;
use crypto::error::CryptoErrorCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuteErrorCode {

    // general
    Unknown,
    IllegalArgument,

    // specific
    ApplicationDataProtocolIsNotReady,
    BufferLengthIncorrect,
    BufferTooShort,
    ClosedSocket,
    CryptoError,
    DecryptionFailed,
    UnsuitableState,
    UnsupportedAlgorithm,
    UnsupportedCipherSuite,
    UnsupportedVersion,
    VerificationFailed,

}

impl MuteErrorCode {

    pub fn to_str(&self) -> &str {
        return match self {
            Self::Unknown                           => "unknown",
            Self::IllegalArgument                   => "illegal argument",
            Self::ApplicationDataProtocolIsNotReady => "application data protocol is not ready",
            Self::BufferLengthIncorrect             => "buffer length incorrect",
            Self::BufferTooShort                    => "buffer too short",
            Self::ClosedSocket                      => "closed socket",
            Self::CryptoError                       => "crypto error",
            Self::DecryptionFailed                  => "decryption failed",
            Self::UnsuitableState                   => "unsuitable state",
            Self::UnsupportedAlgorithm              => "unsupported algorithm",
            Self::UnsupportedCipherSuite            => "unsupported cipher suite",
            Self::UnsupportedVersion                => "unsupported version",
            Self::VerificationFailed                => "verification failed",
        };
    }

}

#[derive(Debug)]
pub struct MuteError {
    err_code: MuteErrorCode,
    crypto_err_code: Option<CryptoErrorCode>
}

impl MuteError {

    pub fn new(err_code: MuteErrorCode) -> Self {
        return Self{
            err_code: err_code,
            crypto_err_code: None
        };
    }

    pub fn err_code(&self) -> MuteErrorCode {
        return self.err_code;
    }

}

impl From<CryptoError> for MuteError {
    fn from(err: CryptoError) -> Self {
        return Self{
            err_code: MuteErrorCode::CryptoError,
            crypto_err_code: Some(err.err_code())
        };
    }
}

impl std::fmt::Display for MuteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return write!(f, "MuteError: {}", if self.err_code == MuteErrorCode::CryptoError {
            format!("crypto error [{}]", self.crypto_err_code.unwrap().to_str())
        } else {
            String::from(self.err_code.to_str())
        });
    }
}

impl std::error::Error for MuteError {}