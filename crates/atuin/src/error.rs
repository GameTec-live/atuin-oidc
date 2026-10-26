use std::error::Error;
use std::fmt;

#[cfg(feature = "sync")]
use atuin_client::record::sync::SyncError;

#[cfg(feature = "sync")]
use crate::i18n::fl;

/// A command that failed, as `main` returns it.
///
/// `main` prints a returned error as `Error: {err:?}`, so [`Debug`](fmt::Debug) is what the user
/// reads.
#[derive(thiserror::Error)]
pub enum CliError {
    /// The local key can't decrypt the records on the server.
    #[cfg(feature = "sync")]
    #[error("{}", SyncError::WrongKey)]
    WrongKey,

    /// `atuin login` was given a key that can't decrypt the records on the server, and logged out
    /// again.
    #[cfg(feature = "sync")]
    #[error("{}", fl!("login-wrong-key-body"))]
    LoginWrongKey,

    /// Anything else, printed as eyre reports it: with its causes and where it was raised.
    #[error(transparent)]
    Other(Box<dyn Error + Send + Sync>),
}

impl fmt::Debug for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // The message says how to fix it, and where it was raised would only bury that.
            #[cfg(feature = "sync")]
            Self::WrongKey | Self::LoginWrongKey => fmt::Display::fmt(self, f),
            Self::Other(err) => fmt::Debug::fmt(err, f),
        }
    }
}

impl From<eyre::Report> for CliError {
    fn from(report: eyre::Report) -> Self {
        #[cfg(feature = "sync")]
        for err in report.chain() {
            if matches!(err.downcast_ref(), Some(SyncError::WrongKey)) {
                return Self::WrongKey;
            }
            if matches!(err.downcast_ref(), Some(Self::LoginWrongKey)) {
                return Self::LoginWrongKey;
            }
        }
        Self::Other(report.into())
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[cfg(feature = "sync")]
    #[rstest]
    #[case::sync(eyre::Report::new(SyncError::WrongKey), SyncError::WrongKey.to_string())]
    #[case::wrapped(
        eyre::Report::new(SyncError::WrongKey).wrap_err("sync failed"),
        SyncError::WrongKey.to_string()
    )]
    #[case::login(CliError::LoginWrongKey.into(), fl!("login-wrong-key-body"))]
    fn wrong_key_prints_only_its_message(#[case] report: eyre::Report, #[case] expected: String) {
        assert_eq!(format!("{:?}", CliError::from(report)), expected);
    }

    #[rstest]
    fn other_errors_print_as_eyre_reports_them() {
        let report = eyre::eyre!("connection refused").wrap_err("sync failed");
        let expected = format!("{report:?}");
        assert_eq!(format!("{:?}", CliError::from(report)), expected);
    }
}
