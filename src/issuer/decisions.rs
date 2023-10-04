use crate::error::{SdjError, SdjResult};

/// Json Pointer path for marking claims as selectively disclosable.
#[derive(Debug, Clone, derive_more::AsRef)]
pub struct Decisions<'a>(Vec<&'a str>);

impl<'a> TryFrom<&'a [&'a str]> for Decisions<'a> {
    type Error = SdjError;

    fn try_from(value: &'a [&'a str]) -> SdjResult<Self> {
        Ok(Self(value.to_vec()))
    }
}
