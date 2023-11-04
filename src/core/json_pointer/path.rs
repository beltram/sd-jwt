use crate::error::SdjError;
use std::borrow::Cow;

#[derive(Debug, Clone, derive_more::AsRef, derive_more::Deref)]
pub(crate) struct JsonPointerPath<'a>(Cow<'a, str>);

impl<'a> JsonPointerPath<'a> {
    const DELIMITER: char = '/';

    pub fn object_key(&self) -> Option<&str> {
        let (_, last) = self.rsplit_once(Self::DELIMITER)?;

        use std::str::FromStr as _;
        // meaning it's an array index
        if usize::from_str(last).is_ok() {
            None
        } else {
            Some(last)
        }
    }

    pub fn is_key(&self) -> bool {
        self.object_key().is_some()
    }

    pub fn parent(&'a self) -> Option<Self> {
        if let Some((parent, _)) = self.rsplit_once(Self::DELIMITER) {
            Some(Self(Cow::Borrowed(parent)))
        } else {
            None
        }
    }

    pub fn append(&mut self, path: &str) {
        self.0 = Cow::Owned(format!("{}{}{path}", self.0, Self::DELIMITER))
    }

    // FIXME: both validations are wrong according to the RFC
    fn is_valid(&self) -> bool {
        !self.is_empty() && self.starts_with(Self::DELIMITER)
    }
}

impl<'a> TryFrom<&'a str> for JsonPointerPath<'a> {
    type Error = SdjError;

    fn try_from(path: &'a str) -> Result<Self, Self::Error> {
        let jpp = Self(Cow::Borrowed(path));
        if !jpp.is_valid() {
            return Err(SdjError::InvalidJsonPointerPath(path.to_string()));
        }
        Ok(jpp)
    }
}

#[cfg(test)]
pub mod tests {

    use super::*;

    mod object_key {
        use super::*;

        #[test]
        fn should_find_object_key() {
            assert_eq!(JsonPointerPath::try_from("/a/b/c").unwrap().object_key(), Some("c"));
            assert_eq!(JsonPointerPath::try_from("/a").unwrap().object_key(), Some("a"));
            assert_eq!(JsonPointerPath::try_from("/a/0/b").unwrap().object_key(), Some("b"));
        }

        #[test]
        fn should_not_find_object_key_for_array_items() {
            assert!(JsonPointerPath::try_from("/a/0").unwrap().object_key().is_none());
        }
    }

    mod validity {
        use super::*;

        #[test]
        fn should_be_invalid_when_empty() {
            assert!(matches!(
                JsonPointerPath::try_from("").unwrap_err(),
                SdjError::InvalidJsonPointerPath(p) if p.is_empty()
            ));
        }

        #[test]
        fn should_be_invalid_when_does_not_start_with_slash() {
            assert!(JsonPointerPath::try_from("/a").is_ok());
            assert!(matches!(
                JsonPointerPath::try_from("a").unwrap_err(),
                SdjError::InvalidJsonPointerPath(p) if p == "a"
            ));
            assert!(matches!(
                JsonPointerPath::try_from("!a").unwrap_err(),
                SdjError::InvalidJsonPointerPath(p) if p == "!a"
            ));
        }
    }
}
