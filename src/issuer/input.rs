use crate::{
    core::disclosure::Disclosure,
    crypto::CryptoBackend,
    error::SdjResult,
    issuer::{decisions::Decisions, json_pointer::JsonPointer},
};

pub struct InputClaimSet<'a> {
    /// Json input claims to selectively disclose
    pub input: serde_json::Value,
    /// Selects claims to mark selectively disclosable. By default, all claims are visible.
    pub decisions: Decisions<'a>,
}

impl<'a> InputClaimSet<'a> {
    pub fn try_new(input: serde_json::Value, decisions: &'a [&'static str]) -> SdjResult<Self> {
        let input = Self {
            input,
            decisions: decisions.try_into()?,
        };
        input.validate()?;
        Ok(input)
    }

    fn validate(&self) -> SdjResult<()> {
        Ok(())
    }

    /// Selects (using Json pointer) the claims to selectively disclose and:
    /// * remove them from the input
    /// * return them hashed
    pub fn try_select_disclosures(&mut self, backend: &mut CryptoBackend) -> SdjResult<Vec<Disclosure>> {
        let mut disclosures = vec![];
        for &path in self.decisions.as_ref() {
            if let Some((name, value)) = self.input.find_drop(path) {
                let disclosure = Disclosure::try_new(backend, Some(name), value)?;
                disclosures.push(disclosure);
            }
        }
        Ok(disclosures)
    }
}

#[cfg(test)]
pub mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn should_trim_disclosable_claims() {
        let input = json!({
            "a": 1,
            "b": 2
        });
        let mut ics = InputClaimSet::try_new(input, &["/a"]).unwrap();
        ics.try_select_disclosures(&mut CryptoBackend::new()).unwrap();
        assert_eq!(ics.input, json!({"b": 2}));
    }

    #[test]
    fn should_create_a_disclosure() {
        let input = json!({
            "a": 1,
            "b": 2
        });
        let mut ics = InputClaimSet::try_new(input, &["/a"]).unwrap();
        let disclosures = ics.try_select_disclosures(&mut CryptoBackend::new()).unwrap();
        assert_eq!(disclosures.len(), 1);
        let disclosure = disclosures.get(0).unwrap();
        assert_eq!(disclosure.name, Some("a".to_string()));
        assert_eq!(disclosure.value, json!(1));
    }
}
