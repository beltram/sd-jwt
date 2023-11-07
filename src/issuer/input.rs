use crate::{
    core::disclosure::Disclosure, core::json_pointer::JsonPointer, crypto::CryptoBackend, error::SdjResult,
    issuer::decisions::Decisions,
};

pub struct InputClaimSet<'a> {
    /// Json input claims to selectively disclose
    pub input: serde_json::Value,
    /// Selects claims to mark selectively disclosable. By default, all claims are visible.
    pub decisions: Decisions<'a>,
}

impl<'a> InputClaimSet<'a> {
    pub fn try_new(input: &serde_json::Value, decisions: &'a [&'a str]) -> SdjResult<Self> {
        let input = Self {
            input: input.clone(),
            decisions: Decisions(decisions.iter().map(|&p| p.try_into()).collect::<SdjResult<_>>()?),
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
        self.decisions
            .as_ref()
            .iter()
            .map(|path| self.input.try_find_drop(backend, path))
            .collect::<SdjResult<Vec<_>>>()
    }
}

#[cfg(test)]
pub mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn should_create_a_disclosure() {
        let input = json!({
            "a": 1,
            "b": 2
        });
        let mut ics = InputClaimSet::try_new(&input, &["/a"]).unwrap();
        let disclosures = ics.try_select_disclosures(&mut CryptoBackend::new()).unwrap();
        assert_eq!(disclosures.len(), 1);
        let Disclosure::Object { name, value, .. } = disclosures.get(0).unwrap() else {
            unimplemented!()
        };
        assert_eq!(name, "a");
        assert_eq!(value, &json!(1));
    }
}
