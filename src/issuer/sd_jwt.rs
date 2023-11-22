use crate::{error::SdjResult, prelude::SDJwt};

impl SDJwt {
    pub fn try_serialize(self) -> SdjResult<String> {
        let disclosures = self
            .disclosures
            .into_iter()
            .map(|d| d.encode())
            .collect::<SdjResult<Vec<_>>>()?;
        let disclosures = disclosures.join(Self::DELIMITER);
        let key_binding = self.key_binding.unwrap_or_default();
        let jws = self.jws.as_ref();
        let delimiter = Self::DELIMITER;
        Ok(format!("{jws}{delimiter}{disclosures}{delimiter}{key_binding}",))
    }
}
