use crate::error::SdjResult;
use crate::prelude::SDJwt;

impl SDJwt {
    pub fn try_serialize(self) -> SdjResult<String> {
        let disclosures = self
            .disclosures
            .into_iter()
            .map(|d| d.build().map(|d| format!("{d}~")))
            .collect::<SdjResult<Vec<_>>>()?;
        let disclosures = disclosures.join("");
        let key_binding = self.key_binding.unwrap_or_default();
        Ok(format!("{}~{disclosures}{key_binding}", self.jws.as_ref()))
    }
}
