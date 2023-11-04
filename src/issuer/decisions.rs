use crate::core::json_pointer::path::JsonPointerPath;

/// Json Pointer path for marking claims as selectively disclosable.
#[derive(Debug, Clone, derive_more::AsRef)]
pub struct Decisions<'a>(pub(crate) Vec<JsonPointerPath<'a>>);
