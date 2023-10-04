#[allow(dead_code)]
pub type SdjResult<T> = Result<T, SdjError>;

#[derive(thiserror::Error, Debug)]
pub enum SdjError {}
