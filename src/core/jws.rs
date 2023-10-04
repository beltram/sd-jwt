pub struct Jws(String);

impl From<String> for Jws {
    fn from(value: String) -> Self {
        Jws(value)
    }
}

impl From<Jws> for String {
    fn from(value: Jws) -> Self {
        value.0
    }
}

impl AsRef<str> for Jws {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
