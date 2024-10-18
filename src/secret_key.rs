#[derive(Debug, Clone)]
pub struct SecretKey {
    content: Vec<u8>,
}

impl SecretKey {
    pub fn new(content: Vec<u8>) -> Self {
        Self { content }
    }

    pub fn inner(&self) -> &[u8] {
        &self.content
    }
}
