use crate::error::ClientError;

/// TCP connection to a Forge server speaking RESP3.
pub struct Connection(shroudb_client_common::Connection);

impl Connection {
    /// Connect to a Forge server.
    pub async fn connect(addr: &str) -> Result<Self, ClientError> {
        Ok(Self(
            shroudb_client_common::Connection::connect(addr).await?,
        ))
    }

    /// Send a command and read the response.
    pub async fn send_command(&mut self, args: &[&str]) -> Result<serde_json::Value, ClientError> {
        Ok(self.0.send_command(args).await?)
    }
}
