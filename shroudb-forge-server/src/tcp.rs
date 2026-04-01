use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use shroudb_acl::{AclRequirement, AuthContext, TokenValidator};
use shroudb_forge_engine::engine::ForgeEngine;
use shroudb_forge_protocol::commands::{ForgeCommand, parse_command};
use shroudb_forge_protocol::dispatch::dispatch;
use shroudb_forge_protocol::response::ForgeResponse;
use shroudb_protocol_wire::Resp3Frame;
use shroudb_server_tcp::ServerProtocol;

pub struct ForgeProtocol;

impl ServerProtocol for ForgeProtocol {
    type Command = ForgeCommand;
    type Response = ForgeResponse;
    type Engine = ForgeEngine<shroudb_storage::EmbeddedStore>;

    fn engine_name(&self) -> &str {
        "forge"
    }

    fn parse_command(&self, args: &[&str]) -> Result<Self::Command, String> {
        parse_command(args)
    }

    fn auth_token(cmd: &Self::Command) -> Option<&str> {
        if let ForgeCommand::Auth { token } = cmd {
            Some(token)
        } else {
            None
        }
    }

    fn acl_requirement(cmd: &Self::Command) -> AclRequirement {
        cmd.acl_requirement()
    }

    fn dispatch<'a>(
        &'a self,
        engine: &'a Self::Engine,
        cmd: Self::Command,
        auth: Option<&'a AuthContext>,
    ) -> Pin<Box<dyn Future<Output = Self::Response> + Send + 'a>> {
        Box::pin(dispatch(engine, cmd, auth))
    }

    fn response_to_frame(&self, response: &Self::Response) -> Resp3Frame {
        match response {
            ForgeResponse::Ok(data) => {
                let json = serde_json::to_string(data).unwrap_or_default();
                Resp3Frame::BulkString(json.into_bytes())
            }
            ForgeResponse::Error(msg) => Resp3Frame::SimpleError(format!("ERR {msg}")),
        }
    }

    fn error_response(&self, msg: String) -> Self::Response {
        ForgeResponse::error(msg)
    }

    fn ok_response(&self) -> Self::Response {
        ForgeResponse::ok_simple()
    }
}

pub async fn run_tcp(
    listener: tokio::net::TcpListener,
    engine: Arc<ForgeEngine<shroudb_storage::EmbeddedStore>>,
    token_validator: Option<Arc<dyn TokenValidator>>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    shroudb_server_tcp::run_tcp(
        listener,
        engine,
        Arc::new(ForgeProtocol),
        token_validator,
        shutdown_rx,
    )
    .await;
}
