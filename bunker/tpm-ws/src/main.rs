/*
Copyright James Connolly 2024

This file is part of tpm-ws.

tpm-ws is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

tpm-ws is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with tpm-ws. If not, see <https://www.gnu.org/licenses/>.
*/

use tokio::net::TcpListener;
use tokio::io::{AsyncRead, AsyncWrite};
use futures::stream::StreamExt;
use futures::sink::SinkExt;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::Message;
use serde::{Serialize, Deserialize};
use std::fmt::Debug;

mod secrets;

mod db;
mod schema;
mod models;

#[cfg(feature = "tpm")]
mod tpm;
#[cfg(feature = "tpm")]
use tpm::TpmBackend;

#[cfg(not(feature = "tpm"))]
mod no_tpm;
#[cfg(not(feature = "tpm"))]
use no_tpm::TpmBackend;

mod pkcs11;
use pkcs11::Pkcs11Backend;

mod software;
use software::SoftwareBackend;

trait Backend: Default + Debug {
	fn is_supported() -> bool;

	fn sign_msg<S>(&self, ws: &mut WebSocketStream<S>, sign_msg: SignMsg) -> impl std::future::Future<Output = ()>
	where
		S: AsyncRead + AsyncWrite + Unpin;
}

#[derive(Debug)]
enum SelectedBackend {
	Tpm(TpmBackend),
	Pkcs11(Pkcs11Backend),
	Software(SoftwareBackend)
}

#[tokio::main]
async fn main() {
	pretty_env_logger::init();
	log::info!("Copyright James Connolly 2024");
	db::run_migrations();

	let selected_backend = {
		if TpmBackend::is_supported() {
			SelectedBackend::Tpm(TpmBackend)
		} else if Pkcs11Backend::is_supported() {
			SelectedBackend::Pkcs11(Pkcs11Backend)
		} else if SoftwareBackend::is_supported() {
			SelectedBackend::Software(SoftwareBackend)
		} else {
			panic!("no backends supported")
		}
	};

	log::debug!("selected {selected_backend:?}");

	let listener = TcpListener::bind("127.0.0.1:8000").await.unwrap();

	while let Ok((stream, _)) = listener.accept().await {
		let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
		log::debug!("accepted connection");

		while let Some(Ok(msg)) = ws.next().await {
			if let Message::Binary(bytes) = msg {
				let msg: Msg = rmp_serde::from_slice(&bytes).unwrap();

				match msg {
					Msg::Sign(sign_msg) => {
						if sign_msg.origin.chars().any(|c| !c.is_ascii_alphanumeric() && c != '.') {
							log::error!("invalid origin");
							let msg = rmp_serde::to_vec(&Resp::Error(String::from("sign origin must be ascii alphanumeric"))).unwrap();
							ws.send(Message::Binary(msg)).await.unwrap();
							continue;
						}

						match &selected_backend {
							SelectedBackend::Pkcs11(pkcs11) => pkcs11.sign_msg(&mut ws, sign_msg).await,
							SelectedBackend::Tpm(tpm) => tpm.sign_msg(&mut ws, sign_msg).await,
							SelectedBackend::Software(software) => software.sign_msg(&mut ws, sign_msg).await
						}
					}
				}
			}
		}
	}
}

#[derive(Deserialize)]
enum Msg {
	Sign(SignMsg)
}

#[derive(Deserialize)]
struct SignMsg {
	origin: String,
	data: Vec<u8>,
	include_key: bool
}

#[derive(Serialize)]
enum Resp {
	Sign(SignResp),
	Error(String)
}

#[derive(Serialize)]
struct SignResp {
	sig_r: Vec<u8>,
	sig_s: Vec<u8>,
	ec_point: Option<EcPoint>
}

#[derive(Serialize)]
struct EcPoint {
	x: Vec<u8>,
	y: Vec<u8>
}
