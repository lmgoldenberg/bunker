/*
Copyright James Connolly 2024

This file is part of tpm-ws.

tpm-ws is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

tpm-ws is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with tpm-ws. If not, see <https://www.gnu.org/licenses/>.
*/

use tokio_tungstenite::WebSocketStream;
use tokio::io::{AsyncRead, AsyncWrite};
use crate::{Backend, SignMsg};

#[derive(Default, Debug)]
pub struct TpmBackend;

impl Backend for TpmBackend {
	fn is_supported() -> bool {
		false
	}

	async fn sign_msg<S>(&self, _ws: &mut WebSocketStream<S>, _sign_msg: SignMsg)
	where
		S: AsyncRead + AsyncWrite + Unpin
	{
		unimplemented!()
	}
}
