/*
Copyright James Connolly 2024

This file is part of tpm-ws.

tpm-ws is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

tpm-ws is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with tpm-ws. If not, see <https://www.gnu.org/licenses/>.
*/

use futures::sink::SinkExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::spawn_blocking;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::Message;
use cryptoki::context::{Pkcs11, CInitializeArgs};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use cryptoki::slot::Slot;
use std::path::PathBuf;
use std::str::FromStr;
use crate::{Backend, Resp, SignMsg, SignResp, EcPoint};

// TODO: store these behind secret service/windows credential manager
const SO_PIN: &str = "1234";
const USER_PIN: &str = "0000";

#[derive(Default, Debug)]
pub struct Pkcs11Backend;

impl Backend for Pkcs11Backend {
	fn is_supported() -> bool {
		if let Some(path) = get_pkcs11_impl() {
			path.exists()
		} else {
			false
		}
	}

	async fn sign_msg<S>(&self, ws: &mut WebSocketStream<S>, sign_msg: SignMsg)
	where
		S: AsyncRead + AsyncWrite + Unpin
	{
		let sign_resp = spawn_blocking(|| sign(sign_msg)).await.unwrap();
		let msg = rmp_serde::to_vec(&Resp::Sign(sign_resp)).unwrap();
		ws.send(Message::Binary(msg)).await.unwrap();
	}
}

fn get_slot(pkcs11: &Pkcs11) -> Slot {
	let mut slots = pkcs11.get_slots_with_token().unwrap();
	log::debug!("slots: {slots:?}");

	for slot in &slots {
		let token_info = pkcs11.get_token_info(*slot).unwrap();

		if token_info.label() == "tpm-ws" {
			return *slot;
		}
	}

	let slot = slots.remove(0);
	pkcs11.init_token(slot, &AuthPin::from_str(SO_PIN).unwrap(), "tpm-ws").unwrap();

	let session = pkcs11.open_rw_session(slot).unwrap();
	session.login(UserType::So, Some(&AuthPin::from_str(SO_PIN).unwrap())).unwrap();
	session.init_pin(&AuthPin::from_str(USER_PIN).unwrap()).unwrap();

	slot
}

#[cfg(target_os = "linux")]
fn get_pkcs11_impl() -> Option<PathBuf> {
	Some(PathBuf::from("/run/current-system/sw/lib/libtpm2_pkcs11.so"))
}

#[cfg(target_os = "windows")]
fn get_pkcs11_impl() -> Option<PathBuf> {
	None
}

fn sign(sign_msg: SignMsg) -> SignResp {
	let pkcs11 = Pkcs11::new(get_pkcs11_impl().expect("checked earlier")).unwrap();
	pkcs11.initialize(CInitializeArgs::OsThreads).unwrap();

	let slot = get_slot(&pkcs11);

	let session = pkcs11.open_rw_session(slot).unwrap();
	session.login(UserType::User, Some(&AuthPin::from_str(USER_PIN).unwrap())).unwrap();

	let (pub_id, priv_id) = (
		format!("auth-{}-pub", &sign_msg.origin).into_bytes(),
		format!("auth-{}-priv", &sign_msg.origin).into_bytes()
	);

	let mut found = session.find_objects(&[Attribute::Id(priv_id.clone())]).unwrap();
	if found.len() > 1 {
		panic!("should have only found zero or one key with id {priv_id:?}");
	}

	let (pub_key, priv_key) = if let Some(priv_key) = found.pop() {
		log::debug!("found previously generated private key");
		let mut found = session.find_objects(&[Attribute::Id(pub_id)]).unwrap();
		if found.len() != 1 {
			panic!("failed to find corresponding public key");
		}

		(found.pop().unwrap(), priv_key)
	} else {
		// P-256 curve (hopefully not NSA backdoored?)
		let ec_params = Attribute::EcParams(vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);

		session.generate_key_pair(&Mechanism::EccKeyPairGen,
			&[Attribute::Token(true), Attribute::Extractable(true), Attribute::Id(pub_id), ec_params],
			&[Attribute::Token(true), Attribute::Extractable(false), Attribute::Id(priv_id)]).unwrap()
	};

	let signed = session.sign(&Mechanism::EcdsaSha256, priv_key, &sign_msg.data).unwrap();
	let sig_r = signed[0..32].to_vec();
	let sig_s = signed[32..64].to_vec();

	let ec_point = if sign_msg.include_key {
		if let Attribute::EcPoint(p) = session.get_attributes(pub_key, &[AttributeType::EcPoint]).unwrap().pop().unwrap() {
			assert_eq!(p.len(), 67);
			let x = p[3..35].to_vec();
			let y = p[35..67].to_vec();

			Some(EcPoint { x, y })
		} else {
			panic!("failed to extract public key info");
		}
	} else {
		None
	};

	SignResp {
		sig_r,
		sig_s,
		ec_point
	}
}
