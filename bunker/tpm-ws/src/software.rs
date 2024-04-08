/*
Copyright James Connolly 2024

This file is part of tpm-ws.

tpm-ws is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

tpm-ws is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with tpm-ws. If not, see <https://www.gnu.org/licenses/>.
*/

use tokio::task::spawn_blocking;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio::io::{AsyncRead, AsyncWrite};
use futures::sink::SinkExt;
use p256::ecdsa::{SigningKey, Signature, signature::Signer};
use rand_core::OsRng;
use diesel::{QueryDsl, RunQueryDsl, ExpressionMethods};
use zeroize::Zeroizing;
use aes_gcm::{Aes256Gcm, KeyInit, AeadInPlace, AeadCore};
use sha3::{Sha3_512, Digest};
use crate::{db, Backend, SignMsg, SignResp, Resp, EcPoint};
use crate::secrets::get_aes_key;

#[derive(Default, Debug)]
pub struct SoftwareBackend;

impl Backend for SoftwareBackend {
	fn is_supported() -> bool {
		true
	}

	async fn sign_msg<S>(&self, ws: &mut WebSocketStream<S>, sign_msg: SignMsg)
	where
		S: AsyncRead + AsyncWrite + Unpin
	{
		let aes_key = get_aes_key(&sign_msg.origin).await;
		let sign_resp = spawn_blocking(|| sign(sign_msg, aes_key)).await.unwrap();
		let msg = rmp_serde::to_vec(&Resp::Sign(sign_resp)).unwrap();
		ws.send(Message::Binary(msg)).await.unwrap();
	}
}

fn get_signing_key(origin: String, aes_key: &Zeroizing<Vec<u8>>) -> SigningKey {
	use crate::schema::software_keys::dsl;
	use crate::models::NewSoftwareKey;

	let mut conn = db::get_conn();

	let selected: Result<(Vec<u8>, Vec<u8>, Vec<u8>), _> = dsl::software_keys.filter(dsl::origin.eq(&origin))
		.select((dsl::encrypted_private_key, dsl::private_key_sha3_512_sum, dsl::encrypted_private_key_iv)).first(&mut conn);

	if let Ok((mut private_key, sha3_512_sum, iv)) = selected {
		let aes = Aes256Gcm::new_from_slice(aes_key).unwrap();
		aes.decrypt_in_place(iv.as_slice().into(), &sha3_512_sum, &mut private_key).unwrap();
		let hash = Sha3_512::digest(&private_key).to_vec();
		if hash != sha3_512_sum { panic!("sha3_512 sum doesn't match") }
		SigningKey::from_bytes(private_key.as_slice().into()).unwrap()
	} else {
		let aes = Aes256Gcm::new(<Zeroizing<Vec<u8>> as AsRef<Vec<u8>>>::as_ref(aes_key).as_slice().into());
		let private_key = SigningKey::random(&mut OsRng);
		let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
		let mut encrypted_private_key = private_key.to_bytes().as_slice().to_vec();
		let hash = Sha3_512::digest(&encrypted_private_key);
		aes.encrypt_in_place(&nonce, &hash, &mut encrypted_private_key).unwrap();

		let new_key = NewSoftwareKey {
			origin,
			encrypted_private_key,
			encrypted_private_key_iv: nonce.to_vec(),
			private_key_sha3_512_sum: hash.to_vec()
		};

		diesel::insert_into(dsl::software_keys).values(new_key).execute(&mut conn).unwrap();

		private_key
	}
}

fn sign(sign_msg: SignMsg, aes_key: Zeroizing<Vec<u8>>) -> SignResp {
	let private_key = get_signing_key(sign_msg.origin, &aes_key);
	let signature: Signature = private_key.sign(&sign_msg.data);
	let (r, s) = signature.split_bytes();

	let ec_point = if sign_msg.include_key {
		let public_key = private_key.verifying_key();

		// this is a bit inefficient, but this library really does not want me to access the raw coordinates...
		let encoded = public_key.to_sec1_bytes();
		assert_eq!(encoded.len(), 65);
		let (x, y) = (encoded[1..33].to_vec(), encoded[33..65].to_vec());

		Some(EcPoint{ x, y })
	} else {
		None
	};

	SignResp {
		sig_r: r.to_vec(),
		sig_s: s.to_vec(),
		ec_point
	}
}
