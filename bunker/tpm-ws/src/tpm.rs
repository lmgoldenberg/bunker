/*
Copyright James Connolly 2024

This file is part of tpm-ws.

tpm-ws is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

tpm-ws is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with tpm-ws. If not, see <https://www.gnu.org/licenses/>.
*/

use futures::sink::SinkExt;
use tokio::task::spawn_blocking;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::Message;
use tss_esapi::Context;
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::structures::{CreatePrimaryKeyResult, Digest, PublicBuilder, SymmetricCipherParameters, SymmetricDefinitionObject, PublicEccParametersBuilder, SignatureScheme, HashScheme, EccScheme, KeyDerivationFunctionScheme, EccPoint, Signature, Public, Private, Auth};
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::interface_types::{
	algorithm::{PublicAlgorithm, HashingAlgorithm},
	resource_handles::Hierarchy,
	ecc::EccCurve,
	session_handles::AuthSession
};
use tss_esapi::traits::{Marshall, UnMarshall};
use std::path::Path;
use diesel::{QueryDsl, RunQueryDsl, ExpressionMethods};
use zeroize::Zeroizing;
use crate::{db, Backend, Resp, SignMsg, SignResp, EcPoint};
use crate::secrets::get_password;

#[derive(Default, Debug)]
pub struct TpmBackend;

impl Backend for TpmBackend {
	// not perfect, but it'll do
	fn is_supported() -> bool {
		Path::new("/dev/tpm0").exists()
	}

	async fn sign_msg<S>(&self, ws: &mut WebSocketStream<S>, sign_msg: SignMsg)
	where
		S: AsyncRead + AsyncWrite + Unpin
	{
		let password = get_password(&sign_msg.origin).await;
		let sign_resp = spawn_blocking(|| sign(sign_msg, password)).await.unwrap();
		let msg = rmp_serde::to_vec(&Resp::Sign(sign_resp)).unwrap();
		ws.send(Message::Binary(msg)).await.unwrap();
	}
}

fn create_primary(tpm: &mut Context, password: &Zeroizing<Vec<u8>>) -> CreatePrimaryKeyResult {
	let attrs = ObjectAttributesBuilder::new()
		.with_fixed_tpm(true)
		.with_fixed_parent(true)
		.with_st_clear(false)
		.with_sensitive_data_origin(true)
		.with_user_with_auth(true)
		.with_decrypt(true)
		.with_restricted(true)
		.build().unwrap();

	let primary_pub = PublicBuilder::new()
		.with_public_algorithm(PublicAlgorithm::SymCipher)
		.with_name_hashing_algorithm(HashingAlgorithm::Sha256)
		.with_object_attributes(attrs)
		.with_symmetric_cipher_parameters(SymmetricCipherParameters::new(
			SymmetricDefinitionObject::AES_256_CFB
		))
		.with_symmetric_cipher_unique_identifier(Digest::default())
		.build().unwrap();

	tpm.execute_with_session(Some(AuthSession::Password), |ctx| {
		let auth_value = Auth::try_from(password.as_ref()).unwrap();
		ctx.create_primary(Hierarchy::Owner, primary_pub, Some(auth_value), None, None, None)
	}).unwrap()
}

fn get_keypair(tpm: &mut Context, primary: &CreatePrimaryKeyResult, password: &Zeroizing<Vec<u8>>, origin: String) -> (Private, Public) {
	use crate::schema::tpm_keys::dsl;
	use crate::models::NewTpmKeyPair;

	let mut conn = db::get_conn();

	let selected: Result<(Vec<u8>, Vec<u8>), _> = dsl::tpm_keys.filter(dsl::origin.eq(&origin)).select((dsl::sealed_private_key, dsl::public_key)).first(&mut conn);

	if let Ok((sealed_private_key, public_key)) = selected {
		let private = sealed_private_key.try_into().unwrap();
		let public = Public::unmarshall(&public_key).unwrap();
		(private, public)
	} else {
		let (private, public) = generate_keypair(tpm, primary, password);

		let pair = NewTpmKeyPair {
			origin,
			sealed_private_key: private.to_vec(),
			public_key: public.marshall().unwrap()
		};

		diesel::insert_into(dsl::tpm_keys).values(pair).execute(&mut conn).unwrap();

		(private, public)
	}
}

fn generate_keypair(tpm: &mut Context, primary: &CreatePrimaryKeyResult, password: &Zeroizing<Vec<u8>>) -> (Private, Public) {
	log::debug!("generating new keypair");

	let attrs = ObjectAttributesBuilder::new()
		.with_fixed_tpm(true)
		.with_fixed_parent(true)
		.with_st_clear(false)
		.with_sensitive_data_origin(true)
		.with_user_with_auth(true)
		.with_decrypt(false)
		.with_sign_encrypt(true)
		.build().unwrap();

	let ecc_params = PublicEccParametersBuilder::new()
		.with_curve(EccCurve::NistP256)
		.with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
		.with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
		.with_is_signing_key(true)
		.with_is_decryption_key(false)
		.with_restricted(true)
		.build().unwrap();

	let key_pub = PublicBuilder::new()
		.with_public_algorithm(PublicAlgorithm::Ecc)
		.with_name_hashing_algorithm(HashingAlgorithm::Sha256)
		.with_object_attributes(attrs)
		.with_ecc_parameters(ecc_params)
		.with_ecc_unique_identifier(EccPoint::default())
		.build().unwrap();

	tpm.execute_with_session(Some(AuthSession::Password), |ctx| {
		let auth_value = Auth::try_from(password.as_ref()).unwrap();
		ctx.create(primary.key_handle, key_pub, Some(auth_value), None, None, None).map(|k| (k.out_private, k.out_public))
	}).unwrap()
}

fn sign(sign_msg: SignMsg, password: Zeroizing<Vec<u8>>) -> SignResp {
	let mut tpm = Context::new(
		TctiNameConf::from_environment_variable().unwrap()
	).unwrap();

	let primary = create_primary(&mut tpm, &password);

	let (sealed_private, public) = get_keypair(&mut tpm, &primary, &password, sign_msg.origin);

	let (hash, ticket) = tpm.execute_with_nullauth_session(|ctx| {
		ctx.hash(sign_msg.data.try_into().unwrap(), HashingAlgorithm::Sha256, Hierarchy::Owner)
	}).unwrap();

	let signed = tpm.execute_with_session(Some(AuthSession::Password), |ctx| {
		let private = ctx.load(primary.key_handle, sealed_private, public.clone()).unwrap();
		let auth_value = Auth::try_from(password.as_ref()).unwrap();
		ctx.tr_set_auth(private.into(), auth_value).unwrap();
		ctx.sign(private, hash, SignatureScheme::EcDsa {
			hash_scheme: HashScheme::new(HashingAlgorithm::Sha256)
		}, ticket)
	}).unwrap();

	if let Signature::EcDsa(sig) = signed {
		let sig_r = sig.signature_r().value().to_vec();
		let sig_s = sig.signature_s().value().to_vec();

		let ec_point = if sign_msg.include_key {
			let (x, y) = if let Public::Ecc { unique, .. } = public {
				(unique.x().value().to_vec(), unique.y().value().to_vec())
			} else {
				unreachable!("should be ecc public key")
			};

			Some(EcPoint { x, y })
		} else {
			None
		};

		SignResp {
			sig_r,
			sig_s,
			ec_point
		}
	} else {
		unreachable!("should be ecdsa signature")
	}
}
