/*
Copyright James Connolly 2024

This file is part of tpm-ws.

tpm-ws is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

tpm-ws is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with tpm-ws. If not, see <https://www.gnu.org/licenses/>.
*/

use rand_core::OsRng;
use zeroize::Zeroizing;
use aes_gcm::{Aes256Gcm, KeyInit};
use tokio::task::spawn_blocking;

#[cfg(feature = "tpm")]
async fn generate_random_password() -> Zeroizing<[u8; 32]> {
	use rand_core::RngCore;

	spawn_blocking(|| {
		let mut password = Zeroizing::new([0u8; 32]);
		OsRng.fill_bytes(password.as_mut());
		password
	}).await.unwrap()
}

fn generate_aes_key_blocking() -> Zeroizing<[u8; 32]> {
	let aes_key = Aes256Gcm::generate_key(OsRng);
	Zeroizing::new(aes_key.into())
}

#[cfg(target_os = "linux")]
async fn generate_aes_key() -> Zeroizing<[u8; 32]> {
	spawn_blocking(generate_aes_key_blocking).await.unwrap()
}

#[cfg(all(feature = "tpm", target_os = "linux"))]
pub async fn get_password(origin: &str) -> Zeroizing<Vec<u8>> {
	use std::collections::HashMap;

	let keyring = oo7::Keyring::new().await.unwrap();
	keyring.unlock().await.unwrap();
	let attributes = HashMap::from([
		("tpm-ws_version", "0.1.0"),
		("origin", origin),
		("type", "tpm_password")
	]);

	let mut items = keyring.search_items(&attributes).await.unwrap();
	match items.len() {
		0 => {
			let new_pass = generate_random_password().await;
			keyring.create_item("origin_password", &attributes, &new_pass, true).await.unwrap();
			// yes this is hacky, but that's why they call it a hackathon!
			let mut v = Zeroizing::new(Vec::<u8>::with_capacity(32));
			v.extend(new_pass.as_ref());
			v
		},
		1 => items.remove(0).secret().await.unwrap(),
		_ => panic!("should only have one password per origin")
	}
}

#[cfg(target_os = "linux")]
pub async fn get_aes_key(origin: &str) -> Zeroizing<Vec<u8>> {
	use std::collections::HashMap;

	let keyring = oo7::Keyring::new().await.unwrap();
	keyring.unlock().await.unwrap();
	let attributes = HashMap::from([
		("tpm-ws_version", "0.1.0"),
		("origin", origin),
		("type", "aes_key")
	]);

	let mut items = keyring.search_items(&attributes).await.unwrap();
	match items.len() {
		0 => {
			let new_aes_key = generate_aes_key().await;
			assert_eq!(new_aes_key.len(), 32);
			keyring.create_item("origin_password", &attributes, &new_aes_key, true).await.unwrap();
			// yeah yeah, silence
			let mut v = Zeroizing::new(Vec::<u8>::with_capacity(32));
			v.extend(new_aes_key.as_ref());
			v
		},
		1 => items.remove(0).secret().await.unwrap(),
		_ => panic!("should only have one password per origin")
	}
}

#[cfg(target_os = "windows")]
pub async fn get_aes_key(origin: &str) -> Zeroizing<Vec<u8>> {
	use std::ffi::CString;
	use core::ffi::c_void;
	use windows::core::{PCSTR, PSTR};
	use windows::Win32::Security::Credentials::{CredReadA, CredWriteA, CREDENTIALA, CRED_FLAGS, CRED_TYPE, CRED_PERSIST, CREDENTIAL_ATTRIBUTEA, CredFree};
	use windows::Win32::System::SystemInformation::GetSystemTime;
	use windows::Win32::System::Time::SystemTimeToFileTime;
	use windows::Win32::Foundation::{SYSTEMTIME, FILETIME};

	let cred_name = CString::new(format!("tpm-ws/{origin}")).unwrap();

	spawn_blocking(move || {
		let layout = std::alloc::Layout::new::<CREDENTIALA>();

		// SAFETY: we must free this later
		let mut cred_ptr = unsafe {
			std::mem::transmute(std::alloc::alloc(layout))
		};
		let double_ptr: *mut *mut CREDENTIALA = &mut cred_ptr;

		// SAFETY: if this is `Err(_)` then `cred_ptr` is probably a biohazard
		let result = unsafe {
			CredReadA(PCSTR::from_raw(cred_name.as_ptr() as *const u8), CRED_TYPE(1), 0, double_ptr)
		};

		if result.is_ok() {
			let key: [u8; 32] = unsafe {
				assert_eq!((*cred_ptr).CredentialBlobSize, 32);
				std::ptr::read_unaligned((*cred_ptr).CredentialBlob as *const [u8; 32])
			};
			let key = key.to_vec();

			std::mem::forget(result);
			// SAFETY: `result` is no longer valid
			unsafe {
				CredFree(cred_ptr as *const c_void);
			}

			Zeroizing::new(key)
		} else {
			std::mem::forget(result);
			// SAFETY: `result` is no longer valid
			unsafe {
				CredFree(cred_ptr as *const c_void);
			}

			let key = generate_aes_key_blocking();

			let file_time_layout = std::alloc::Layout::new::<FILETIME>();
			// SAFETY: we gotta free this
			let file_time = unsafe {
				let system_time = GetSystemTime();
				let file_time: *mut FILETIME = std::mem::transmute(std::alloc::alloc(file_time_layout));
				SystemTimeToFileTime(&system_time as *const SYSTEMTIME, file_time).unwrap();
				file_time
			};

			let blob_layout = std::alloc::Layout::new::<[u8; 32]>();
			// SAFETY: we must free this later, also that these types match
			let blob = unsafe {
				let blob: *mut [u8; 32] = std::mem::transmute(std::alloc::alloc_zeroed(blob_layout));
				(*blob).clone_from(&key);
				blob
			};

			let comment = CString::new("decryption keys for tpm-ws software backend").unwrap();
			let username = CString::new("joe").unwrap();

			let cred = CREDENTIALA {
				Flags: CRED_FLAGS(2),
				Type: CRED_TYPE(1),
				TargetName: PSTR::from_raw(cred_name.as_ptr() as *mut u8),
				Comment: PSTR::from_raw(comment.as_ptr() as *mut u8),
				LastWritten: unsafe { *file_time }, // SAFETY: we unwrapped on `SystemTimeToFileTime` earlier
				CredentialBlobSize: 32,
				CredentialBlob: blob as *mut u8,
				Persist: CRED_PERSIST(2),
				AttributeCount: 0,
				Attributes: std::ptr::null::<CREDENTIAL_ATTRIBUTEA>() as *mut CREDENTIAL_ATTRIBUTEA, // I think windows ignores this for `CRED_TYPE_GENERIC`
				TargetAlias: PSTR::null(),
				UserName: PSTR::from_raw(username.as_ptr() as *mut u8)
			};

			// SAFETY: pray to the windows gods
			unsafe {
				CredWriteA(&cred as *const CREDENTIALA, 0).unwrap();
			}

			// SAFETY: I think GetSystemTime is infallable?
			unsafe {
				std::alloc::dealloc(file_time as *mut u8, file_time_layout);
				std::alloc::dealloc(blob as *mut u8, blob_layout);
			}

			// yes... I know...
			assert_eq!(key.len(), 32);
			let mut v = Zeroizing::new(Vec::<u8>::with_capacity(32));
			v.extend(key.as_ref());
			v
		}
	}).await.unwrap()
}
