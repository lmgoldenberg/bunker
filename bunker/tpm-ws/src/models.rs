/*
Copyright James Connolly 2024

This file is part of tpm-ws.

tpm-ws is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

tpm-ws is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with tpm-ws. If not, see <https://www.gnu.org/licenses/>.
*/

use diesel::prelude::*;

#[derive(Insertable)]
#[diesel(table_name = crate::schema::tpm_keys)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct NewTpmKeyPair {
	pub origin: String,
	pub sealed_private_key: Vec<u8>,
	pub public_key: Vec<u8>
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::software_keys)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct NewSoftwareKey {
	pub origin: String,
	pub encrypted_private_key: Vec<u8>,
	pub encrypted_private_key_iv: Vec<u8>,
	pub private_key_sha3_512_sum: Vec<u8>
}
