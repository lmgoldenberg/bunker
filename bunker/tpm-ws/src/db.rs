/*
Copyright James Connolly 2024

This file is part of tpm-ws.

tpm-ws is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

tpm-ws is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with tpm-ws. If not, see <https://www.gnu.org/licenses/>.
*/

use diesel::{sql_query, Connection, RunQueryDsl, sqlite::SqliteConnection};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

pub fn get_conn() -> SqliteConnection {
	let mut conn = SqliteConnection::establish("db.sqlite").unwrap();
	sql_query("PRAGMA foreign_keys = ON;").execute(&mut conn).unwrap();
	sql_query("PRAGMA busy_timeout = 500;").execute(&mut conn).unwrap();

	conn
}

pub fn run_migrations() {
	let mut conn = get_conn();
	const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");
	conn.run_pending_migrations(MIGRATIONS).unwrap();
}
