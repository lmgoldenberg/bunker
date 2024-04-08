// @generated automatically by Diesel CLI.

diesel::table! {
    software_keys (id) {
        id -> Integer,
        origin -> Text,
        encrypted_private_key -> Binary,
        encrypted_private_key_iv -> Binary,
        private_key_sha3_512_sum -> Binary,
    }
}

diesel::table! {
    tpm_keys (id) {
        id -> Integer,
        origin -> Text,
        sealed_private_key -> Binary,
        public_key -> Binary,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    software_keys,
    tpm_keys,
);
