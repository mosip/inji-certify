drop table rendering_template;
drop table credential_template;
drop table ca_cert_store;

--- Keymanager policy drop ---
DELETE FROM certify.key_policy_def where APP_ID in ('CERTIFY_VC_SIGN_RSA', 'CERTIFY_VC_SIGN_ED25519', 'BASE');
