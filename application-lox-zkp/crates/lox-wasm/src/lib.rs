use chrono::{DateTime, NaiveDateTime, NaiveTime, Utc};
use julianday::JulianDay;
use lox_library::bridge_table::{BridgeLine, MAX_BRIDGES_PER_BUCKET};
use lox_library::cred::{Invitation, Migration};
use lox_library::dumper;
use lox_library::proto::{
    blockage_migration, check_blockage, issue_invite, level_up, migration, open_invite,
    redeem_invite, trust_promotion, update_cred, update_invite,
};
use lox_library::scalar_u32;
use std::panic;
use wasm_bindgen::prelude::*;

// Returns today's Julian date as a u32 value
fn today() -> u32 {
    let naive_now = Utc::now().date_naive();
    JulianDay::from(naive_now).inner().try_into().unwrap()
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(s: &str);
}

#[wasm_bindgen]
pub fn set_panic_hook() {
    panic::set_hook(Box::new(console_error_panic_hook::hook));
}

// Receives an invite and prepares an open_invite request, returning the
// Request and State
#[wasm_bindgen]
pub fn open_invite(base64_invite: String, lox_pub: String) -> Result<String, JsValue> {
    dumper::dump_to_string();
    log(&format!("Using invite: {base64_invite}"));
    let invite: lox_utils::Invite = match serde_json::from_str(&base64_invite) {
        Ok(invite) => invite,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let token = match lox_utils::validate(&invite.invite) {
        Ok(token) => token,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let pubkeys: lox_utils::PubKeys = match serde_json::from_str(&lox_pub) {
        Ok(pubkeys) => pubkeys,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let (request, state) = open_invite::request(&token, &pubkeys.lox_pub);
    let req_state = lox_utils::OpenReqState { request, state };
    let buf = dumper::dump_buffer();
    log(&format!(
        "Dump buffer: {}",
        serde_json::to_string(&buf).unwrap()
    ));
    log(&format!(
        "Formatted open invite request: {}",
        serde_json::to_string(&req_state).unwrap()
    ));
    match serde_json::to_string(&req_state) {
        Ok(req_state) => Ok(req_state),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}

#[wasm_bindgen]
pub fn handle_new_lox_credential(
    open_lox_result: String,
    open_lox_response: String,
    lox_pub: String,
) -> Result<String, JsValue> {
    dumper::dump_to_string();
    let req_state: lox_utils::OpenReqState = match serde_json::from_str(&open_lox_result) {
        Ok(req_state) => req_state,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let deserialized_state = req_state.state;
    let deserialized_response = match serde_json::from_str(&open_lox_response) {
        Ok(deserialized_response) => deserialized_response,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let pubkeys: lox_utils::PubKeys = match serde_json::from_str(&lox_pub) {
        Ok(pubkeys) => pubkeys,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let lox_cred = match open_invite::handle_response(
        deserialized_state,
        deserialized_response,
        &pubkeys.lox_pub,
    ) {
        Ok(lox_cred) => lox_cred,
        Err(e) => {
            log(&format!("Error: {:?}", e.to_string()));
            return Err(JsValue::from(e.to_string()));
        }
    };
    let lox_cred = lox_utils::LoxCredential {
        lox_credential: lox_cred.0,
        bridgelines: Some(vec![lox_cred.1]),
        invitation: None,
    };
    let buf = dumper::dump_buffer();
    log(&format!(
        "Dump buffer: {}",
        serde_json::to_string(&buf).unwrap()
    ));

    log(&format!(
        "Got new Lox Credential: {}",
        serde_json::to_string(&lox_cred.lox_credential).unwrap()
    ));
    log(&format!(
        "Got new bridgeline: {}",
        serde_json::to_string(&lox_cred.bridgelines).unwrap()
    ));
    match serde_json::to_string(&lox_cred) {
        Ok(lox_cred) => Ok(lox_cred),
        Err(e) => {
            log(&format!("Error: {:?}", e.to_string()));
            Err(JsValue::from(e.to_string()))
        }
    }
}

#[wasm_bindgen]
pub fn trust_promotion(
    open_lox_cred: String,
    lox_pub: String,
    server_today: u32,
) -> Result<String, JsValue> {
    dumper::dump_to_string();
    let lox_cred: lox_utils::LoxCredential = match serde_json::from_str(&open_lox_cred) {
        Ok(lox_cred) => lox_cred,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let pubkeys: lox_utils::PubKeys = match serde_json::from_str(&lox_pub) {
        Ok(pubkeys) => pubkeys,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    // To test creation of the credential we need to advance the day to 30
    // in production this should just use the today() function
    log(&format!(
        "TEST ONLY: Add 31 days to today's date: {}",
        server_today
    ));

    let tp_result = match trust_promotion::request(
        &lox_cred.lox_credential,
        &pubkeys.lox_pub,
        &pubkeys.migrationkey_pub,
        server_today,
    ) {
        Ok(tp_result) => tp_result,
        Err(e) => {
            log(&format!("Error: {:?}", e.to_string()));
            return Err(JsValue::from(e.to_string()));
        }
    };
    let req_state = lox_utils::TrustReqState {
        request: tp_result.0,
        state: tp_result.1,
    };
    let buf = dumper::dump_buffer();
    log(&format!(
        "Dump buffer: {}",
        serde_json::to_string(&buf).unwrap()
    ));

    log(&format!(
        "Formatted Trust Promotion request: {}",
        serde_json::to_string(&req_state).unwrap()
    ));
    match serde_json::to_string(&req_state) {
        Ok(req_state) => Ok(req_state),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}

#[wasm_bindgen]
pub fn handle_trust_promotion(
    trust_promo_request: String,
    trust_promo_response: String,
) -> Result<String, JsValue> {
    dumper::dump_to_string();
    let req_state: lox_utils::TrustReqState = match serde_json::from_str(&trust_promo_request) {
        Ok(req_state) => req_state,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let deserialized_state = req_state.state;
    let deserialized_response = match serde_json::from_str(&trust_promo_response) {
        Ok(deserialized_response) => deserialized_response,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let migration_cred =
        match trust_promotion::handle_response(deserialized_state, deserialized_response) {
            Ok(migration_cred) => migration_cred,
            Err(e) => {
                log(&format!("Error: {:?}", e.to_string()));
                return Err(JsValue::from(e.to_string()));
            }
        };
    let buf = dumper::dump_buffer();
    log(&format!(
        "Dump buffer: {}",
        serde_json::to_string(&buf).unwrap()
    ));

    log(&format!(
        "Got new Migration Credential: {}",
        serde_json::to_string(&migration_cred).unwrap()
    ));
    match serde_json::to_string(&migration_cred) {
        Ok(migration_cred) => Ok(migration_cred),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}

#[wasm_bindgen]
pub fn trust_migration(
    open_lox_cred: String,
    trust_promo_cred: String,
    lox_pub: String,
) -> Result<String, JsValue> {
    dumper::dump_to_string();
    let lox_cred: lox_utils::LoxCredential = match serde_json::from_str(&open_lox_cred) {
        Ok(lox_cred) => lox_cred,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let pubkeys: lox_utils::PubKeys = match serde_json::from_str(&lox_pub) {
        Ok(pubkeys) => pubkeys,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let mig_cred: Migration = serde_json::from_str(&trust_promo_cred).unwrap();
    let tm_result = match migration::request(
        &lox_cred.lox_credential,
        &mig_cred,
        &pubkeys.lox_pub,
        &pubkeys.migration_pub,
    ) {
        Ok(tm_result) => tm_result,
        Err(e) => {
            log(&format!("Error: {:?}", e.to_string()));
            return Err(JsValue::from(e.to_string()));
        }
    };
    let req_state = lox_utils::MigReqState {
        request: tm_result.0,
        state: tm_result.1,
    };
    let buf = dumper::dump_buffer();
    log(&format!(
        "Dump buffer: {}",
        serde_json::to_string(&buf).unwrap()
    ));

    log(&format!(
        "Formatted Trust Migration request: {}",
        serde_json::to_string(&req_state).unwrap()
    ));
    match serde_json::to_string(&req_state) {
        Ok(req_state) => Ok(req_state),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}

#[wasm_bindgen]
pub fn handle_trust_migration(
    trust_migration_request: String,
    trust_migration_response: String,
    lox_pub: String,
) -> Result<String, JsValue> {
    dumper::dump_to_string();
    let pubkeys: lox_utils::PubKeys = match serde_json::from_str(&lox_pub) {
        Ok(pubkeys) => pubkeys,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let req_state: lox_utils::MigReqState = match serde_json::from_str(&trust_migration_request) {
        Ok(req_state) => req_state,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let deserialized_state = req_state.state;
    let deserialized_response = match serde_json::from_str(&trust_migration_response) {
        Ok(deserialized_response) => deserialized_response,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let level_one_cred = match migration::handle_response(
        deserialized_state,
        deserialized_response,
        &pubkeys.lox_pub,
    ) {
        Ok(level_1_cred) => lox_utils::LoxCredential {
            lox_credential: level_1_cred,
            bridgelines: None,
            invitation: None,
        },
        Err(e) => {
            log(&format!("Error: {:?}", e.to_string()));
            return Err(JsValue::from(e.to_string()));
        }
    };
    let buf = dumper::dump_buffer();
    log(&format!(
        "Dump buffer: {}",
        serde_json::to_string(&buf).unwrap()
    ));

    log(&format!(
        "Got new Level 1 Credential: {}",
        serde_json::to_string(&level_one_cred).unwrap()
    ));

    match serde_json::to_string(&level_one_cred) {
        Ok(level_one_cred) => Ok(level_one_cred),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}

#[wasm_bindgen]
pub fn level_up(
    level_one_cred: String,
    encrypted_table: String,
    lox_pub: String,
    server_today: u32,
) -> Result<String, JsValue> {
    dumper::dump_to_string();
    let lox_cred: lox_utils::LoxCredential = match serde_json::from_str(&level_one_cred) {
        Ok(lox_cred) => lox_cred,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let pubkeys: lox_utils::PubKeys = match serde_json::from_str(&lox_pub) {
        Ok(pubkeys) => pubkeys,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let reach_cred =
        lox_utils::generate_reachability_cred(&lox_cred.lox_credential, encrypted_table);

    // To test creation of the credential we need to advance the day to 30
    // in production this should just use the today() function
    log(&format!(
        "TEST ONLY: Today's date on Server: {}",
        server_today
    ));

    let lu_result = match level_up::request(
        &lox_cred.lox_credential,
        &reach_cred,
        &pubkeys.lox_pub,
        &pubkeys.reachability_pub,
        server_today,
    ) {
        Ok(lu_result) => lu_result,
        Err(e) => {
            log(&format!("Error: {:?}", e.to_string()));
            return Err(JsValue::from(e.to_string()));
        }
    };
    let req_state = lox_utils::LevelupReqState {
        request: lu_result.0,
        state: lu_result.1,
    };
    let buf = dumper::dump_buffer();
    log(&format!(
        "Dump buffer: {}",
        serde_json::to_string(&buf).unwrap()
    ));

    log(&format!(
        "Formatted Level Up request: {}",
        serde_json::to_string(&req_state).unwrap()
    ));
    match serde_json::to_string(&req_state) {
        Ok(req_state) => Ok(req_state),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}

#[wasm_bindgen]
pub fn handle_level_up(
    levelup_request: String,
    levelup_response: String,
    lox_pub: String,
) -> Result<String, JsValue> {
    dumper::dump_to_string();
    let pubkeys: lox_utils::PubKeys = match serde_json::from_str(&lox_pub) {
        Ok(pubkeys) => pubkeys,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let req_state: lox_utils::LevelupReqState = match serde_json::from_str(&levelup_request) {
        Ok(req_state) => req_state,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let deserialized_state = req_state.state;
    let deserialized_response = match serde_json::from_str(&levelup_response) {
        Ok(deserialized_response) => deserialized_response,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let level_up_cred = match level_up::handle_response(
        deserialized_state,
        deserialized_response,
        &pubkeys.lox_pub,
    ) {
        Ok(level_up_cred) => lox_utils::LoxCredential {
            lox_credential: level_up_cred,
            bridgelines: None,
            invitation: None,
        },
        Err(e) => {
            log(&format!("Error: {:?}", e.to_string()));
            return Err(JsValue::from(e.to_string()));
        }
    };
    let buf = dumper::dump_buffer();
    log(&format!(
        "Dump buffer: {}",
        serde_json::to_string(&buf).unwrap()
    ));

    log(&format!(
        "Got new Level Up Credential: {}",
        serde_json::to_string(&level_up_cred).unwrap()
    ));
    match serde_json::to_string(&level_up_cred) {
        Ok(level_up_cred) => Ok(level_up_cred),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}

#[wasm_bindgen]
pub fn issue_invite(
    trusted_cred: String,
    encrypted_table: String,
    lox_pub: String,
    server_today: u32,
) -> Result<String, JsValue> {
    dumper::dump_to_string();
    let lox_cred: lox_utils::LoxCredential = match serde_json::from_str(&trusted_cred) {
        Ok(lox_cred) => lox_cred,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let pubkeys: lox_utils::PubKeys = match serde_json::from_str(&lox_pub) {
        Ok(pubkeys) => pubkeys,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let reach_cred =
        lox_utils::generate_reachability_cred(&lox_cred.lox_credential, encrypted_table);

    let issue_result = match issue_invite::request(
        &lox_cred.lox_credential,
        &reach_cred,
        &pubkeys.lox_pub,
        &pubkeys.reachability_pub,
        &pubkeys.invitation_pub,
        server_today,
    ) {
        Ok(issue_result) => issue_result,
        Err(e) => {
            log(&format!("Error: {:?}", e.to_string()));
            return Err(JsValue::from(e.to_string()));
        }
    };
    let req_state = lox_utils::IssueInviteReqState {
        request: issue_result.0,
        state: issue_result.1,
    };
    let buf = dumper::dump_buffer();
    log(&format!(
        "Dump buffer: {}",
        serde_json::to_string(&buf).unwrap()
    ));

    log(&format!(
        "Formatted Issue Invite request: {}",
        serde_json::to_string(&req_state).unwrap()
    ));
    match serde_json::to_string(&req_state) {
        Ok(req_state) => Ok(req_state),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}

#[wasm_bindgen]
pub fn handle_issue_invite(
    issue_invite_request: String,
    issue_invite_response: String,
    lox_pub: String,
) -> Result<String, JsValue> {
    dumper::dump_to_string();
    let pubkeys: lox_utils::PubKeys = match serde_json::from_str(&lox_pub) {
        Ok(pubkeys) => pubkeys,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let req_state: lox_utils::IssueInviteReqState =
        match serde_json::from_str(&issue_invite_request) {
            Ok(req_state) => req_state,
            Err(e) => return Err(JsValue::from(e.to_string())),
        };
    let deserialized_state = req_state.state;
    let deserialized_response = match serde_json::from_str(&issue_invite_response) {
        Ok(deserialized_response) => deserialized_response,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let issue_invite_cred = match issue_invite::handle_response(
        deserialized_state,
        deserialized_response,
        &pubkeys.lox_pub,
        &pubkeys.invitation_pub,
    ) {
        Ok(issue_invite_cred) => issue_invite_cred,
        Err(e) => {
            log(&format!("Error: {:?}", e.to_string()));
            return Err(JsValue::from(e.to_string()));
        }
    };
    let invitation_cred = lox_utils::LoxCredential {
        lox_credential: issue_invite_cred.0,
        bridgelines: None,
        invitation: Some(issue_invite_cred.1),
    };

    let buf = dumper::dump_buffer();
    log(&format!(
        "Dump buffer: {}",
        serde_json::to_string(&buf).unwrap()
    ));

    log(&format!(
        "Got new Invitation Credential and Lox Credential: {}",
        serde_json::to_string(&invitation_cred).unwrap()
    ));
    match serde_json::to_string(&invitation_cred) {
        Ok(invitation_cred) => Ok(invitation_cred),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}

// Separate Trusted Invite from credential prior to passing it to friend
#[wasm_bindgen]
pub fn prepare_invite(invitation_cred: String) -> Result<String, JsValue> {
    let cred: lox_utils::LoxCredential = match serde_json::from_str(&invitation_cred) {
        Ok(lox_cred) => lox_cred,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    log(&format!(
        "Prepared Invitation: {}",
        serde_json::to_string(&cred.invitation).unwrap()
    ));
    let invite: Invitation = cred.invitation.unwrap();
    match serde_json::to_string(&invite) {
        Ok(invitation) => Ok(invitation),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}

//
#[wasm_bindgen]
pub fn redeem_invite(
    invitation: String,
    lox_pub: String,
    server_today: u32,
) -> Result<String, JsValue> {
    dumper::dump_to_string();
    let invitation_cred: Invitation = match serde_json::from_str(&invitation) {
        Ok(invitation_cred) => invitation_cred,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let pubkeys: lox_utils::PubKeys = match serde_json::from_str(&lox_pub) {
        Ok(pubkeys) => pubkeys,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let redeem_result = match redeem_invite::request(
        &invitation_cred,
        &pubkeys.lox_pub,
        &pubkeys.invitation_pub,
        server_today,
    ) {
        Ok(redeem_result) => redeem_result,
        Err(e) => {
            log(&format!("Error: {:?}", e.to_string()));
            return Err(JsValue::from(e.to_string()));
        }
    };
    let req_state = lox_utils::RedeemReqState {
        request: redeem_result.0,
        state: redeem_result.1,
    };
    let buf = dumper::dump_buffer();
    log(&format!(
        "Dump buffer: {}",
        serde_json::to_string(&buf).unwrap()
    ));

    log(&format!(
        "Formatted Redeem Invite request: {}",
        serde_json::to_string(&req_state).unwrap()
    ));
    match serde_json::to_string(&req_state) {
        Ok(req_state) => Ok(req_state),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}

#[wasm_bindgen]
pub fn handle_redeem_invite(
    redeem_invite_request: String,
    redeem_invite_response: String,
    lox_pub: String,
) -> Result<String, JsValue> {
    dumper::dump_to_string();
    let pubkeys: lox_utils::PubKeys = match serde_json::from_str(&lox_pub) {
        Ok(pubkeys) => pubkeys,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let req_state: lox_utils::RedeemReqState = match serde_json::from_str(&redeem_invite_request) {
        Ok(req_state) => req_state,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let deserialized_state = req_state.state;
    let deserialized_response = match serde_json::from_str(&redeem_invite_response) {
        Ok(deserialized_response) => deserialized_response,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let redeem_invite_cred = match redeem_invite::handle_response(
        deserialized_state,
        deserialized_response,
        &pubkeys.lox_pub,
    ) {
        Ok(issue_invite_cred) => lox_utils::LoxCredential {
            lox_credential: issue_invite_cred,
            bridgelines: None,
            invitation: None,
        },
        Err(e) => {
            log(&format!("Error: {:?}", e.to_string()));
            return Err(JsValue::from(e.to_string()));
        }
    };
    let buf = dumper::dump_buffer();
    log(&format!(
        "Dump buffer: {}",
        serde_json::to_string(&buf).unwrap()
    ));

    log(&format!(
        "Got new Trusted Lox Credential from Invitation: {}",
        serde_json::to_string(&redeem_invite_cred).unwrap()
    ));
    match serde_json::to_string(&redeem_invite_cred) {
        Ok(redeem_invite_cred) => Ok(redeem_invite_cred),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}

#[wasm_bindgen]
pub fn check_blockage(lox_cred: String, lox_pub: String) -> Result<String, JsValue> {
    dumper::dump_to_string();
    let lox_cred: lox_utils::LoxCredential = match serde_json::from_str(&lox_cred) {
        Ok(lox_cred) => lox_cred,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let pubkeys: lox_utils::PubKeys = match serde_json::from_str(&lox_pub) {
        Ok(pubkeys) => pubkeys,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let cb_result = match check_blockage::request(
        &lox_cred.lox_credential,
        &pubkeys.lox_pub,
        &pubkeys.migrationkey_pub,
    ) {
        Ok(cb_result) => cb_result,
        Err(e) => {
            log(&format!("Error: {:?}", e.to_string()));
            return Err(JsValue::from(e.to_string()));
        }
    };
    let req_state = lox_utils::CheckBlockageReqState {
        request: cb_result.0,
        state: cb_result.1,
    };
    let buf = dumper::dump_buffer();
    log(&format!(
        "Dump buffer: {}",
        serde_json::to_string(&buf).unwrap()
    ));

    log(&format!(
        "Formatted Check Blockage request: {}",
        serde_json::to_string(&req_state).unwrap()
    ));
    match serde_json::to_string(&req_state) {
        Ok(req_state) => Ok(req_state),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}

#[wasm_bindgen]
pub fn handle_check_blockage(
    check_blockage_request: String,
    check_blockage_response: String,
) -> Result<String, JsValue> {
    dumper::dump_to_string();
    let req_state: lox_utils::CheckBlockageReqState =
        match serde_json::from_str(&check_blockage_request) {
            Ok(req_state) => req_state,
            Err(e) => return Err(JsValue::from(e.to_string())),
        };
    let deserialized_state = req_state.state;
    let deserialized_response = match serde_json::from_str(&check_blockage_response) {
        Ok(deserialized_response) => deserialized_response,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let migration_cred =
        match check_blockage::handle_response(deserialized_state, deserialized_response) {
            Ok(migration_cred) => migration_cred,
            Err(e) => {
                log(&format!("Error: {:?}", e.to_string()));
                return Err(JsValue::from(e.to_string()));
            }
        };
    let buf = dumper::dump_buffer();
    log(&format!(
        "Dump buffer: {}",
        serde_json::to_string(&buf).unwrap()
    ));

    log(&format!(
        "Got new Blockage Migration Credential: {}",
        serde_json::to_string(&migration_cred).unwrap()
    ));
    match serde_json::to_string(&migration_cred) {
        Ok(migration_cred) => Ok(migration_cred),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}

#[wasm_bindgen]
pub fn blockage_migration(
    lox_cred: String,
    check_migration_cred: String,
    lox_pub: String,
) -> Result<String, JsValue> {
    dumper::dump_to_string();
    let lox_cred: lox_utils::LoxCredential = match serde_json::from_str(&lox_cred) {
        Ok(lox_cred) => lox_cred,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let pubkeys: lox_utils::PubKeys = match serde_json::from_str(&lox_pub) {
        Ok(pubkeys) => pubkeys,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let mig_cred: Migration = serde_json::from_str(&check_migration_cred).unwrap();
    let bm_result = match blockage_migration::request(
        &lox_cred.lox_credential,
        &mig_cred,
        &pubkeys.lox_pub,
        &pubkeys.migration_pub,
    ) {
        Ok(bm_result) => bm_result,
        Err(e) => {
            log(&format!("Error: {:?}", e.to_string()));
            return Err(JsValue::from(e.to_string()));
        }
    };
    let req_state = lox_utils::BlockageMigReqState {
        request: bm_result.0,
        state: bm_result.1,
    };
    let buf = dumper::dump_buffer();
    log(&format!(
        "Dump buffer: {}",
        serde_json::to_string(&buf).unwrap()
    ));

    log(&format!(
        "Formatted Blockage Migration request: {}",
        serde_json::to_string(&req_state).unwrap()
    ));
    match serde_json::to_string(&req_state) {
        Ok(req_state) => Ok(req_state),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}

#[wasm_bindgen]
pub fn handle_blockage_migration(
    blockage_migration_request: String,
    blockage_migration_response: String,
    lox_pub: String,
) -> Result<String, JsValue> {
    dumper::dump_to_string();
    let pubkeys: lox_utils::PubKeys = match serde_json::from_str(&lox_pub) {
        Ok(pubkeys) => pubkeys,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let req_state: lox_utils::BlockageMigReqState =
        match serde_json::from_str(&blockage_migration_request) {
            Ok(req_state) => req_state,
            Err(e) => return Err(JsValue::from(e.to_string())),
        };
    let deserialized_state = req_state.state;
    let deserialized_response = match serde_json::from_str(&blockage_migration_response) {
        Ok(deserialized_response) => deserialized_response,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let lox_cred = match blockage_migration::handle_response(
        deserialized_state,
        deserialized_response,
        &pubkeys.lox_pub,
    ) {
        Ok(lox_cred) => lox_utils::LoxCredential {
            lox_credential: lox_cred,
            bridgelines: None,
            invitation: None,
        },
        Err(e) => {
            log(&format!("Error: {:?}", e.to_string()));
            return Err(JsValue::from(e.to_string()));
        }
    };
    let buf = dumper::dump_buffer();
    log(&format!(
        "Dump buffer: {}",
        serde_json::to_string(&buf).unwrap()
    ));

    log(&format!(
        "Got new Lox Credential after Migration: {}",
        serde_json::to_string(&lox_cred).unwrap()
    ));
    match serde_json::to_string(&lox_cred) {
        Ok(lox_cred) => Ok(lox_cred),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}

#[wasm_bindgen]
pub fn update_cred(
    lox_cred: String,
    old_lox_pub: String,
    new_lox_pub: String,
) -> Result<String, JsValue> {
    dumper::dump_to_string();
    let lox_cred: lox_utils::LoxCredential = match serde_json::from_str(&lox_cred) {
        Ok(lox_cred) => lox_cred,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let old_pubkeys: lox_utils::PubKeys = match serde_json::from_str(&old_lox_pub) {
        Ok(pubkeys) => pubkeys,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let new_pubkeys: lox_utils::PubKeys = match serde_json::from_str(&new_lox_pub) {
        Ok(pubkeys) => pubkeys,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let up_cred_result = match update_cred::request(
        &lox_cred.lox_credential,
        &old_pubkeys.lox_pub,
        &new_pubkeys.lox_pub,
    ) {
        Ok(up_result) => up_result,
        Err(e) => {
            log(&format!("Error: {:?}", e.to_string()));
            return Err(JsValue::from(e.to_string()));
        }
    };
    let req_state = lox_utils::UpdateCredReqState {
        request: up_cred_result.0,
        state: up_cred_result.1,
    };
    let buf = dumper::dump_buffer();
    log(&format!(
        "Dump buffer: {}",
        serde_json::to_string(&buf).unwrap()
    ));

    log(&format!(
        "Formatted Update Credential request: {}",
        serde_json::to_string(&req_state).unwrap()
    ));
    match serde_json::to_string(&req_state) {
        Ok(req_state) => Ok(req_state),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}

#[wasm_bindgen]
pub fn handle_update_cred(
    update_cred_request: String,
    update_cred_response: String,
    updated_lox_pub: String,
) -> Result<String, JsValue> {
    dumper::dump_to_string();
    let pubkeys: lox_utils::PubKeys = match serde_json::from_str(&updated_lox_pub) {
        Ok(pubkeys) => pubkeys,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let req_state: lox_utils::UpdateCredReqState = match serde_json::from_str(&update_cred_request)
    {
        Ok(req_state) => req_state,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let deserialized_state = req_state.state;
    let deserialized_response = match serde_json::from_str(&update_cred_response) {
        Ok(deserialized_response) => deserialized_response,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let lox_cred = match update_cred::handle_response(
        deserialized_state,
        deserialized_response,
        &pubkeys.lox_pub,
    ) {
        Ok(lox_cred) => lox_utils::LoxCredential {
            lox_credential: lox_cred,
            bridgelines: None,
            invitation: None,
        },
        Err(e) => {
            log(&format!("Error: {:?}", e.to_string()));
            return Err(JsValue::from(e.to_string()));
        }
    };
    let buf = dumper::dump_buffer();
    log(&format!(
        "Dump buffer: {}",
        serde_json::to_string(&buf).unwrap()
    ));

    log(&format!(
        "Got updated Lox Credential after Lox Key Rotation: {}",
        serde_json::to_string(&lox_cred).unwrap()
    ));
    match serde_json::to_string(&lox_cred) {
        Ok(lox_cred) => Ok(lox_cred),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}

#[wasm_bindgen]
pub fn update_invite(
    invite_cred: String,
    old_lox_pub: String,
    new_lox_pub: String,
) -> Result<String, JsValue> {
    dumper::dump_to_string();
    let invite_cred: Invitation = match serde_json::from_str(&invite_cred) {
        Ok(invite_cred) => invite_cred,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let old_pubkeys: lox_utils::PubKeys = match serde_json::from_str(&old_lox_pub) {
        Ok(pubkeys) => pubkeys,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let new_pubkeys: lox_utils::PubKeys = match serde_json::from_str(&new_lox_pub) {
        Ok(pubkeys) => pubkeys,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let up_invite_result = match update_invite::request(
        &invite_cred,
        &old_pubkeys.invitation_pub,
        &new_pubkeys.invitation_pub,
    ) {
        Ok(up_result) => up_result,
        Err(e) => {
            log(&format!("Error: {:?}", e.to_string()));
            return Err(JsValue::from(e.to_string()));
        }
    };
    let req_state = lox_utils::UpdateInviteReqState {
        request: up_invite_result.0,
        state: up_invite_result.1,
    };
    let buf = dumper::dump_buffer();
    log(&format!(
        "Dump buffer: {}",
        serde_json::to_string(&buf).unwrap()
    ));

    log(&format!(
        "Formatted Update Credential request: {}",
        serde_json::to_string(&req_state).unwrap()
    ));
    match serde_json::to_string(&req_state) {
        Ok(req_state) => Ok(req_state),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}

#[wasm_bindgen]
pub fn handle_update_invite(
    update_invite_request: String,
    update_invite_response: String,
    updated_lox_pub: String,
) -> Result<String, JsValue> {
    dumper::dump_to_string();
    let pubkeys: lox_utils::PubKeys = match serde_json::from_str(&updated_lox_pub) {
        Ok(pubkeys) => pubkeys,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let req_state: lox_utils::UpdateInviteReqState =
        match serde_json::from_str(&update_invite_request) {
            Ok(req_state) => req_state,
            Err(e) => return Err(JsValue::from(e.to_string())),
        };
    let deserialized_response = match serde_json::from_str(&update_invite_response) {
        Ok(deserialized_response) => deserialized_response,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let lox_cred = match update_invite::handle_response(
        req_state.state,
        deserialized_response,
        &pubkeys.invitation_pub,
    ) {
        Ok(invite) => invite,
        Err(e) => {
            log(&format!("Error: {:?}", e.to_string()));
            return Err(JsValue::from(e.to_string()));
        }
    };
    let buf = dumper::dump_buffer();
    log(&format!(
        "Dump buffer: {}",
        serde_json::to_string(&buf).unwrap()
    ));

    log(&format!(
        "Got updated Lox Invitation after Invitation Key Rotation: {}",
        serde_json::to_string(&lox_cred).unwrap()
    ));
    match serde_json::to_string(&lox_cred) {
        Ok(lox_cred) => Ok(lox_cred),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}

#[wasm_bindgen]
pub fn get_last_upgrade_time(lox_cred_str: String) -> Result<String, JsValue> {
    let lox_cred: lox_utils::LoxCredential = match serde_json::from_str(&lox_cred_str) {
        Ok(lox_cred) => lox_cred,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let upgrade_date = scalar_u32(&lox_cred.lox_credential.level_since).unwrap();
    let date_time = JulianDay::new(upgrade_date as i32).to_date();
    log(&format!(
        "Time of last upgrade {}",
        serde_json::to_string(&date_time).unwrap()
    ));
    match serde_json::to_string(&date_time) {
        Ok(date_str) => Ok(date_str),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}

#[wasm_bindgen]
pub fn get_trust_level(lox_cred_str: String) -> Result<String, JsValue> {
    let lox_cred: lox_utils::LoxCredential = match serde_json::from_str(&lox_cred_str) {
        Ok(lox_cred) => lox_cred,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let trust_level = scalar_u32(&lox_cred.lox_credential.trust_level).unwrap();
    log(&format!(
        "Trust level {}",
        serde_json::to_string(&trust_level).unwrap()
    ));
    match serde_json::to_string(&trust_level) {
        Ok(trust_str) => Ok(trust_str),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}

#[wasm_bindgen]
pub fn get_invites_remaining(lox_cred_str: String) -> Result<String, JsValue> {
    let lox_cred: lox_utils::LoxCredential = match serde_json::from_str(&lox_cred_str) {
        Ok(lox_cred) => lox_cred,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let invites = scalar_u32(&lox_cred.lox_credential.invites_remaining);
    log(&format!(
        "Invites remaining {}",
        serde_json::to_string(&invites).unwrap()
    ));
    match serde_json::to_string(&invites) {
        Ok(invite_str) => Ok(invite_str),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}

#[wasm_bindgen]
pub fn get_issued_invite_expiry(lox_cred_str: String) -> Result<String, JsValue> {
    let lox_cred: lox_utils::LoxCredential = match serde_json::from_str(&lox_cred_str) {
        Ok(lox_cred) => lox_cred,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    match lox_cred.invitation {
        Some(invitation) => {
            let expiry = (scalar_u32(&invitation.date).unwrap() + 15) as i32;
            let date_time = JulianDay::new(expiry).to_date();
            println!("Datetime is: {date_time}");
            log(&format!(
                "Invitation Expiry {}",
                serde_json::to_string(&date_time).unwrap()
            ));
            match serde_json::to_string(&date_time) {
                Ok(inv_date_str) => Ok(inv_date_str),
                Err(e) => Err(JsValue::from(e.to_string())),
            }
        }
        None => Err(JsValue::from("No Invitation Issued")),
    }
}

#[wasm_bindgen]
pub fn get_received_invite_expiry(invite_cred_str: String) -> Result<String, JsValue> {
    let invite_cred: lox_utils::IssuedInvitation = match serde_json::from_str(&invite_cred_str) {
        Ok(invite_cred) => invite_cred,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let expiry = (scalar_u32(&invite_cred.invitation.date).unwrap() + 15) as i32;
    let date_time = JulianDay::new(expiry).to_date();
    println!("Datetime is: {date_time}");
    log(&format!(
        "Invitation Expiry {}",
        serde_json::to_string(&date_time).unwrap()
    ));
    match serde_json::to_string(&date_time) {
        Ok(date_str) => Ok(date_str),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}

#[wasm_bindgen]
pub fn get_bridgelines_from_bucket(
    lox_cred_str: String,
    encrypted_table: String,
) -> Result<String, JsValue> {
    let lox_cred: lox_utils::LoxCredential = match serde_json::from_str(&lox_cred_str) {
        Ok(lox_cred) => lox_cred,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let bridgelines =
        lox_utils::get_credential_bridgelines(&lox_cred.lox_credential, encrypted_table);
    log(&format!(
        "Lox BridgeLines available {}",
        serde_json::to_string(&bridgelines).unwrap()
    ));
    match serde_json::to_string(&bridgelines) {
        Ok(bridgelines_str) => Ok(bridgelines_str),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}

#[wasm_bindgen]
pub fn get_bridge_fingerprint(bridgelines_str: String, index: u32) -> Result<String, JsValue> {
    let bridgelines: [BridgeLine; MAX_BRIDGES_PER_BUCKET] =
        match serde_json::from_str(&bridgelines_str) {
            Ok(bridgelines) => bridgelines,
            Err(e) => return Err(JsValue::from(e.to_string())),
        };
    let bridge = bridgelines.get(index as usize).unwrap();
    match serde_json::to_string(&bridge) {
        Ok(converted) => Ok(converted),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}

#[wasm_bindgen]
pub fn invitation_is_trusted(unspecified_invitation_str: String) -> Result<bool, JsValue> {
    match serde_json::from_str::<Invitation>(&unspecified_invitation_str) {
        Ok(_) => Ok(true),
        Err(_) => match serde_json::from_str::<lox_utils::Invite>(&unspecified_invitation_str) {
            Ok(_) => Ok(false),
            Err(e) => Err(JsValue::from(e.to_string())),
        },
    }
}

#[wasm_bindgen]
pub fn get_next_unlock(constants_str: String, lox_cred_str: String) -> Result<String, JsValue> {
    let constants: lox_utils::LoxSystemInfo = match serde_json::from_str(&constants_str) {
        Ok(constants) => constants,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let lox_cred: lox_utils::LoxCredential = match serde_json::from_str(&lox_cred_str) {
        Ok(lox_cred) => lox_cred,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let trust_level = scalar_u32(&lox_cred.lox_credential.trust_level).unwrap();
    let (days_to_next_level, mut invitations_at_next_level) = match trust_level as usize {
        // If the credential is at trust level 0, we use the untrusted interval from the
        // trust promotion protocol to calculate the date of the next level update
        0 => (constants.untrusted_interval, 0),

        // Otherwise, we use the invitation and upgrade dates from the level up protocol constants
        _ => (
            constants.level_interval[trust_level as usize],
            constants.level_invitations[trust_level as usize],
        ),
    };
    let mut days_to_invite_inc = days_to_next_level;
    // If there are no invitations at the next trust level upgrade
    // i.e., if the credential is at level 0, calculate the time until they will
    // unlock invitations
    if invitations_at_next_level == 0 {
        days_to_invite_inc =
            days_to_next_level + constants.level_interval[trust_level as usize + 1];
        invitations_at_next_level = constants.level_invitations[trust_level as usize + 1];
    }
    let days_to_blockage_migration_unlock = match trust_level
        < constants.min_blockage_migration_trust_level
    {
        // If the credential is greater than the minimum level that enables
        // migrating after a blockage, the time to unlock is 0, otherwise we
        // add the time to upgrade until that level
        true => {
            let mut blockage_days = days_to_next_level;
            let mut count = 1;
            while trust_level + count < constants.min_blockage_migration_trust_level {
                blockage_days += constants.level_interval[trust_level as usize + count as usize];
                count += 1;
            }
            blockage_days
        }
        false => 0,
    };
    let day_of_level_unlock =
        (scalar_u32(&lox_cred.lox_credential.level_since).unwrap() + days_to_next_level) as i32;
    let level_unlock_date = JulianDay::new(day_of_level_unlock).to_date();
    let day_of_invite_unlock =
        (scalar_u32(&lox_cred.lox_credential.level_since).unwrap() + days_to_invite_inc) as i32;
    let invite_unlock_date = JulianDay::new(day_of_invite_unlock).to_date();
    let day_of_blockage_migration_unlock = (scalar_u32(&lox_cred.lox_credential.level_since)
        .unwrap()
        + days_to_blockage_migration_unlock) as i32;
    let blockage_migration_unlock_date =
        JulianDay::new(day_of_blockage_migration_unlock as i32).to_date();
    let next_unlock: lox_utils::LoxNextUnlock = lox_utils::LoxNextUnlock {
        trust_level_unlock_date: DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDateTime::new(level_unlock_date, NaiveTime::from_hms_opt(0, 0, 0).unwrap()),
            Utc,
        ),
        invitation_unlock_date: DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDateTime::new(
                invite_unlock_date,
                NaiveTime::from_hms_opt(0, 0, 0).unwrap(),
            ),
            Utc,
        ),
        num_invitations_unlocked: invitations_at_next_level,
        blockage_migration_unlock_date: DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDateTime::new(
                blockage_migration_unlock_date,
                NaiveTime::from_hms_opt(0, 0, 0).unwrap(),
            ),
            Utc,
        ),
    };
    match serde_json::to_string(&next_unlock) {
        Ok(next_unlock) => Ok(next_unlock),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}

#[wasm_bindgen]
pub fn check_lox_pubkeys_update(
    new_pubkeys_str: String,
    old_pubkeys_str: String,
    old_lox_cred: String,
) -> Result<String, JsValue> {
    let old_pubkeys: lox_utils::PubKeys = match serde_json::from_str(&old_pubkeys_str) {
        Ok(old_pubkeys) => old_pubkeys,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let new_pubkeys: lox_utils::PubKeys = match serde_json::from_str(&new_pubkeys_str) {
        Ok(new_pubkeys) => new_pubkeys,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };

    if old_pubkeys.lox_pub != new_pubkeys.lox_pub {
        match update_cred(old_lox_cred, old_pubkeys_str, new_pubkeys_str) {
            Ok(update_req) => {
                let update_cred = lox_utils::UpdateCredOption {
                    updated: true,
                    req: update_req,
                };
                return match serde_json::to_string(&update_cred) {
                    Ok(next_unlock) => Ok(next_unlock),
                    Err(e) => Err(JsValue::from(e.to_string())),
                };
            }
            Err(e) => return Err(e),
        }
    }
    let update_cred = lox_utils::UpdateCredOption {
        updated: false,
        req: "None".to_string(),
    };
    match serde_json::to_string(&update_cred) {
        Ok(update) => Ok(update),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}

#[wasm_bindgen]
pub fn check_invitation_pubkeys_update(
    new_pubkeys_str: String,
    old_pubkeys_str: String,
    old_invite_cred: String,
) -> Result<String, JsValue> {
    let old_pubkeys: lox_utils::PubKeys = match serde_json::from_str(&old_pubkeys_str) {
        Ok(old_pubkeys) => old_pubkeys,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };
    let new_pubkeys: lox_utils::PubKeys = match serde_json::from_str(&new_pubkeys_str) {
        Ok(new_pubkeys) => new_pubkeys,
        Err(e) => return Err(JsValue::from(e.to_string())),
    };

    if old_pubkeys.invitation_pub != new_pubkeys.invitation_pub {
        match update_cred(old_invite_cred, old_pubkeys_str, new_pubkeys_str) {
            Ok(update_req) => {
                let update_cred = lox_utils::UpdateCredOption {
                    updated: true,
                    req: update_req,
                };
                return match serde_json::to_string(&update_cred) {
                    Ok(update) => Ok(update),
                    Err(e) => Err(JsValue::from(e.to_string())),
                };
            }
            Err(e) => return Err(e),
        }
    }
    let update_cred = lox_utils::UpdateCredOption {
        updated: false,
        req: "None".to_string(),
    };
    match serde_json::to_string(&update_cred) {
        Ok(update) => Ok(update),
        Err(e) => Err(JsValue::from(e.to_string())),
    }
}
