import init, {
  open_invite,
  handle_new_lox_credential,
  trust_promotion,
  handle_trust_promotion,
  trust_migration,
  handle_trust_migration,
  level_up,
  handle_level_up,
  issue_invite,
  handle_issue_invite,
  prepare_invite,
  redeem_invite,
  handle_redeem_invite,
  check_blockage,
  handle_check_blockage,
  blockage_migration,
  handle_blockage_migration, prepare_update_invite, update_cred, handle_update_cred, prepare_update_cred, update_invite,handle_update_invite,
  set_panic_hook, get_last_upgrade_time, get_trust_level, get_invites_remaining, get_next_unlock, get_received_invite_expiry, get_bridgelines_from_bucket, get_bridge_fingerprint} from "./pkg/lox_wasm.js";
let pubkeys = await simple_request("/pubkeys");
console.log("Got pubkeys: " + pubkeys);
let constants = await simple_request("/constants");
console.log("Got constants: " + constants);

// Get Lox Invitation
let requested_invite = await init().then(() => {
  set_panic_hook();
  let requested_invite = request_open_invite().then((token) => {
    return open_invite(token, pubkeys);
  });
  return requested_invite;
});
console.log("Got request and state: "+requested_invite);

// Redeem Lox Invitation for an Open Invitation Lox Credential
// Trust Level 0
let open_lox_cred = await init().then(() => {
  set_panic_hook();
  let cred = open_requested_cred("/openreq", requested_invite).then((response) => {
    console.log("Got new Level 0 Lox Credential: " + response);
    return handle_new_lox_credential(requested_invite, response);
  });
  return cred;
});
let unlock_info = get_next_unlock(constants, open_lox_cred);
console.log("Unlock info: "+unlock_info);
get_last_upgrade_time(open_lox_cred);
get_trust_level(open_lox_cred);
get_invites_remaining(open_lox_cred);

let encrypted_table = await simple_request("/reachability");
let info_five = get_bridgelines_from_bucket(open_lox_cred, encrypted_table, pubkeys);
console.log("Bridgelines available: "+info_five);
let requested_trust_promo = await init().then(() => {
    set_panic_hook();
    let num = 35;
    let req = requested_days("/advancedays", num.toString()).then((today)=> {
        console.log("Advanced days by "+num+" days to: "+today);
        
    return trust_promotion(open_lox_cred, pubkeys, today);
    });
    return req;
});

console.log("Got request and state: "+requested_trust_promo);

// Get Migration credential for Trust Promotion from Trust Level 0 -> 1
let trust_promo_cred = await init().then(() => {
  set_panic_hook();
  let cred = requested_cred("/trustpromo", requested_trust_promo).then((response)=> {
    console.log("Got Migration Credential for Trust Promotion: " + response);
    return handle_trust_promotion(requested_trust_promo, response, pubkeys);
  });
  return cred;
  });


let requested_trust_migration = trust_migration(open_lox_cred, trust_promo_cred);

// Trust Promotion from Trust Level 0 -> 1
let lox_cred = await init().then(() => {
  set_panic_hook();
  let cred = requested_cred("/trustmig", requested_trust_migration).then((response)=> {
    console.log("Got new Level 1 Lox Credential: " + response);
    return handle_trust_migration(requested_trust_migration, response, pubkeys);
  });
  return cred;
  });
// Level Up days + 15
  let num = 15;
  let server_today = await requested_days("/advancedays", num.toString());
  console.log("Advanced days by "+num+" days to: "+ server_today.toString());


encrypted_table = await simple_request("/reachability");
console.log("Got Encrypted Table: " + encrypted_table);
let requested_level_two = level_up(lox_cred, encrypted_table, pubkeys, server_today);

// Level Up to Trust Level 2
lox_cred = await init().then(() => {
  set_panic_hook();
  let cred = requested_cred("/levelup", requested_level_two).then((response)=> {
    console.log("Got new Level 2 Lox Credential: " + response);
    return handle_level_up(requested_level_two, response, pubkeys);
  });
  return cred;
  });

 // Level Up days + 29
  num = 29;
  server_today = await requested_days("/advancedays", num.toString());
  console.log("Advanced days by "+num+" days to: "+ server_today.toString());


// Update reachability cred
  encrypted_table = await simple_request("/reachability");
  console.log("Got Encrypted Table: " + encrypted_table);
  let requested_level_three = level_up(lox_cred, encrypted_table, pubkeys, server_today);

// Level Up to Trust Level 3
  lox_cred = await init().then(() => {
    set_panic_hook();
    let cred = requested_cred("/levelup", requested_level_three).then((response)=> {
      console.log("Got new Level 3 Lox Credential: " + response);
      return handle_level_up(requested_level_three, response, pubkeys);
    });
    return cred;
    });

let info_three = get_invites_remaining(lox_cred);
console.log("Last upgrade time: "+info_three);


  // Level Up days + 57
  num = 57;
  server_today = await requested_days("/advancedays", num.toString());
  console.log("Advanced days by "+num+" days to: "+ server_today.toString());


// Update reachability cred
encrypted_table = await simple_request("/reachability");
console.log("Got Encrypted Table: " + encrypted_table);
let requested_level_four = level_up(lox_cred, encrypted_table, pubkeys, server_today);

// Level Up to Trust Level 4
lox_cred = await init().then(() => {
  set_panic_hook();
  let cred = requested_cred("/levelup", requested_level_four).then((response)=> {
    console.log("Got new Level 4 Lox Credential: " + response);
    return handle_level_up(requested_level_four, response, pubkeys);
  });
  return cred;
  });

// Update reachability cred
encrypted_table = await simple_request("/reachability");
console.log("Got Encrypted Table: " + encrypted_table);
let requested_issue_invitation = issue_invite(lox_cred, encrypted_table, pubkeys, server_today);

// Issue an Invitation cred
lox_cred = await init().then(() => {
  set_panic_hook();
  let cred = requested_cred("/issueinvite", requested_issue_invitation).then((response)=> {
    console.log("Got new Invite and Lox Credential: " + response);
    return handle_issue_invite(requested_issue_invitation, response, pubkeys);
  });
  return cred;
  });

let prepared_invitation = prepare_invite(lox_cred);

await simple_request("/rotate_invite_keys");
console.log("Rotated invite keys");
let new_pubkeys = await simple_request("/pubkeys");
console.log("Got pubkeys: " + pubkeys);
let reqstate_update_invitation = update_invite(prepared_invitation, new_pubkeys);

let up_req = prepare_update_invite(reqstate_update_invitation, pubkeys);
// Update Invitation cred
let new_prepared_invitation = await init().then(() => {
  set_panic_hook();
  let cred = requested_update_invite("/updateinvite", up_req).then((response)=> {
    console.log("Got updated Invite: " + response);
    return handle_update_invite(reqstate_update_invitation, response);
  });
  return cred;
});

console.log("Got prepared invite: " + new_prepared_invitation);

// Trusted Invitation Request
let requested_invitation = redeem_invite(new_prepared_invitation, new_pubkeys, server_today);
// Redeem an Invitation cred

let info_four = get_received_invite_expiry(lox_cred);
console.log("Last upgrade time: "+info_four);

let lox_cred_from_invite = await init().then(() => {
  set_panic_hook();
  let cred = requested_cred("/redeem", requested_invitation).then((response)=> {
    console.log("Got new Trusted Lox Credential Invite: " + response);
    return handle_redeem_invite(requested_invitation, response, new_pubkeys);
  });
  return cred;
  });

await simple_request("/rotate_lox_keys");
console.log("Rotated lox keys");
let new_new_pubkeys = await simple_request("/pubkeys");
console.log("Got pubkeys: " + new_pubkeys);
let reqstate_update_cred = update_cred(lox_cred, new_new_pubkeys);

let up_cred = prepare_update_cred(reqstate_update_cred, new_pubkeys);
// Update Invitation cred
let new_prepared_cred = await init().then(() => {
  set_panic_hook();
  let cred = requested_update_cred("/updatecred", up_cred).then((response)=> {
    console.log("Got updated cred: " + response);
    return handle_update_cred(reqstate_update_cred, response);
  });
  return cred;
  });


  let bridgelines = get_bridgelines_from_bucket(new_prepared_cred, encrypted_table, new_new_pubkeys);
  console.log("Bridgelines available: "+bridgelines);
  let single_bridgeline = get_bridge_fingerprint(bridgelines, 2);
  console.log("Bridgelines available: "+single_bridgeline);

  await loxServerBlockageRequest("/blockbridges", JSON.parse(single_bridgeline));
  let second_bridgeline = get_bridge_fingerprint(bridgelines, 1);
  console.log("Bridgelines available: "+second_bridgeline);

  await loxServerBlockageRequest("/blockbridges", JSON.parse(second_bridgeline));

  let requested_check_blockage = check_blockage(new_prepared_cred, new_new_pubkeys);

  // Check whether or not a bucket is blocked
  let check_migration_cred = await init().then(() => {
    set_panic_hook();
    let cred = requested_cred("/checkblockage", requested_check_blockage).then((response)=> {
      console.log("Got check blockage Migration Credential: " + response);
      return handle_check_blockage(requested_check_blockage, response, new_pubkeys);
    });
    return cred;
    });

let requested_blockage_migration = blockage_migration(new_prepared_cred, check_migration_cred, new_pubkeys);

  // Migrate to a new unblocked bridge
  lox_cred = await init().then(() => {
    set_panic_hook();
    let cred = requested_cred("/blockagemigration", requested_blockage_migration).then((response)=> {
      console.log("Got Lox Credential for new bucket: " + response);
      return handle_blockage_migration(requested_blockage_migration, response, new_pubkeys);
    });
    return cred;
    });

function open_requested_cred(command, requested) {
  return new Promise((fulfill, reject) => {
  let req = JSON.parse(requested);
    loxServerPostRequest(command, req.open_inv_req).then((response) => {
      fulfill(JSON.stringify(response));
      return;
    }).catch(() => {
      console.log("Error requesting new Lox credential from server");
      reject();
    });
  });
}


function requested_cred(command, requested) {
  return new Promise((fulfill, reject) => {
  let req = JSON.parse(requested);
    loxServerPostRequest(command, req.request).then((response) => {
      fulfill(JSON.stringify(response));
      return;
    }).catch(() => {
      console.log("Error requesting new Lox credential from server");
      reject();
    });
  });
}

function requested_update_invite(command, requested) {
  return new Promise((fulfill, reject) => {
  let req = JSON.parse(requested);
    loxServerPostRequest(command, req).then((response) => {
      fulfill(JSON.stringify(response));
      return;
    }).catch(() => {
      console.log("Error requesting new Lox credential from server");
      reject();
    });
  });
}

function requested_update_cred(command, requested) {
  return new Promise((fulfill, reject) => {
  let req = JSON.parse(requested);
    loxServerPostRequest(command, req).then((response) => {
      fulfill(JSON.stringify(response));
      return;
    }).catch(() => {
      console.log("Error requesting new Lox credential from server");
      reject();
    });
  });
}

function requested_days(command, days) {
  return new Promise((fulfill, reject) => {
    let req = JSON.parse(days)
    loxServerPostRequest(command, req).then((response) => {
      fulfill(response);
      return;
    }).catch(() => {
      console.log("Error requesting new Lox credential from server");
      reject();
    });
  });
}


function request_open_invite() {
  return new Promise((fulfill, reject) => {
    loxServerPostRequest("/invite", null).then((response) => {
      console.log("Got invitation token: " + response.invite);
      fulfill(JSON.stringify(response));
      return;
    }).catch(() => {
      console.log("Error requesting open invite from Lox server");
      reject();
    });
  });
}

function simple_request(requested) {
  return new Promise((fulfill, reject) => {
    loxServerPostRequest(requested, null).then((response) => {
      fulfill(JSON.stringify(response));
      return;
    }).catch(() => {
      console.log("Error making simple request: " + requested);
      reject();
    });
  });
}


function loxServerPostRequest(data, payload) {
  return new Promise((fulfill, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
      if (xhr.DONE !== xhr.readyState) {
        return;
      }
      if (xhr.status !== 200) {
        console.log("Error. Status code: "+xhr.status);
        console.log(xhr);
        reject();
        return;
      }
      const response = JSON.parse(xhr.responseText);
      fulfill(response);
      return;
    };
    try {
      xhr.open('POST', "http://localhost:8001"+data, true)
      xhr.setRequestHeader("Content-Type", "application/json");
    } catch (err) {
      console.log("Error connecting to lox bridge db");
      reject();
      return;
    }
    xhr.send(JSON.stringify(payload));
  });
}

function loxServerBlockageRequest(data, payload) {
  return new Promise((fulfill, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
      if (xhr.DONE !== xhr.readyState) {
        return;
      }
      if (xhr.status !== 200) {
        console.log("Error. Status code: "+xhr.status);
        console.log(xhr);
        reject();
        return;
      }
      fulfill();
      return;
    };
    try {
      xhr.open('POST', "http://localhost:8001"+data, true)
      xhr.setRequestHeader("Content-Type", "application/json");
    } catch (err) {
      console.log("Error connecting to lox bridge db");
      reject();
      return;
    }
    xhr.send(JSON.stringify(payload));
  });
}

// The correct key should be matched against a public commit to the key to
// verify that the key issuer is in fact the correct Bridge Authority
function loxKeyRequest(key_type) {
  return new Promise((fulfull, reject) => {


  })
}
