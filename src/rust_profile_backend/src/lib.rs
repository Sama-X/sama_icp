use ic_cdk::{
    api::call::ManualReply,
    export::{
        candid::CandidType,
        serde::{Deserialize, Serialize},
        Principal,
    }
};
use ic_cdk_macros::*;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use lazy_static::lazy_static;


use ic_cdk::{query, update};
use std::convert::TryFrom;
use std::str::FromStr;

#[derive(CandidType, Serialize, Debug)]
struct PublicKeyReply {
    pub public_key_hex: String,
}

#[derive(CandidType, Serialize, Debug)]
struct SignatureReply {
    pub signature_hex: String,
}

#[derive(CandidType, Serialize, Debug)]
struct SignatureVerificationReply {
    pub is_signature_valid: bool,
}

type CanisterId = Principal;

#[derive(CandidType, Serialize, Debug)]
struct ECDSAPublicKey {
    pub canister_id: Option<CanisterId>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: EcdsaKeyId,
}

#[derive(CandidType, Deserialize, Debug)]
struct ECDSAPublicKeyReply {
    pub public_key: Vec<u8>,
    pub chain_code: Vec<u8>,
}

#[derive(CandidType, Serialize, Debug)]
struct SignWithECDSA {
    pub message_hash: Vec<u8>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: EcdsaKeyId,
}

#[derive(CandidType, Deserialize, Debug)]
struct SignWithECDSAReply {
    pub signature: Vec<u8>,
}

#[derive(CandidType, Serialize, Debug, Clone)]
struct EcdsaKeyId {
    pub curve: EcdsaCurve,
    pub name: String,
}

#[derive(CandidType, Serialize, Debug, Clone)]
pub enum EcdsaCurve {
    #[serde(rename = "secp256k1")]
    Secp256k1,
}

#[update]
async fn public_key() -> Result<PublicKeyReply, String> {
    let request = ECDSAPublicKey {
        canister_id: None,
        derivation_path: vec![],
        key_id: EcdsaKeyIds::TestKeyLocalDevelopment.to_key_id(),
    };

    let (res,): (ECDSAPublicKeyReply,) =
        ic_cdk::call(mgmt_canister_id(), "ecdsa_public_key", (request,))
            .await
            .map_err(|e| format!("ecdsa_public_key failed {}", e.1))?;

    Ok(PublicKeyReply {
        public_key_hex: hex::encode(&res.public_key),
    })
}

#[update]
async fn sign(message: String) -> Result<SignatureReply, String> {
    let request = SignWithECDSA {
        message_hash: sha256(&message).to_vec(),
        derivation_path: vec![],
        key_id: EcdsaKeyIds::TestKeyLocalDevelopment.to_key_id(),
    };

    let (response,): (SignWithECDSAReply,) = ic_cdk::api::call::call_with_payment(
        mgmt_canister_id(),
        "sign_with_ecdsa",
        (request,),
        25_000_000_000,
    )
    .await
    .map_err(|e| format!("sign_with_ecdsa failed {}", e.1))?;

    Ok(SignatureReply {
        signature_hex: hex::encode(&response.signature),
    })
}

#[query]
async fn verify(
    signature_hex: String,
    message: String,
    public_key_hex: String,
) -> Result<SignatureVerificationReply, String> {
    let signature_bytes = hex::decode(&signature_hex).expect("failed to hex-decode signature");
    let pubkey_bytes = hex::decode(&public_key_hex).expect("failed to hex-decode public key");
    let message_bytes = message.as_bytes();

    use k256::ecdsa::signature::Verifier;
    let signature = k256::ecdsa::Signature::try_from(signature_bytes.as_slice())
        .expect("failed to deserialize signature");
    let is_signature_valid= k256::ecdsa::VerifyingKey::from_sec1_bytes(&pubkey_bytes)
        .expect("failed to deserialize sec1 encoding into public key")
        .verify(message_bytes, &signature)
        .is_ok();

    Ok(SignatureVerificationReply{
        is_signature_valid
    })
}

fn verify_iner(message: String, signature_hex: String, public_key_hex: String) -> bool {
    let signature_bytes = match hex::decode(&signature_hex) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Failed to hex-decode signature: {}", e);
            return false;
        }
    };

    let pubkey_bytes = match hex::decode(&public_key_hex) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Failed to hex-decode public key: {}", e);
            return false;
        }
    };

    let message_bytes = message.as_bytes();

    use k256::ecdsa::signature::Verifier;
    let signature = match k256::ecdsa::Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(e) => {
            eprintln!("Failed to deserialize signature: {}", e);
            return false;
        }
    };

    let is_signature_valid = match k256::ecdsa::VerifyingKey::from_sec1_bytes(&pubkey_bytes) {
        Ok(verify_key) => verify_key.verify(message_bytes, &signature).is_ok(),
        Err(e) => {
            eprintln!("Failed to deserialize sec1 encoding into public key: {}", e);
            false
        }
    };

    is_signature_valid
}


fn mgmt_canister_id() -> CanisterId {
    CanisterId::from_str(&"aaaaa-aa").unwrap()
}

fn sha256(input: &String) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(input.as_bytes());
    hasher.finalize().into()
}

enum EcdsaKeyIds {
    #[allow(unused)]
    TestKeyLocalDevelopment,
    #[allow(unused)]
    TestKey1,
    #[allow(unused)]
    ProductionKey1,
}

impl EcdsaKeyIds {
    fn to_key_id(&self) -> EcdsaKeyId {
        EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: match self {
                Self::TestKeyLocalDevelopment => "dfx_test_key",
                Self::TestKey1 => "test_key_1",
                Self::ProductionKey1 => "key_1",
            }
            .to_string(),
        }
    }
}

// In the following, we register a custom getrandom implementation because
// otherwise getrandom (which is a dependency of k256) fails to compile.
// This is necessary because getrandom by default fails to compile for the
// wasm32-unknown-unknown target (which is required for deploying a canister).
// Our custom implementation always fails, which is sufficient here because
// we only use the k256 crate for verifying secp256k1 signatures, and such
// signature verification does not require any randomness.
getrandom::register_custom_getrandom!(always_fail);
pub fn always_fail(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}



#[ic_cdk::query]
fn greet(name: String) -> String {
    format!("Hello, {}!", name)
}



#[derive(Clone, Debug, Default, CandidType, Deserialize)]
struct MyData {
    pub key : String,
    pub value : String,
}

#[derive(Clone, Debug, Default, CandidType, Deserialize)]
struct MyDataWithSign {
    key: String,
    value: String,
    sign: String,
}

type PublicKey = String;
type User = (Principal, PublicKey);

// type ProfileStore = HashMap<Principal, HashMap<String, String>>;
type ProfileStore = HashMap<Principal, (HashMap<String, String>, String)>;
type Users = BTreeSet<User>;


static mut GLOBAL_CALLER_ID: Option<String> = None;
lazy_static! {
    static ref MY_GLOBAL_BOOL: bool = true;
}

thread_local! {
    static USERS: RefCell<Users> = RefCell::default();
    static PROFILE_STORE: RefCell<ProfileStore> = RefCell::default();
}

#[init]
fn init() {
    let user = (ic_cdk::api::caller(), "".to_string());
    USERS.with(|users| users.borrow_mut().insert(user));
}

fn is_user() -> Result<(), String> {
    let caller_principal = ic_cdk::api::caller();

    if USERS.with(|users| users.borrow().iter().any(|(principal, _)| principal == &caller_principal)) {
        Ok(())
    } else {
        if *MY_GLOBAL_BOOL {
            Ok(())
        } else {
            Err("Store can only be set by the owner of the asset canister.".to_string())
        }
    }
}



#[update(guard = "is_user")]
fn get_self() -> Option<String> {
    // 获取当前调用者的 Principal
    let caller_principal = ic_cdk::api::caller();

    // 将 Principal 转换为 String，并返回
    Some(caller_principal.to_string())
}


#[update(guard = "is_user")]
fn add_key(public_key: String) -> Option<String> {
    let caller_principal = ic_cdk::api::caller();
    let user = (caller_principal.clone(), public_key.clone());

    USERS.with(|users| {
        // Mutable access to USERS
        let mut users_borrow = users.borrow_mut();

        if let Some(existing_user) = users_borrow.iter().find(|(principal, _)| principal == &user.0) {
            // User already exists, check if public keys match
            if existing_user.1 == public_key {
                Some("User and public key already exist.".to_string())
            } else {
                Some("User exists, please use update_key method to update.".to_string())
            }
        } else {
            // User does not exist, insert new user
            users_borrow.insert(user);
            Some("User added.".to_string())
        }
    })
}


#[update]
fn update_key(new_key: String, sign: String) -> Option<String> {
    let caller_principal = ic_cdk::api::caller();
    let user = (caller_principal.clone(), new_key.clone());

    USERS.with(|users| {
        let mut users_borrow = users.borrow_mut();
        
        // Clone the BTreeSet to create a new one
        let mut new_users_set = users_borrow.clone();

        if let Some((existing_user, old_key)) = users_borrow.iter().find(|(principal, _)| principal == &user.0) {
            let result = verify_iner(new_key.clone(), sign.clone(), old_key.clone());
            if result {
                // Remove the existing user from the cloned set
                new_users_set.remove(&(existing_user.clone(), old_key.clone()));
                // Insert the new user
                new_users_set.insert(user);
                
                // Replace the original set with the modified set
                *users_borrow = new_users_set;

                Some("Update key ok!".to_string())
            } else {
                Some("Verify failed!".to_string())
                // Some(format!("Verify failed! new_key: {}, sign: {}, old_key: {}", new_key, sign, old_key))
            }
        } else {
            Some("User or key not exist.".to_string())
        }
    })
}



#[query(guard = "is_user")]
fn get_key() -> Option<String> {
    let caller_principal = ic_cdk::api::caller();

    USERS.with(|users| {
        let borrowed_users = users.borrow();
        let user_option = borrowed_users.iter().find(|(principal, _)| principal == &caller_principal);

        user_option.map(|(_, public_key)| public_key.clone())
    })
}


// 设置全局身份
fn set_global_caller_id(caller_id: &str) {
    unsafe {
        GLOBAL_CALLER_ID = Some(caller_id.to_string());
    }
}


#[update(guard = "is_user")]
fn add(key: String, value: String, sign: String) -> Option<String> {
    let principal_id = ic_cdk::api::caller();
    let public_key = "026bbf4ab2ebddf5cf11d1b76d792d3ae66c7576c5c4757a91524cbbfeb9b4b8b3".to_string();

    //获取公钥
    let pk = USERS.with(|users| {
        let borrowed_users = users.borrow();
        borrowed_users.iter().find(|(principal, _)| principal == &principal_id)
            .map(|(_, public_key)| public_key.clone())
    });
    if let Some(ref found_key) = pk {
        println!("Found key: {}", found_key);
    } else {
        return Some("Public key not found.".to_string());
    }
    let pk = pk.unwrap_or_else(|| String::new());

    //验签
    let result = verify_iner(value.clone(), sign.clone(), pk.clone());
    if !result {
        return Some("Verify failed!".to_string())
    }

    PROFILE_STORE.with(|profile_store| {
        let mut profile_store_borrow = profile_store.borrow_mut();
        let profiles_map = profile_store_borrow.entry(principal_id).or_insert_with(|| (HashMap::new(), sign.clone()));

        // 检查是否已经存在该数据
        if profiles_map.0.contains_key(&key) {
            return Some("Data already exists.".to_string()); // 数据已存在，返回特定数据
        }

        // 数据不存在，执行插入操作
        profiles_map.0.insert(key, value);
        let total_size: usize = profile_store_borrow
            .values()
            .flat_map(|(map, _)| map.iter())
            .map(|(key, value)| key.len() + value.len())
            .sum();
        return Some(format!("Ok, total size is {}", total_size));
        // return Some(total_size.to_string());
    })

}

#[query(guard = "is_user")]
fn get_amount() -> Option<String> {
    let total_size: usize = PROFILE_STORE.with(|profile_store| {
        let profile_store_borrow = profile_store.borrow();
        profile_store_borrow
            .values()
            .flat_map(|(map, _)| map.iter())
            .map(|(key, value)| key.len() + value.len())
            .sum()
    });

    Some(format!("Total size is {}", total_size))
}


#[update(guard = "is_user")]
fn update(key: String, value: String) -> Option<String> {
    let principal_id = ic_cdk::api::caller();
    PROFILE_STORE.with(|profile_store| {
        let mut profile_store_borrow = profile_store.borrow_mut();
        if let Some((profiles_map, _)) = profile_store_borrow.get_mut(&principal_id) {
            if let Some(existing_value) = profiles_map.get_mut(&key) {
                *existing_value = value;
                Some("Ok".to_string()) // Overwrite the existing element
            } else {
                Some("No matching element".to_string()) // No matching element found
            }
        } else {
            Some("No matching element".to_string()) // No matching element found
        }
    })
}

#[update(guard = "is_user")]
fn remove(key: String) -> Option<String> {
    let principal_id = ic_cdk::api::caller();
    PROFILE_STORE.with(|profile_store| {
        let mut profile_store_borrow = profile_store.borrow_mut();
        if let Some((profiles_map, _)) = profile_store_borrow.get_mut(&principal_id) {
            if profiles_map.remove(&key).is_some() {
                Some("Ok".to_string())
            } else {
                Some("No matching element".to_string()) // No matching element found
            }
        } else {
            Some("No matching element".to_string()) // No matching element found
        }
    })
}

#[query(manual_reply = true)]
fn get_all() -> ManualReply<Option<Vec<MyDataWithSign>>> {
    let principal_id = ic_cdk::api::caller();
    PROFILE_STORE.with(|profile_store| {
        if let Some((profiles_map, sign)) = profile_store.borrow().get(&principal_id) {
            let profiles: Vec<MyDataWithSign> = profiles_map
                .iter()
                .map(|(key, value)| MyDataWithSign {
                    key: key.clone(),
                    value: value.clone(),
                    sign: sign.clone(),
                })
                .collect();
            ManualReply::one(Some(profiles))
        } else {
            ManualReply::one(None::<Vec<MyDataWithSign>>)
        }
    })
}


#[query]
fn get(name: String) -> Option<(String)> {
    PROFILE_STORE.with(|profile_store| {
        let principal_id = ic_cdk::api::caller();
        if let Some((profiles_map, sign)) = profile_store.borrow().get(&principal_id).cloned() {
            if let Some(profile_entry) = profiles_map.get(&name) {
                return Some((profile_entry.clone()));
            }
        }
        None // If no relevant data is found, return None
    })
}



// 使用 `PROFILE_STORE` 查询指定 ID 的数据，并返回 ManualReply<Option<Vec<MyDataWithSign>>>
#[query(manual_reply = true)]
fn get_by_id(id: String) -> ManualReply<Option<Vec<MyDataWithSign>>> {
    let id_principal = Principal::from_text(&id).expect("Failed to parse the id as Principal.");
    PROFILE_STORE.with(|profile_store| {
        if let Some((profiles_map, sign)) = profile_store.borrow().get(&id_principal) {
            let profiles: Vec<MyDataWithSign> = profiles_map
                .iter()
                .map(|(key, value)| MyDataWithSign {
                    key: key.clone(),
                    value: value.clone(),
                    sign: sign.clone(),
                })
                .collect();
            ManualReply::one(Some(profiles))
        } else {
            ManualReply::one(None::<Vec<MyDataWithSign>>)
        }
    })
}