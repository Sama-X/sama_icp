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


type ProfileStore = HashMap<Principal, HashMap<String, String>>;
type Users = BTreeSet<Principal>;

#[derive(Clone, Debug, Default, CandidType, Deserialize)]
struct MyData {
    pub key : String,
    pub value : String,
}



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
    USERS.with(|users| users.borrow_mut().insert(ic_cdk::api::caller()));
}

fn is_user() -> Result<(), String> {
    if USERS.with(|users| users.borrow().contains(&ic_cdk::api::caller())) {
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
fn add_user(principal: Principal) {
    USERS.with(|users| users.borrow_mut().insert(principal));
}

// 设置全局身份
fn set_global_caller_id(caller_id: &str) {
    unsafe {
        GLOBAL_CALLER_ID = Some(caller_id.to_string());
    }
}

#[query]
fn get(name: String) -> Option<String> {
    PROFILE_STORE.with(|profile_store| {
        let principal_id = ic_cdk::api::caller();
        if let Some(profiles_map) = profile_store.borrow().get(&principal_id) {
            if let Some(profile_entry) = profiles_map.get(&name) {
                return Some(profile_entry.clone());
            }
        }
        None // 如果找不到相关数据则返回 None
    })
}


#[update(guard = "is_user")]
fn add(key: String, value: String) -> Option<String> {
    let principal_id = ic_cdk::api::caller();
    PROFILE_STORE.with(|profile_store| {
        let mut profile_store_borrow = profile_store.borrow_mut();
        let profiles_map = profile_store_borrow.entry(principal_id).or_insert_with(HashMap::new);

        // 检查是否已经存在该数据
        if profiles_map.contains_key(&key) {
            return Some("Data already exists.".to_string()); // 数据已存在，返回特定数据
        }

        // 数据不存在，执行插入操作
        profiles_map.insert(key, value);
        return Some("Ok.".to_string()); // 数据已存在，返回特定数据
    })
}

#[update(guard = "is_user")]
fn update(key: String, value: String) -> Option<String> {
    let principal_id = ic_cdk::api::caller();
    PROFILE_STORE.with(|profile_store| {
        let mut profile_store_borrow = profile_store.borrow_mut();
        if let Some(profiles_map) = profile_store_borrow.get_mut(&principal_id) {
            if let Some(existing_value) = profiles_map.get_mut(&key) {
                *existing_value = value; 
                Some("Ok".to_string()) // 覆盖现有元素
            } else {
                Some("No matching element".to_string()) // 未找到匹配的元素提示
            }
        } else {
            Some("No matching element".to_string()) // 未找到匹配的元素提示
        }
    })
}

#[update(guard = "is_user")]
fn remove(key: String) -> Option<String> {
    let principal_id = ic_cdk::api::caller();
    PROFILE_STORE.with(|profile_store| {
        let mut profile_store_borrow = profile_store.borrow_mut();
        if let Some(profiles_map) = profile_store_borrow.get_mut(&principal_id) {
            if let Some(existing_value) = profiles_map.remove(&key) {
                Some("Ok".to_string())
            } else {
                Some("No matching element".to_string()) // 未找到匹配的元素提示
            }
        } else {
            Some("No matching element".to_string()) // 未找到匹配的元素提示
        }
    })
}

#[query(manual_reply = true)]
fn get_all() -> ManualReply<Option<Vec<MyData>>> {
    let principal_id = ic_cdk::api::caller();
    PROFILE_STORE.with(|profile_store| {
        if let Some(profiles_map) = profile_store.borrow().get(&principal_id) {
            let profiles: Vec<MyData> = profiles_map
                .iter()
                .map(|(key, value)| MyData { key: key.clone(), value: value.clone() })
                .collect();
            ManualReply::one(Some(profiles))
        } else {
            ManualReply::one(None::<Vec<MyData>>)
        }
    })
}

// 使用 `PROFILE_STORE` 查询指定 ID 的数据，并返回 ManualReply<Option<Vec<MyData>>>
#[query(manual_reply = true)]
fn get_by_id(id: String) -> ManualReply<Option<Vec<MyData>>> {
    let id_principal = Principal::from_text(&id).expect("Failed to parse the id as Principal.");
    PROFILE_STORE.with(|profile_store| {
        if let Some(profiles_map) = profile_store.borrow().get(&id_principal) {
            let profiles: Vec<MyData> = profiles_map
                .iter()
                .map(|(key, value)| MyData { key: key.clone(), value: value.clone() })
                .collect();
            ManualReply::one(Some(profiles))
        } else {
            ManualReply::one(None::<Vec<MyData>>)
        }
    })
}

