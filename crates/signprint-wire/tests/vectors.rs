//! Cross-language test vectors. The TypeScript client runs against the same
//! file, so any change to canonicalisation or the signature base shows up as a
//! diff here first.
//!
//! Regenerate with `SIGNPRINT_BLESS=1 cargo test -p signprint-wire --test vectors`.

use std::path::PathBuf;

use p256::elliptic_curve::sec1::ToSec1Point;
use serde_json::{Value, json};
use signprint_wire::{b64, digest, nonce::RequestNonce, sig};

const MAC_KEY: [u8; 32] = [0x42; 32];
const CREATED: u64 = 1_760_716_800;
const KEYID: &str = "AgEBAAEAAQIDBAUGBwgJCgsMDQ4P";

struct Case {
    name: &'static str,
    method: &'static str,
    authority: &'static str,
    https: bool,
    path: &'static str,
    query: Option<&'static str>,
    body: Option<&'static [u8]>,
    nonce: &'static str,
}

const CASES: &[Case] = &[
    Case {
        name: "get without query",
        method: "GET",
        authority: "shop.example",
        https: true,
        path: "/api/items",
        query: None,
        body: None,
        nonce: "00000001.0",
    },
    Case {
        name: "get with empty query",
        method: "GET",
        authority: "shop.example",
        https: true,
        path: "/api/items",
        query: Some(""),
        body: None,
        nonce: "00000001.1",
    },
    Case {
        name: "uppercase host, default port, encoded path",
        method: "GET",
        authority: "Shop.EXAMPLE:443",
        https: true,
        path: "/api/a%2Fb/%C3%A9",
        query: Some("q=caf%C3%A9&page=2"),
        body: None,
        nonce: "9f3a1c07.17",
    },
    Case {
        name: "non-default port",
        method: "GET",
        authority: "localhost:8443",
        https: true,
        path: "/",
        query: None,
        body: None,
        nonce: "deadbeef.123456789",
    },
    Case {
        name: "empty path",
        method: "GET",
        authority: "shop.example",
        https: true,
        path: "",
        query: None,
        body: None,
        nonce: "00000002.5",
    },
    Case {
        name: "post json",
        method: "POST",
        authority: "shop.example",
        https: true,
        path: "/api/cart",
        query: Some("item=42"),
        body: Some(br#"{"qty":1}"#),
        nonce: "9f3a1c07.18",
    },
    Case {
        name: "ipv6 authority",
        method: "PUT",
        authority: "[2001:DB8::1]:443",
        https: true,
        path: "/v1/thing",
        query: None,
        body: Some(b"x"),
        nonce: "0000000a.99",
    },
];

fn signature_vectors() -> Vec<Value> {
    CASES
        .iter()
        .map(|c| {
            let authority = sig::canonical_authority(c.authority, c.https).unwrap();
            let query = sig::canonical_query(c.query);
            let content_digest = c.body.map(digest::content_digest);
            let params = sig::Params {
                created: CREATED,
                keyid: KEYID.into(),
                nonce: RequestNonce::parse(c.nonce).unwrap(),
            };
            let components = sig::Components {
                method: c.method,
                authority: &authority,
                path: sig::canonical_path(c.path),
                query: &query,
                content_digest: content_digest.as_deref(),
            };
            let base = sig::signature_base(&components, &params);
            let mac = sig::mac(&MAC_KEY, &base);
            let (input, signature) = sig::header_values(&params, c.body.is_some(), &mac);
            json!({
                "name": c.name,
                "input": {
                    "method": c.method,
                    "authority": c.authority,
                    "https": c.https,
                    "path": c.path,
                    "query": c.query,
                    "body_b64": c.body.map(b64::encode_std),
                    "created": CREATED,
                    "keyid": KEYID,
                    "nonce": c.nonce,
                },
                "expect": {
                    "authority": authority,
                    "path": sig::canonical_path(c.path),
                    "query": query,
                    "content_digest": content_digest,
                    "signature_base": base,
                    "signature_input": input,
                    "signature": signature,
                },
            })
        })
        .collect()
}

/// ECDH -> HMAC key, the way the browser derives it with
/// `deriveKey({name: "ECDH"}, ..., {name: "HMAC", hash: "SHA-256", length: 256})`.
fn ecdh_vectors() -> Vec<Value> {
    let pairs: [([u8; 32], [u8; 32]); 2] = [([0x11; 32], [0x22; 32]), ([0x5a; 32], [0xc3; 32])];
    pairs
        .iter()
        .map(|(client_d, server_d)| {
            let client = p256::SecretKey::from_slice(client_d).unwrap();
            let server = p256::SecretKey::from_slice(server_d).unwrap();
            let client_pub = client.public_key().to_sec1_point(false);
            let server_pub = server.public_key().to_sec1_point(false);
            let shared = p256::ecdh::diffie_hellman(
                server.to_nonzero_scalar(),
                client.public_key().as_affine(),
            );
            let mac_key: [u8; 32] = shared.raw_secret_bytes().as_slice().try_into().unwrap();
            let base = "\"@method\": GET\n\"@signature-params\": ()";
            json!({
                "client_jwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "d": b64::encode_url(client_d),
                    "x": b64::encode_url(client_pub.x().unwrap()),
                    "y": b64::encode_url(client_pub.y().unwrap()),
                },
                "client_public_raw": b64::encode_url(client_pub.as_bytes()),
                "server_public_raw": b64::encode_url(server_pub.as_bytes()),
                "mac_key_hex": hex(&mac_key),
                "base": base,
                "mac_b64": b64::encode_std(&sig::mac(&mac_key, base)),
            })
        })
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn generate() -> Value {
    json!({
        "comment": "generated by crates/signprint-wire/tests/vectors.rs, do not edit",
        "mac_key_hex": hex(&MAC_KEY),
        "signatures": signature_vectors(),
        "ecdh": ecdh_vectors(),
        "nonces": {
            "valid": ["00000000.0", "9f3a1c07.17", "ffffffff.18446744073709551615"],
            "invalid": ["9f3a1c07.017", "9F3A1C07.17", "9f3a1c7.17", "9f3a1c07.", "9f3a1c07.18446744073709551616"],
        },
    })
}

#[test]
fn vectors_are_current() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testvectors/wire.json");
    let fresh = serde_json::to_string_pretty(&generate()).unwrap() + "\n";

    if std::env::var_os("SIGNPRINT_BLESS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &fresh).unwrap();
        return;
    }
    let on_disk = std::fs::read_to_string(&path)
        .expect("testvectors/wire.json missing; run with SIGNPRINT_BLESS=1")
        .replace("\r\n", "\n");
    assert!(
        on_disk == fresh,
        "testvectors/wire.json is stale; rerun with SIGNPRINT_BLESS=1 and review the diff"
    );
}

#[test]
fn every_vector_parses_back() {
    for v in signature_vectors() {
        let e = &v["expect"];
        let got = sig::parse(
            e["signature_input"].as_str().unwrap(),
            e["signature"].as_str().unwrap(),
        )
        .unwrap();
        let base = e["signature_base"].as_str().unwrap();
        assert!(sig::verify_mac(&MAC_KEY, base, &got.mac), "{}", v["name"]);
    }
}
