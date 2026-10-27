//! AWS Signature Version 4, to re-sign a request a masked AWS credential signed.
//!
//! A masked AWS pair hands the agent a fake access key id and a fake secret, so
//! the signature the client computes is an HMAC over the fake secret: swapping
//! the key id in the credential scope cannot repair it. On a terminated host the
//! broker re-signs: it keeps the client's credential scope, signed-header set and
//! `x-amz-date`, and computes the signature with the real secret over the request
//! as it goes upstream.
//!
//! Ported from sandbox-runtime's `aws-sigv4.ts` (Apache-2.0, see NOTICE), which
//! was validated against the aws-sig-v4-test-suite; the test below is the
//! signing example from AWS's documentation. Only header-signed requests are
//! re-signed. A streaming (aws-chunked) body, a presigned URL and SigV4a carry
//! signatures the broker cannot reproduce, and are refused (mitm.rs).

use ring::{digest, hmac};

pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// `AWS4-HMAC-SHA256 Credential=<akid>/<date>/<region>/<service>/aws4_request, SignedHeaders=…, Signature=…`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorization {
    pub access_key_id: String,
    pub date: String,
    pub region: String,
    pub service: String,
    pub signed_headers: Vec<String>,
}

/// Parse an Authorization value; None when it is not a complete SigV4 one.
pub fn parse_authorization(auth: &str) -> Option<Authorization> {
    let rest = auth.strip_prefix(ALGORITHM)?;
    let field = |name: &str| -> Option<String> {
        let at = rest.find(&format!("{name}="))? + name.len() + 1;
        let v: String = rest[at..].chars().take_while(|c| *c != ',' && !c.is_whitespace()).collect();
        (!v.is_empty()).then_some(v)
    };
    let cred = field("Credential")?;
    let signed = field("SignedHeaders")?;
    field("Signature").filter(|s| s.chars().all(|c| c.is_ascii_hexdigit()))?;
    let parts: Vec<&str> = cred.split('/').collect();
    if parts.len() != 5 || parts[4] != "aws4_request" || parts[..4].iter().any(|p| p.is_empty()) {
        return None;
    }
    Some(Authorization {
        access_key_id: parts[0].to_string(),
        date: parts[1].to_string(),
        region: parts[2].to_string(),
        service: parts[3].to_string(),
        signed_headers: signed.split(';').map(|h| h.to_ascii_lowercase()).collect(),
    })
}

/// The access key id in a request's Authorization (any SigV4 algorithm) or in a
/// presigned query's `X-Amz-Credential`: what decides whether it is ours to re-sign.
pub fn credential_access_key_id(auth: Option<&str>, target: &str) -> Option<String> {
    if let Some(a) = auth {
        if let Some(at) = a.find("Credential=") {
            let v: String = a[at + 11..].chars().take_while(|c| *c != '/' && *c != ',' && !c.is_whitespace()).collect();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    let query = target.split_once('?')?.1;
    for kv in query.split('&') {
        if let Some(v) = kv.strip_prefix("X-Amz-Credential=") {
            let v = percent_decode(v);
            return v.split('/').next().filter(|s| !s.is_empty()).map(str::to_string);
        }
    }
    None
}

/// Strict RFC 3986 encoding: everything but `A-Za-z0-9-_.~` is encoded.
pub fn uri_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Canonical URI: S3's path as sent; any other service's path with its dot
/// segments resolved and encoded once more on top of its wire encoding.
pub fn canonical_uri(raw_path: &str, service: &str) -> String {
    if raw_path.is_empty() {
        return "/".into();
    }
    if service == "s3" {
        return raw_path.into();
    }
    let mut segs: Vec<&str> = Vec::new();
    for seg in raw_path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                segs.pop();
            }
            s => segs.push(s),
        }
    }
    let trailing = if !segs.is_empty() && raw_path.ends_with('/') { "/" } else { "" };
    uri_encode(&format!("/{}{trailing}", segs.join("/"))).replace("%2F", "/")
}

/// Canonical query: each key and value decoded, strictly re-encoded, sorted.
pub fn canonical_query(raw: &str) -> String {
    let mut pairs: Vec<(String, String)> = raw
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (uri_encode(&percent_decode(k)), uri_encode(&percent_decode(v)))
        })
        .collect();
    pairs.sort();
    pairs.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&")
}

fn trimall(v: &str) -> String {
    v.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, data).as_ref())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hmac_sha256(key: &[u8], data: &str) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data.as_bytes()).as_ref().to_vec()
}

/// The canonical request. `headers` are the request's as they go upstream
/// (lower-case names); a signed header that is missing is an error, since a
/// signature over a value the service never sees would only fail there.
pub fn canonical_request(
    method: &str,
    target: &str,
    auth: &Authorization,
    headers: &[(String, String)],
    payload_hash: &str,
) -> Result<String, String> {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut names = auth.signed_headers.clone();
    names.sort();
    let mut lines = String::new();
    for n in &names {
        let values: Vec<String> = headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| trimall(v)).collect();
        if values.is_empty() {
            return Err(format!("signed header {n:?} is missing from the request"));
        }
        lines.push_str(&format!("{n}:{}\n", values.join(",")));
    }
    Ok([
        method.to_ascii_uppercase(),
        canonical_uri(path, &auth.service),
        canonical_query(query),
        lines,
        names.join(";"),
        payload_hash.to_string(),
    ]
    .join("\n"))
}

/// The Authorization value for the request, signed with the real key.
pub fn sign(
    canonical: &str,
    amz_date: &str,
    auth: &Authorization,
    real_access_key_id: &str,
    real_secret: &str,
) -> String {
    let scope = format!("{}/{}/{}/aws4_request", auth.date, auth.region, auth.service);
    let to_sign = format!("{ALGORITHM}\n{amz_date}\n{scope}\n{}", sha256_hex(canonical.as_bytes()));
    let k = hmac_sha256(format!("AWS4{real_secret}").as_bytes(), &auth.date);
    let k = hmac_sha256(&k, &auth.region);
    let k = hmac_sha256(&k, &auth.service);
    let k = hmac_sha256(&k, "aws4_request");
    let sig = hex(&hmac_sha256(&k, &to_sign));
    let mut names = auth.signed_headers.clone();
    names.sort();
    format!("{ALGORITHM} Credential={real_access_key_id}/{scope}, SignedHeaders={}, Signature={sig}", names.join(";"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AWS's documented example: IAM ListUsers, 2015-08-30.
    #[test]
    fn the_documented_example_signs_to_the_documented_signature() {
        let auth = parse_authorization(
            "AWS4-HMAC-SHA256 Credential=AKIDFAKE/20150830/us-east-1/iam/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date, Signature=00ff",
        )
        .unwrap();
        let headers = vec![
            ("content-type".to_string(), "application/x-www-form-urlencoded; charset=utf-8".to_string()),
            ("host".to_string(), "iam.amazonaws.com".to_string()),
            ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
        ];
        let c = canonical_request("GET", "/?Action=ListUsers&Version=2010-05-08", &auth, &headers, &sha256_hex(b"")).unwrap();
        assert_eq!(sha256_hex(c.as_bytes()), "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59");
        let a = sign(&c, "20150830T123600Z", &auth, "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
        assert!(a.ends_with("Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"), "{a}");
        assert!(a.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date"));
    }

    #[test]
    fn uri_and_query_are_canonical() {
        assert_eq!(canonical_uri("/a/./b/../c%20d", "iam"), "/a/c%2520d");
        assert_eq!(canonical_uri("/bucket/a/../b", "s3"), "/bucket/a/../b");
        assert_eq!(canonical_uri("", "iam"), "/");
        assert_eq!(canonical_query("b=2&a=1&a=0&c"), "a=0&a=1&b=2&c=");
        assert_eq!(canonical_query("k=a%20b&k2=a+b"), "k=a%20b&k2=a%2Bb");
    }

    #[test]
    fn the_access_key_id_comes_from_the_header_or_a_presigned_query() {
        assert_eq!(credential_access_key_id(Some("AWS4-HMAC-SHA256 Credential=AK1/20150830/x/y/aws4_request, SignedHeaders=host, Signature=ab"), "/").as_deref(), Some("AK1"));
        assert_eq!(credential_access_key_id(None, "/o?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AK2%2F20150830%2Fx%2Fs3%2Faws4_request").as_deref(), Some("AK2"));
        assert_eq!(credential_access_key_id(None, "/o?a=b"), None);
        assert!(parse_authorization("AWS4-HMAC-SHA256 Credential=AK/d/r/s/aws4_request, SignedHeaders=host").is_none());
    }
}
