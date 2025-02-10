use rand::rngs::OsRng;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyIdMethod, KeyPair,
    SanType,
};
use rcgen::{Certificate, KeyUsagePurpose};
use rsa::{pkcs8::EncodePrivateKey, RsaPrivateKey};
use std::fs;
use std::io::{BufReader, Read};

use std::time::Duration;
use time::ext::NumericalDuration;
use time::OffsetDateTime;

///自签名生成一个CA证书
pub fn generate_self_signed_cert_with_privkey() -> Result<(Certificate, String, String), Box<dyn std::error::Error>> {
    let mut params = CertificateParams::default();
    // Add the SAN we want to test the parsing for

    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.not_before = OffsetDateTime::now_local().unwrap(); // 当前时间
    params.not_after = params.not_before.checked_add(365.days()).unwrap(); // 当前时间 + 365 , 即有效期一年
    params.distinguished_name = DistinguishedName::new();

    params.subject_alt_names = vec![SanType::DnsName("*".into())];
    params
        .distinguished_name
        .push(DnType::CommonName, "CthulhuRs cert");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "CthulhuRs");
    params
        .distinguished_name
        .push(DnType::CountryName, "imagination");
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);

    params.alg = &rcgen::PKCS_RSA_SHA256;
    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits)?;
    let private_key_der = private_key.to_pkcs8_der()?;
    let key_pair = rcgen::KeyPair::try_from(private_key_der.as_bytes()).unwrap();
    params.key_pair = Some(key_pair);
    let cert = Certificate::from_params(params)?;
    let pem_serialized = cert.serialize_pem()?;

    let key_serialized = cert.serialize_private_key_pem();
    Ok((cert, pem_serialized, key_serialized))
}
#[allow(unused)]
///自签名使用CA证书给其他域名生成证书
pub fn signed_cert_with_ca(
    root_cert: &Certificate,
    domin: &str,
    ip: Option<[u8; 4]>,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let mut params = CertificateParams::default();

    params.alg = &rcgen::PKCS_ECDSA_P384_SHA384;
    params.key_pair = Some(KeyPair::generate(&rcgen::PKCS_ECDSA_P384_SHA384)?);
    params.key_identifier_method = KeyIdMethod::Sha384;
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, domin);
    params.distinguished_name = dn;

    params.subject_alt_names = vec![SanType::DnsName(domin.into())];
    if let Some(v) = ip {
        let ipv4 = std::net::Ipv4Addr::from(v);
        let ip_san = SanType::IpAddress(std::net::IpAddr::V4(ipv4));
        params.subject_alt_names.push(ip_san);
    }

    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + Duration::from_secs(365 * 60 * 60 * 24 * 10);

    let cert = Certificate::from_params(params)?;

    let pem_serialized = cert.serialize_pem_with_signer(root_cert)?;

    let key_serialized = cert.serialize_private_key_pem();
    Ok((pem_serialized, key_serialized))
}
#[allow(unused)]
pub fn gen_client(root_cert: &Certificate) -> Result<String, rcgen::RcgenError> {
    let mut params = CertificateParams::default();

    params.alg = &rcgen::PKCS_ECDSA_P384_SHA384;
    params.key_pair = Some(KeyPair::generate(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap());
    params.key_identifier_method = KeyIdMethod::Sha384;

    let dn = DistinguishedName::new();
    params.distinguished_name = dn;

    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + Duration::from_secs(365 * 60 * 60 * 24 * 10);

    let cert = Certificate::from_params(params)?;

    let cert_signed = cert.serialize_pem_with_signer(&root_cert)?;
    Ok(cert_signed)
}
#[allow(unused)]
pub fn read_cert(cert: &str, key: &str) -> Result<Certificate, Box<dyn std::error::Error>> {
    // Open the PEM file containing both the certificate and private key .pem
    let pem_cert_file = fs::File::open(cert)?;
    let mut pem_cert_reader = BufReader::new(pem_cert_file);

    let mut cert_string = String::new();
    pem_cert_reader.read_to_string(&mut cert_string)?;
    //.key
    let pem_key_file = fs::File::open(key)?;
    let mut pem_key_reader = BufReader::new(pem_key_file);

    let mut key_pair_sting = String::new();
    pem_key_reader.read_to_string(&mut key_pair_sting)?;

    let ca = from_ca_cert_pem(cert_string.as_str(), key_pair_sting.as_str())?;
    Ok(ca)
}
#[allow(unused)]
pub fn from_ca_cert_pem(pem: &str, key: &str) -> Result<Certificate, rcgen::RcgenError> {
    let key_pair = KeyPair::from_pem(key)?;
    // Parse the PEM file and create a new CertificateParams object
    let ca_cert_params = CertificateParams::from_ca_cert_pem(pem, key_pair)?;
    // Create a new certificate using the CertificateParams object
    Certificate::from_params(ca_cert_params)
}

pub fn ca_gen(out_dir: &str) {
    let (_, pem, key) = generate_self_signed_cert_with_privkey().unwrap();
    std::fs::create_dir_all(out_dir).unwrap();
    let key_path = format!("{out_dir}/cthulhu.key");
    let cer_path = format!("{out_dir}/cthulhu.cer");
    std::fs::write(&key_path, key.as_bytes()).unwrap();
    std::fs::write(&cer_path, pem.as_bytes()).unwrap();

    println!("private key output '{key_path}'");
    println!("certificate output '{key_path}'");
}


#[test]
pub fn gen() {
    ca_gen("./ca")
}