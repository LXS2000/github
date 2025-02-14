use rand::rngs::OsRng;
use rand::{thread_rng, Rng};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, Ia5String, IsCa, KeyIdMethod,
    KeyPair, SanType,
};
use rcgen::{Certificate, KeyUsagePurpose};
use rsa::{pkcs8::EncodePrivateKey, RsaPrivateKey};
use std::fs;
use std::io::{BufReader, Read};

use std::str::FromStr;
use std::time::Duration;
use time::ext::NumericalDuration;
use time::OffsetDateTime;

///自签名生成一个CA证书
pub fn generate_self_signed_cert_with_privkey() -> Result<Certificate, Box<dyn std::error::Error>> {
    let mut params = CertificateParams::default();
    // Add the SAN we want to test the parsing for
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.not_before = OffsetDateTime::now_local().unwrap(); // 当前时间
    
    params.not_after = params.not_before.checked_add(365.days()).unwrap(); // 当前时间 + 365 , 即有效期一年
    params.distinguished_name = DistinguishedName::new();

    params.subject_alt_names = vec![SanType::DnsName(Ia5String::from_str("*").unwrap())];
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
    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits)?;
    let private_key_der = private_key.to_pkcs8_der()?;
    let key_pair = rcgen::KeyPair::try_from(private_key_der.as_bytes()).unwrap();
    let cert = params.self_signed(&key_pair)?;
    Ok(cert)
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
    let params = CertificateParams::from_ca_cert_pem(&cert_string)?;
    let key_pair = KeyPair::from_pem(&key_pair_sting)?;
    let cert = params.self_signed(&key_pair)?;
    Ok(cert)
}

pub fn ca_gen(out_dir: &str) {
    let cert = generate_self_signed_cert_with_privkey().unwrap();
    std::fs::create_dir_all(out_dir).unwrap();
    let key_path = format!("{out_dir}/ca.key");
    let cer_path = format!("{out_dir}/ca.cer");
    std::fs::write(&key_path, cert.key_identifier()).unwrap();
    std::fs::write(&cer_path, cert.pem()).unwrap();

    println!("private key output '{key_path}'");
    println!("certificate output '{key_path}'");
}

#[test]
pub fn gen() {
    ca_gen("./ca")
}
