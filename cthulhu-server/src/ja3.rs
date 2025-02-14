use rand::{rngs::StdRng, seq::SliceRandom};

use rustls::{ALL_KX_GROUPS, DEFAULT_CIPHER_SUITES};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, DEFAULT_VERSIONS};

// #[allow(unused)]
// fn parse<T: From<u16>>(ja3: &str) -> Vec<T> {
//     let splits: Vec<&str> = ja3.splitn(5, ",").collect();
//     let boxed: Box<[&str; 5]> = splits
//         .into_boxed_slice()
//         .try_into()
//         .expect("Expected a array of length 5");
//     let [version, ciphers, extensions, groups, format] = *boxed;
//     let version = version.parse::<u16>().unwrap();
//     let version = ProtocolVersion::from(version);
//     let items = items.split("-");
//     items
//         .map(|suite| suite.parse::<u16>().unwrap())
//         .map(|v| T::from(v))
//         .collect::<Vec<T>>()
// }
// fn parse_items_u16<T: From<u16>>(items: &str) -> Vec<T> {
//     let items = items.split("-");
//     items
//         .map(|item| item.parse::<u16>().unwrap())
//         .map(|v| T::from(v))
//         .collect::<Vec<T>>()
// }
// fn parse_items_u8<T: From<u8>>(items: &str) -> Vec<T> {
//     let items = items.split("-");
//     items
//         .map(|item| item.parse::<u8>().unwrap())
//         .map(|v| T::from(v))
//         .collect::<Vec<T>>()
// }
// fn parse_ja3<T: From<u16>>(ja3: &str) -> Vec<T> {
//     let splits: Vec<&str> = ja3.splitn(5, ",").collect();
//     let boxed: Box<[&str; 5]> = splits
//         .into_boxed_slice()
//         .try_into()
//         .expect("Expected a array of length 5");
//     let [versions, ciphers, extensions, groups, format] = *boxed;
//     let versions = parse_items_u16::<ProtocolVersion>(versions);

//     let ciphers = parse_items_u16::<CipherSuite>(ciphers);
//     let extensions = parse_items_u16::<ExtensionType>(extensions);

//     let groups = parse_items_u16::<NamedGroup>(groups);
//     let format = parse_items_u8::<ECPointFormat>(format);

//     let mut exts = vec![
//         ClientExtension::SupportedVersions(supported_versions),
//         ClientExtension::EcPointFormats(ECPointFormat::SUPPORTED.to_vec()),
//         ClientExtension::NamedGroups(
//             config
//                 .provider
//                 .kx_groups
//                 .iter()
//                 .map(|skxg| skxg.name())
//                 .collect(),
//         ),
//         ClientExtension::SignatureAlgorithms(
//             config
//                 .verifier
//                 .supported_verify_schemes(),
//         ),
//         ClientExtension::ExtendedMasterSecretRequest,
//         ClientExtension::CertificateStatusRequest(CertificateStatusRequest::build_ocsp()),
//     ];

//     if let (ServerName::DnsName(dns), true) = (&input.server_name, config.enable_sni) {
//         // We only want to send the SNI extension if the server name contains a DNS name.
//         exts.push(ClientExtension::make_sni(dns));
//     }

//     if let Some(key_share) = &key_share {
//         debug_assert!(support_tls13);
//         let key_share = KeyShareEntry::new(key_share.group(), key_share.pub_key());
//         exts.push(ClientExtension::KeyShare(vec![key_share]));
//     }

//     if let Some(cookie) = retryreq.and_then(HelloRetryRequest::get_cookie) {
//         exts.push(ClientExtension::Cookie(cookie.clone()));
//     }

//     if support_tls13 {
//         // We could support PSK_KE here too. Such connections don't
//         // have forward secrecy, and are similar to TLS1.2 resumption.
//         let psk_modes = vec![PSKKeyExchangeMode::PSK_DHE_KE];
//         exts.push(ClientExtension::PresharedKeyModes(psk_modes));
//     }

//     if !config.alpn_protocols.is_empty() {
//         exts.push(ClientExtension::Protocols(Vec::from_slices(
//             &config
//                 .alpn_protocols
//                 .iter()
//                 .map(|proto| &proto[..])
//                 .collect::<Vec<_>>(),
//         )));
//     }

//     for ext in extensions {

//         match ext {
//             _ => {},
//         }
//     }

// }

// pub fn root_store() -> RootCertStore {
//     let mut roots = rustls::RootCertStore::empty();

//     for cert in rustls_native_certs::load_native_certs().expect("加载本地系统证书失败") {
//         let cert = rustls::Certificate(cert.0);
//         roots.add(&cert).unwrap();
//     }

//     roots
// }

//TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
// pub fn random_ja3(seed: usize) -> ClientConfig {
//     let root_store = root_store();
//     let mut tls_config = if seed == 0 {
//         ClientConfig::builder()
//             // .with_safe_defaults()
//             .with_root_certificates(root_store)
//             .with_no_client_auth()
//     } else {
//         let mut random: StdRng = rand::SeedableRng::seed_from_u64(seed as u64);

//         let mut cipher_suites = DEFAULT_CIPHER_SUITES.to_vec();
//         cipher_suites.shuffle(&mut random);

//         let mut kx_groups = ALL_KX_GROUPS.to_vec();
//         kx_groups.shuffle(&mut random);

//         let mut protocol_versions = DEFAULT_VERSIONS.to_vec();
//         protocol_versions.shuffle(&mut random);

//         ClientConfig::builder()
//             .dangerous()
//             .with_custom_certificate_verifier(verifier)
//             .
//             .with_cipher_suites(&cipher_suites)
//             .with_kx_groups(&kx_groups)
//             .with_protocol_versions(&protocol_versions)
//             .unwrap()
//             .with_root_certificates(root_store)
//             .with_no_client_auth()
//     };
//     tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
//     tls_config
// }
