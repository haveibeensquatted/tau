use sigma_rust::{check_rule, rule_from_yaml, Event};

#[cfg(feature = "serde_json")]
use serde_json::json;

#[cfg(feature = "serde_json")]
#[test]
fn test_real_world_domain_monitoring_data() {
    let event: Event = json!({
        "id": "df79ebc3-b5e2-4cdd-b873-f58fede69fe2",
        "lookup_id": "a0ee0f76-2d95-4afe-90a0-62169340789e",
        "permutation": "cosumo.com",
        "created_on": "2025-06-11T11:04:34.481Z",
        "levenshtein_distance": 1,
        "dns_a": ["163.44.78.108"],
        "http_banner": "Apache/2.2.34 (Unix) mod_ssl/2.2.34 OpenSSL/1.0.2n",
        "classification": {
            "parked": 0.01,
            "phishing": 0.01,
            "legitimate": 0.98
        },
        "geolocation": {
            "ip": "163.44.78.108",
            "asn": {
                "number": 7506,
                "organization": "GMO Internet Group, Inc."
            },
            "country": {
                "iso_code": "JP",
                "continent": "AS"
            }
        },
        "registration_metadata": {
            "registrar": "GMO Internet Group, Inc. d/b/a Onamae.com",
            "registrar_iana_id": "49",
            "registration_date": "1999-12-14T11:37:42Z",
            "expiration_date": "2025-12-14T11:37:42Z",
            "nameservers": ["DNS01.ATHOME-HP.JP", "DNS02.ATHOME-HP.JP"],
            "dnssec_status": "Unsigned"
        },
        "origin_x509": {
            "is_ca": false,
            "serial": "519c06f127a3c0165c36b6ba07a7e38e676",
            "key_alg": "1.2.840.113549.1.1.1",
            "san_dns": ["cosumo.com", "www.cosumo.com"],
            "ttl_days": 89,
            "issuer_dn": "C=US, O=Let's Encrypt, CN=R10",
            "not_after": 1752776014,
            "not_before": 1745000015,
            "subject_dn": "CN=cosumo.com",
            "sig_alg_oid": "1.2.840.113549.1.1.11",
            "key_size_bits": 2056,
            "san_dns_count": 2,
            "fingerprint_sha256": "82db36cbdfbc43d3e807846d0e56dba670e6c1fc0191fc34297a8cdadbb9c970"
        },
        "technologies": ["Apache HTTP Server:2.2.34", "Google Analytics", "OpenSSL:1.0.2n", "PHP:5.5.38", "jQuery:1.10.1"],
        "screenshot_url": "https://screenshot.haveibeensquatted.com/f6526fdd-b352-467e-ad1b-be602fffeafb"
    }).try_into().unwrap();

    // Test 1: High legitimacy score (opposite of phishing)
    let legitimate_rule = r#"
title: High Legitimacy Score Detection
logsource:
    category: domain_analysis
detection:
    high_legitimacy:
        classification.legitimate|gt: 0.9
    condition: high_legitimacy
"#;
    let rule = rule_from_yaml(legitimate_rule).unwrap();
    assert!(check_rule(&rule, &event), "Should detect high legitimacy score");

    // Test 2: Low phishing score
    let low_phishing_rule = r#"
title: Low Phishing Score
logsource:
    category: domain_analysis
detection:
    low_phishing:
        classification.phishing|lt: 0.1
    condition: low_phishing
"#;
    let rule = rule_from_yaml(low_phishing_rule).unwrap();
    assert!(check_rule(&rule, &event), "Should detect low phishing score");

    // Test 3: Japanese domain detection
    let japanese_domain_rule = r#"
title: Japanese Domain Detection
logsource:
    category: domain_analysis
detection:
    japanese_domain:
        geolocation.country.iso_code: 'JP'
        geolocation.country.continent: 'AS'
    condition: japanese_domain
"#;
    let rule = rule_from_yaml(japanese_domain_rule).unwrap();
    assert!(check_rule(&rule, &event), "Should detect Japanese domain");

    // Test 4: GMO Internet (Japanese hosting provider) detection
    let gmo_hosting_rule = r#"
title: GMO Internet Hosting Detection
logsource:
    category: domain_analysis
detection:
    gmo_asn:
        geolocation.asn.number: 7506
    gmo_registrar:
        registration_metadata.registrar|contains: 'GMO Internet'
    condition: gmo_asn and gmo_registrar
"#;
    let rule = rule_from_yaml(gmo_hosting_rule).unwrap();
    assert!(check_rule(&rule, &event), "Should detect GMO Internet hosting");

    // Test 5: Let's Encrypt certificate detection
    let letsencrypt_cert_rule = r#"
title: Let's Encrypt Certificate Detection
logsource:
    category: domain_analysis
detection:
    letsencrypt_issuer:
        origin_x509.issuer_dn|contains: "Let's Encrypt"
    not_ca_cert:
        origin_x509.is_ca: false
    modern_cert:
        origin_x509.key_size_bits|gte: 2048
    condition: letsencrypt_issuer and not_ca_cert and modern_cert
"#;
    let rule = rule_from_yaml(letsencrypt_cert_rule).unwrap();
    assert!(check_rule(&rule, &event), "Should detect Let's Encrypt certificate");

    // Test 6: Domain in SAN list
    let san_domain_rule = r#"
title: Domain in Certificate SAN
logsource:
    category: domain_analysis
detection:
    domain_in_san:
        origin_x509.san_dns|contains: 'cosumo.com'
    www_variant_in_san:
        origin_x509.san_dns|contains: 'www.cosumo.com'
    condition: domain_in_san and www_variant_in_san
"#;
    let rule = rule_from_yaml(san_domain_rule).unwrap();
    assert!(check_rule(&rule, &event), "Should detect domain in SAN list");

    // Test 7: Long-lived domain (registered in 1999)
    let old_domain_rule = r#"
title: Long-lived Domain Detection
logsource:
    category: domain_analysis
detection:
    old_registration:
        registration_metadata.registration_date|startswith: '1999'
    unsigned_dnssec:
        registration_metadata.dnssec_status: 'Unsigned'
    condition: old_registration and unsigned_dnssec
"#;
    let rule = rule_from_yaml(old_domain_rule).unwrap();
    assert!(check_rule(&rule, &event), "Should detect old domain registration");

    // Test 8: Complex rule combining multiple criteria (legitimate domain characteristics)
    let legitimate_domain_rule = r#"
title: Legitimate Domain Characteristics
logsource:
    category: domain_analysis
detection:
    high_legitimacy:
        classification.legitimate|gt: 0.9
    low_phishing:
        classification.phishing|lt: 0.1
    established_domain:
        registration_metadata.registration_date|startswith: '1999'
    valid_cert:
        origin_x509.is_ca: false
        origin_x509.key_size_bits|gte: 2048
    condition: high_legitimacy and low_phishing and established_domain and valid_cert
"#;
    let rule = rule_from_yaml(legitimate_domain_rule).unwrap();
    assert!(check_rule(&rule, &event), "Should detect legitimate domain characteristics");

    // Test 9: Technology stack detection
    let tech_stack_rule = r#"
title: Apache PHP Technology Stack
logsource:
    category: domain_analysis
detection:
    apache_server:
        http_banner|contains: 'Apache'
    has_php:
        technologies|contains: 'PHP'
    has_jquery:
        technologies|contains: 'jQuery'
    condition: apache_server and has_php and has_jquery
"#;
    let rule = rule_from_yaml(tech_stack_rule).unwrap();
    assert!(check_rule(&rule, &event), "Should detect Apache PHP technology stack");
}

#[cfg(feature = "serde_json")]
#[test]
fn test_simple_nested_field_rule() {
    let event: Event = json!({
        "domain": "example.com",
        "classification": {
            "phishing": 0.85,
            "parked": 0.1,
            "legitimate": 0.05
        }
    }).try_into().unwrap();

    let rule_yaml = r#"
title: High Phishing Score Detection
logsource:
    category: domain_analysis
detection:
    high_phishing:
        classification.phishing|gt: 0.8
    condition: high_phishing
"#;

    let rule = rule_from_yaml(rule_yaml).unwrap();
    assert!(check_rule(&rule, &event));

    let rule_yaml_no_match = r#"
title: High Phishing Score Detection
logsource:
    category: domain_analysis
detection:
    high_phishing:
        classification.phishing|gt: 0.9
    condition: high_phishing
"#;

    let rule_no_match = rule_from_yaml(rule_yaml_no_match).unwrap();
    assert!(!check_rule(&rule_no_match, &event));
}

#[cfg(feature = "serde_json")]
#[test]
fn test_deep_nested_field_rule() {
    let event: Event = json!({
        "domain": "example.com",
        "geolocation": {
            "country": {
                "iso_code": "US",
                "continent": "NA"
            },
            "asn": {
                "number": 15169,
                "organization": "Google LLC"
            }
        }
    }).try_into().unwrap();

    let rule_yaml = r#"
title: US Domain Detection
logsource:
    category: domain_analysis
detection:
    us_domain:
        geolocation.country.iso_code: 'US'
    condition: us_domain
"#;

    let rule = rule_from_yaml(rule_yaml).unwrap();
    assert!(check_rule(&rule, &event));

    let rule_yaml_no_match = r#"
title: CN Domain Detection
logsource:
    category: domain_analysis
detection:
    cn_domain:
        geolocation.country.iso_code: 'CN'
    condition: cn_domain
"#;

    let rule_no_match = rule_from_yaml(rule_yaml_no_match).unwrap();
    assert!(!check_rule(&rule_no_match, &event));
}

#[cfg(feature = "serde_json")]
#[test]
fn test_mixed_fields_rule() {
    let event: Event = json!({
        "domain": "suspicious.com",
        "permutation": true,
        "classification": {
            "phishing": 0.9,
            "legitimate": 0.1
        },
        "geolocation": {
            "country": {
                "iso_code": "CN"
            }
        }
    }).try_into().unwrap();

    let rule_yaml = r#"
title: Suspicious Domain Detection
logsource:
    category: domain_analysis
detection:
    high_phishing:
        classification.phishing|gt: 0.8
    suspicious_country:
        geolocation.country.iso_code: 'CN'
    is_permutation:
        permutation: true
    condition: high_phishing and suspicious_country and is_permutation
"#;

    let rule = rule_from_yaml(rule_yaml).unwrap();
    assert!(check_rule(&rule, &event));
}

#[cfg(feature = "serde_json")]
#[test]
fn test_tls_certificate_fields() {
    let event: Event = json!({
        "domain": "example.com",
        "origin_x509": {
            "fingerprint_sha256": "abc123def456",
            "issuer_dn": "CN=Let's Encrypt Authority X3",
            "subject_dn": "CN=example.com",
            "san_dns": ["example.com", "www.example.com"],
            "not_before": 1640995200,
            "not_after": 1672531200,
            "key_alg": "rsaEncryption",
            "sig_alg_oid": "1.2.840.113549.1.1.11",
            "is_ca": false
        }
    }).try_into().unwrap();

    let rule_yaml = r#"
title: Certificate Validation
logsource:
    category: domain_analysis
detection:
    lets_encrypt_cert:
        origin_x509.issuer_dn|contains: "Let's Encrypt"
    not_ca_cert:
        origin_x509.is_ca: false
    condition: lets_encrypt_cert and not_ca_cert
"#;

    let rule = rule_from_yaml(rule_yaml).unwrap();
    assert!(check_rule(&rule, &event));
}

#[cfg(feature = "serde_json")]
#[test]
fn test_registration_metadata_fields() {
    let event: Event = json!({
        "domain": "example.com",
        "registration_metadata": {
            "registrar": "GoDaddy",
            "registration_date": "2010-01-01",
            "expiration_date": "2025-01-01",
            "nameservers": ["ns1.godaddy.com", "ns2.godaddy.com"],
            "dnssec_status": "unsigned",
            "registrar_iana_id": "146"
        }
    }).try_into().unwrap();

    let rule_yaml = r#"
title: GoDaddy Domain Detection
logsource:
    category: domain_analysis
detection:
    godaddy_domain:
        registration_metadata.registrar: 'GoDaddy'
    unsigned_dnssec:
        registration_metadata.dnssec_status: 'unsigned'
    condition: godaddy_domain and unsigned_dnssec
"#;

    let rule = rule_from_yaml(rule_yaml).unwrap();
    assert!(check_rule(&rule, &event));
}

#[cfg(feature = "serde_json")]
#[test]
fn test_array_operations() {
    let event: Event = json!({
        "domain": "example.com",
        "origin_x509": {
            "san_dns": ["example.com", "www.example.com", "api.example.com"]
        }
    }).try_into().unwrap();

    let rule_yaml = r#"
title: SAN DNS Contains Domain
logsource:
    category: domain_analysis
detection:
    san_contains_api:
        origin_x509.san_dns|contains: 'api.example.com'
    condition: san_contains_api
"#;

    let rule = rule_from_yaml(rule_yaml).unwrap();
    assert!(check_rule(&rule, &event));
}

#[cfg(feature = "serde_json")]
#[test]
fn test_field_existence() {
    let event: Event = json!({
        "domain": "example.com",
        "classification": {
            "phishing": 0.1
        }
    }).try_into().unwrap();

    let rule_yaml = r#"
title: Has Classification Data
logsource:
    category: domain_analysis
detection:
    has_phishing_score:
        classification.phishing|exists: true
    no_parked_score:
        classification.parked|exists: false
    condition: has_phishing_score and no_parked_score
"#;

    let rule = rule_from_yaml(rule_yaml).unwrap();
    assert!(check_rule(&rule, &event));
}

#[cfg(feature = "serde_json")]
#[test]
fn test_string_modifiers_with_nested_fields() {
    let event: Event = json!({
        "domain": "example.com",
        "origin_x509": {
            "subject_dn": "CN=example.com,O=Example Corp,C=US"
        }
    }).try_into().unwrap();

    let rule_yaml = r#"
title: Certificate Subject Contains Example
logsource:
    category: domain_analysis
detection:
    example_in_subject:
        origin_x509.subject_dn|contains: 'example.com'
    starts_with_cn:
        origin_x509.subject_dn|startswith: 'CN='
    condition: example_in_subject and starts_with_cn
"#;

    let rule = rule_from_yaml(rule_yaml).unwrap();
    assert!(check_rule(&rule, &event));
}

#[cfg(feature = "serde_json")]
#[test]
fn test_numeric_comparisons_nested_fields() {
    let event: Event = json!({
        "domain": "example.com",
        "geolocation": {
            "asn": {
                "number": 15169
            }
        },
        "origin_x509": {
            "not_before": 1640995200,
            "not_after": 1672531200
        }
    }).try_into().unwrap();

    let rule_yaml = r#"
title: ASN and Certificate Timing Check
logsource:
    category: domain_analysis
detection:
    google_asn:
        geolocation.asn.number: 15169
    cert_not_before:
        origin_x509.not_before|gte: 1640000000
    cert_not_after:
        origin_x509.not_after|lte: 1700000000
    condition: google_asn and cert_not_before and cert_not_after
"#;

    let rule = rule_from_yaml(rule_yaml).unwrap();
    assert!(check_rule(&rule, &event));
} 