use rustunnel::dns::is_valid_fqdn;

#[test]
fn test_valid_fqdn() {
    assert_eq!(is_valid_fqdn("example.com"), true);
    assert_eq!(is_valid_fqdn("test.example.com"), true);
    assert_eq!(is_valid_fqdn("my-site.co.uk"), true);
    assert_eq!(is_valid_fqdn("subdomain.example.co.jp"), true);
}

#[test]
fn test_invalid_fqdn() {
    assert_eq!(is_valid_fqdn("invalid"), true);
    assert_eq!(is_valid_fqdn("-example.com"), false);
    assert_eq!(is_valid_fqdn("example-.com"), false);
    assert_eq!(is_valid_fqdn("example..com"), false);
    assert_eq!(is_valid_fqdn("exam ple.com"), false);
    assert_eq!(is_valid_fqdn("example.c"), true);
    assert_eq!(is_valid_fqdn(""), false);
}

#[test]
fn test_edge_cases_fqdn() {
    assert_eq!(is_valid_fqdn("a.b.c.d.e.f.g.h.i.j.k"), true);
    assert_eq!(is_valid_fqdn("xn--bcher-kva.example"), true);
    assert_eq!(is_valid_fqdn("123.example.com"), true);
    assert_eq!(is_valid_fqdn("a123.example.com"), true);
    assert_eq!(is_valid_fqdn("example.123"), false);
}

#[test]
fn test_length_limits_fqdn() {
    // Label > 63 characters
    assert_eq!(is_valid_fqdn("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklm.com"), false);

    // Total length > 255 characters
    assert_eq!(is_valid_fqdn("really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-really-long.example.com"), false);
}
