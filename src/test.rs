#[test]
fn bench2() {
    let mut keyauth = crate::v1_2::KeyauthApi::new("library-development", "EdmsTKiuld", "9f752b6a414455175efd942abfd2183667413d57b1d59d6742d8437c71802b49", "1.0", "https://keyauth.win/api/1.2/");
    keyauth.init(None);
    keyauth.login("demoseller".to_string(), "R9yzxdRyybgY75".to_string(), None);
}

#[test]
#[cfg(feature = "v1_0")]
fn bench1() {
    let mut keyauth = crate::v1_0::KeyauthApi::new("library-development", "EdmsTKiuld", "9f752b6a414455175efd942abfd2183667413d57b1d59d6742d8437c71802b49", "1.0", "https://keyauth.win/api/1.0/");
    keyauth.init(None);
    keyauth.login("demoseller".to_string(), "R9yzxdRyybgY75".to_string(), None);
}
