use sec_store::Store;

///Obviously do not store credentials like that.
const USER: &[u8] = b"loli";
const PASS: &[u8] = b"pass";

#[test]
fn should_securely_manage_values() {
    let mut owned_bytes = Vec::new();
    let mut bytes: [u8; 1024] = [0; 1024];
    let mut store = Store::new(USER, PASS);

    assert_eq!(store.len(), 0);
    assert!(store.insert(b"1", PASS).is_none());
    assert_eq!(store.len(), 1);
    assert_eq!(store.get(b"1").unwrap(), PASS);
    assert_eq!(store.get_to(b"1", &mut bytes).unwrap(), PASS.len());
    assert_eq!(bytes[..PASS.len()], PASS[..]);
    assert_eq!(store.get_to_vec(b"1", &mut owned_bytes).unwrap(), PASS.len());
    assert_eq!(owned_bytes.as_slice(), &PASS[..]);
    assert_eq!(store.get_to_vec(b"1", &mut owned_bytes).unwrap(), PASS.len());
    assert_eq!(owned_bytes.as_slice(), &PASS[..]);

    assert_eq!(store.insert(b"1", USER).unwrap(), PASS);
    assert_eq!(store.len(), 1);
    assert_eq!(store.get(b"1").unwrap(), USER);

    assert!(store.insert(b"2", PASS).is_none());
    assert_eq!(store.len(), 2);
    assert_eq!(store.get(b"2").unwrap(), PASS);

    let store = store.into_inner();
    let store = Store::from_inner(store, USER, PASS);
    assert_eq!(store.get(b"1").unwrap(), USER);
    assert_eq!(store.get(b"2").unwrap(), PASS);

    let store = store.into_inner();
    let mut store = Store::from_inner(store, USER, b"WRONG");

    assert!(store.get(b"1").is_none());
    assert!(store.get(b"2").is_none());
    assert_eq!(store.remove_to(b"2", &mut []).unwrap(), 0);
    assert_eq!(store.len(), 2);
    assert!(store.remove(b"2").is_none());
    assert_eq!(store.len(), 2);
    assert!(store.insert(b"2", PASS).is_none());
    bytes = [0; 1024];
    assert_eq!(store.remove_to(b"2", &mut bytes).unwrap(), PASS.len());
    assert_eq!(bytes[..PASS.len()], PASS[..]);
    assert_eq!(store.len(), 1);

    let store = store.into_inner();
    let mut store = Store::from_inner(store, b"WRONG", PASS);

    assert!(store.get(b"1").is_none());
    assert!(store.get_to(b"1", &mut bytes).is_err());
    assert!(store.remove_to(b"1", &mut bytes).is_err());
    assert_eq!(store.len(), 1);
    assert!(store.remove(b"1").is_none());
    assert_eq!(store.len(), 1);
}
