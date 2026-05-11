//! Determinism, content-sensitivity and path-sensitivity tests for the
//! Merkle manifest.

use std::fs;

use agenomic_hash::compute_manifest;
use rand::seq::SliceRandom;
use tempfile::tempdir;

fn build_fixture(root: &std::path::Path, files: &[(&str, &[u8])]) {
    for (rel, content) in files {
        let p = root.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, content).unwrap();
    }
}

#[test]
fn same_input_same_root() {
    let files: &[(&str, &[u8])] = &[
        ("a.txt", b"alpha"),
        ("b/c.txt", b"charlie"),
        ("b/d.txt", b"delta"),
        ("z.json", b"{}"),
    ];

    let d1 = tempdir().unwrap();
    build_fixture(d1.path(), files);
    let m1 = compute_manifest(d1.path()).unwrap();

    // Recreate with shuffled creation order
    let d2 = tempdir().unwrap();
    let mut shuffled: Vec<_> = files.to_vec();
    let mut rng = rand::thread_rng();
    shuffled.shuffle(&mut rng);
    build_fixture(d2.path(), &shuffled);
    let m2 = compute_manifest(d2.path()).unwrap();

    assert_eq!(m1.root_hash, m2.root_hash);
    assert_eq!(m1.entries, m2.entries);
}

#[test]
fn path_independence() {
    let files: &[(&str, &[u8])] = &[("foo", b"bar")];

    let d1 = tempdir().unwrap();
    let d2 = tempdir().unwrap();
    build_fixture(d1.path(), files);
    build_fixture(d2.path(), files);
    let m1 = compute_manifest(d1.path()).unwrap();
    let m2 = compute_manifest(d2.path()).unwrap();
    assert_eq!(m1.root_hash, m2.root_hash);
}

#[test]
fn one_bit_flip_changes_hash() {
    let d1 = tempdir().unwrap();
    build_fixture(d1.path(), &[("a.txt", b"hello")]);
    let m1 = compute_manifest(d1.path()).unwrap();

    let d2 = tempdir().unwrap();
    build_fixture(d2.path(), &[("a.txt", b"hellp")]);
    let m2 = compute_manifest(d2.path()).unwrap();

    assert_ne!(m1.root_hash, m2.root_hash);
}

#[test]
fn rename_changes_hash() {
    let d1 = tempdir().unwrap();
    build_fixture(d1.path(), &[("a.txt", b"x")]);
    let m1 = compute_manifest(d1.path()).unwrap();

    let d2 = tempdir().unwrap();
    build_fixture(d2.path(), &[("b.txt", b"x")]);
    let m2 = compute_manifest(d2.path()).unwrap();

    assert_ne!(m1.root_hash, m2.root_hash);
}
