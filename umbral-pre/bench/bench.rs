use criterion::measurement::Measurement;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};

#[cfg(feature = "bench-internals")]
use umbral_pre::bench::{
    capsule_from_public_key, capsule_open_original, capsule_open_reencrypted, unsafe_hash_to_point,
};

use umbral_pre::{
    decrypt_original, decrypt_reencrypted, encrypt, generate_kfrags, reencrypt, SecretKey, Signer,
    VerifiedCapsuleFrag,
};

#[cfg(feature = "bench-internals")]
fn bench_unsafe_hash_to_point<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let data = b"abcdefg";
    let label = b"sdasdasd";
    group.bench_function("unsafe_hash_to_point", |b| {
        b.iter(|| unsafe_hash_to_point(&data[..], &label[..]))
    });
}

#[cfg(feature = "bench-internals")]
fn bench_capsule_from_public_key<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let delegating_sk = SecretKey::random();
    let delegating_pk = delegating_sk.public_key();
    group.bench_function("Capsule::from_public_key", |b| {
        b.iter(|| capsule_from_public_key(&delegating_pk))
    });
}

#[cfg(feature = "bench-internals")]
fn bench_capsule_open_original<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let delegating_sk = SecretKey::random();
    let delegating_pk = delegating_sk.public_key();
    let plaintext = b"peace at dawn";
    let (capsule, _ciphertext) = encrypt(&delegating_pk, plaintext).unwrap();
    group.bench_function("Capsule::open_original", |b| {
        b.iter(|| capsule_open_original(&capsule, &delegating_sk))
    });
}

#[cfg(feature = "bench-internals")]
fn bench_capsule_open_reencrypted<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let delegating_sk = SecretKey::random();
    let delegating_pk = delegating_sk.public_key();

    let signer = Signer::new(SecretKey::random());

    let receiving_sk = SecretKey::random();
    let receiving_pk = receiving_sk.public_key();

    let (capsule, _key_seed) = capsule_from_public_key(&delegating_pk);

    let threshold: usize = 2;
    let num_frags: usize = threshold + 1;

    let kfrags = generate_kfrags(
        &delegating_sk,
        &receiving_pk,
        &signer,
        threshold,
        num_frags,
        true,
        true,
    );

    let vcfrags: Vec<_> = kfrags
        .iter()
        .map(|kfrag| reencrypt(&capsule, kfrag.clone()))
        .collect();

    let cfrags: Vec<_> = vcfrags[0..threshold]
        .iter()
        .cloned()
        .map(|vcfrag| vcfrag.unverify())
        .collect();

    group.bench_function("Capsule::open_reencrypted", |b| {
        b.iter(|| capsule_open_reencrypted(&capsule, &receiving_sk, &delegating_pk, &cfrags))
    });
}

fn bench_pre<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let delegating_sk = SecretKey::random();
    let delegating_pk = delegating_sk.public_key();
    let plaintext = b"peace at dawn";

    // Encryption

    group.bench_function("encrypt", |b| {
        b.iter(|| encrypt(&delegating_pk, &plaintext[..]))
    });

    // Decryption with the original key

    let (capsule, ciphertext) = encrypt(&delegating_pk, plaintext).unwrap();
    group.bench_function("decrypt_original", |b| {
        b.iter(|| decrypt_original(&delegating_sk, &capsule, &ciphertext[..]))
    });

    // Kfrag generation

    let threshold: usize = 2;
    let num_frags: usize = threshold + 1;

    let signer = Signer::new(SecretKey::random());

    let receiving_sk = SecretKey::random();
    let receiving_pk = receiving_sk.public_key();

    group.bench_function("generate_kfrags", |b| {
        b.iter(|| {
            generate_kfrags(
                &delegating_sk,
                &receiving_pk,
                &signer,
                threshold,
                num_frags,
                true,
                true,
            )
        })
    });

    // Reencryption

    let verified_kfrags = generate_kfrags(
        &delegating_sk,
        &receiving_pk,
        &signer,
        threshold,
        num_frags,
        true,
        true,
    );

    let vkfrag = &verified_kfrags[0];

    group.bench_function("reencrypt", |b| {
        b.iter(|| reencrypt(&capsule, vkfrag.clone()))
    });

    // Decryption of the reencrypted data

    let verified_cfrags: Vec<VerifiedCapsuleFrag> = verified_kfrags[0..threshold]
        .iter()
        .cloned()
        .map(|vkfrag| reencrypt(&capsule, vkfrag))
        .collect();

    group.bench_function("decrypt_reencrypted", |b| {
        b.iter(|| {
            decrypt_reencrypted(
                &receiving_sk,
                &delegating_pk,
                &capsule,
                verified_cfrags.clone(),
                &ciphertext,
            )
        })
    });
}

#[cfg(feature = "bench-internals")]
fn group_internals(c: &mut Criterion) {
    let mut group = c.benchmark_group("internals");
    bench_unsafe_hash_to_point(&mut group);
    bench_capsule_from_public_key(&mut group);
    bench_capsule_open_original(&mut group);
    bench_capsule_open_reencrypted(&mut group);
    group.finish();
}

fn group_pre(c: &mut Criterion) {
    let mut group = c.benchmark_group("PRE API");
    bench_pre(&mut group);
    group.finish();
}

#[cfg(feature = "bench-internals")]
criterion_group!(benches, group_internals, group_pre);

#[cfg(not(feature = "bench-internals"))]
criterion_group!(benches, group_pre);

criterion_main!(benches);
