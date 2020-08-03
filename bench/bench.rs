use criterion::measurement::Measurement;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};

use umbral::random_oracles::unsafe_hash_to_point;

fn bench_unsafe_hash_to_point<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let data = b"abcdefg";
    let label = b"sdasdasd";
    group.bench_function("unsafe_hash_to_point", |b| {
        b.iter(|| unsafe_hash_to_point(&data[..], &label[..]))
    });
}

fn bench_all(c: &mut Criterion) {
    let mut group = c.benchmark_group("group name");
    bench_unsafe_hash_to_point(&mut group);
    group.finish();
}

criterion_group!(benches, bench_all);
criterion_main!(benches);
