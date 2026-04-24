#![allow(clippy::arithmetic_side_effects)]

mod fused_pbkdf2;

use {
    bip39::{Language, Mnemonic, MnemonicType},
    clap::{Arg, Command, value_parser},
    solana_derivation_path::DerivationPath,
    solana_keypair::seed_derivable::keypair_from_seed_and_derivation_path,
    solana_signer::Signer,
    std::{
        collections::HashSet,
        num::NonZeroU32,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        thread,
        time::{Duration, Instant},
    },
};

// ── PBKDF2 backends (selected at runtime via --pbkdf2 flag) ──

#[derive(Clone, Copy)]
enum Pbkdf2Backend {
    Ring,
    #[cfg(target_os = "macos")]
    CommonCrypto,
    Soft,
    Fused,
    FusedBip32, // fused PBKDF2 + lean BIP32 (skips 4 unnecessary scalar multiplies)
}

extern "C" {
    #[cfg(target_os = "macos")]
    fn CCKeyDerivationPBKDF(
        algorithm: u32,
        password: *const u8, password_len: usize,
        salt: *const u8, salt_len: usize,
        prf: u32, rounds: u32,
        derived_key: *mut u8, derived_key_len: usize,
    ) -> i32;
}

#[inline]
fn derive_seed(mnemonic: &Mnemonic, backend: Pbkdf2Backend) -> [u8; 64] {
    match backend {
        Pbkdf2Backend::Ring => {
            let mut seed = [0u8; 64];
            ring::pbkdf2::derive(
                ring::pbkdf2::PBKDF2_HMAC_SHA512,
                NonZeroU32::new(2048).unwrap(),
                b"mnemonic",
                mnemonic.phrase().as_bytes(),
                &mut seed,
            );
            seed
        }
        #[cfg(target_os = "macos")]
        Pbkdf2Backend::CommonCrypto => {
            let mut seed = [0u8; 64];
            let phrase = mnemonic.phrase();
            unsafe {
                CCKeyDerivationPBKDF(
                    2, // kCCPBKDF2
                    phrase.as_ptr(), phrase.len(),
                    b"mnemonic".as_ptr(), 8,
                    5, // kCCPRFHmacAlgSHA512
                    2048,
                    seed.as_mut_ptr(), 64,
                );
            }
            seed
        }
        Pbkdf2Backend::Soft => {
            let seed = bip39::Seed::new(mnemonic, "");
            let mut out = [0u8; 64];
            out.copy_from_slice(seed.as_bytes());
            out
        }
        Pbkdf2Backend::Fused | Pbkdf2Backend::FusedBip32 => {
            let mut seed = [0u8; 64];
            fused_pbkdf2::derive_seed_fused(mnemonic.phrase().as_bytes(), &mut seed);
            seed
        }
    }
}

// ============================================================
// WORD BANKS
// base58 safe: use lowercase o (not O), lowercase i (not i),
//              uppercase L (not l). No zeros.
// ============================================================

const POSITIVE: &[&str] = &[
    "BEST", "GoLD", "FAST", "FiRE", "KiNG", "CASH", "CooL", "DEEP", "LoRD", "RiCH",
    "VoiD", "RARE", "EViL", "PURE", "BoLD", "BoSS", "SoLo", "WiSE", "HERo", "PUNK",
    "DUKE", "NUKE", "BooM", "SAGE", "FUNK", "HACK", "EPiC", "DUDE", "RAGE", "FLEX",
    "GoAT", "DANK", "DoPE", "HoDL", "SWAG", "ViBE", "YEET", "YoLo", "STUD", "LoVE",
    "PEAK", "WiNS", "HiGH", "HoLY", "LoUD", "HARD", "DEAD", "CoDE", "NERD", "GEEK",
    "GoLF", "RUNS", "GURU", "JERK", "RUST", "DEVS", "RooT", "SUDo", "TALL",
];

const ROAST: &[&str] = &[
    "ANAL", "FUCK", "CoCK", "DiCK", "SUCK", "DiLF", "SLUT", "BoNE", "BANG", "SEXY",
    "KiLL", "HATE", "DAMN", "WANG", "FooL", "CRAP", "NUDE", "PoRN", "TiTS", "DoRK",
    "PAiN", "HELL", "BUTT", "SHiT", "ooPS", "BoMB", "BooB", "NUTS", "DUMB", "BoNK",
    "BRUH", "LMAo", "BRRR", "DoNG",
];

const TEAM_WORDS: &[&str] = &["FUSE", "ETHR", "TEAM"];

// ============================================================
// DEV NAMES
// ============================================================

struct Name {
    prefix_forms: &'static [&'static str],
    suffix_forms: &'static [&'static str],
}

const ERIK: Name = Name { prefix_forms: &["ERiK"], suffix_forms: &["ERiK"] };
const LANDON: Name = Name { prefix_forms: &["LAND"], suffix_forms: &["LAND"] };
const JORDAN: Name = Name { prefix_forms: &["JoRD"], suffix_forms: &["JoRD"] };
const JONATHAN: Name = Name {
    prefix_forms: &["JoN1", "JoN2", "JoN3", "JoN4", "JoN5", "JoN6", "JoN7", "JoN8", "JoN9", "JoNS"],
    suffix_forms: &["1JoN", "2JoN", "3JoN", "4JoN", "5JoN", "6JoN", "7JoN", "8JoN", "9JoN", "JoNS"],
};
const AJ: Name = Name { prefix_forms: &["AJAY"], suffix_forms: &["AJAY"] };

const ALL_FIRST_NAMES: &[&Name] = &[&ERIK, &LANDON, &JORDAN, &JONATHAN, &AJ];

const DONOHOO: Name = Name { prefix_forms: &["DoNo"], suffix_forms: &["DoNo"] };
const HOOO: Name = Name { prefix_forms: &["Hooo"], suffix_forms: &["Hooo"] };
const POCH: Name = Name { prefix_forms: &["PoCH"], suffix_forms: &["PoCH"] };
const GATES: Name = Name { prefix_forms: &["GATE"], suffix_forms: &["GATE"] };
const GAWRYCH: Name = Name { prefix_forms: &["GAWR"], suffix_forms: &["GAWR"] };
const TAYLOR: Name = Name { prefix_forms: &["TAYL"], suffix_forms: &["TAYL"] };
const TAYLOR2: Name = Name { prefix_forms: &["TLoR"], suffix_forms: &["TLoR"] };

const LAST_NAMES_WITH_WORDS: &[&Name] = &[&DONOHOO, &POCH, &GATES, &GAWRYCH, &TAYLOR, &TAYLOR2];

/// Name pairs: (first, last) — generates both prefix/suffix directions
const NAME_PAIRS: &[(&Name, &Name)] = &[
    (&ERIK, &DONOHOO), (&ERIK, &HOOO),
    (&LANDON, &POCH), (&JORDAN, &GATES),
    (&JONATHAN, &GAWRYCH),
    (&AJ, &TAYLOR), (&AJ, &TAYLOR2),
    (&DONOHOO, &HOOO),
];

const SELF_REPEATS: &[&str] = &[
    "ERiK", "PoCH", "LAND", "GATE", "GAWR", "AJAY", "TAYL", "DoNo", "Hooo", "JoRD", "TLoR",
];

const LANDON_SPECIALS: &[&str] = &["LoRD", "MiNE", "MARK", "FiLL", "MASS", "FALL", "LoCK", "oooo"];

// ============================================================
// HOLLOW KNIGHT PAIRS (prefix, suffix)
// ============================================================

const HK_PAIRS: &[(&str, &str)] = &[
    ("DEEP","NEST"), ("CiTY","TEAR"), ("GREY","ZoTE"), ("GRAY","ZoTE"),
    ("GRiM","KiNG"), ("DREM","NAiL"), ("BELL","HART"), ("GoDS","HoME"),
    ("GREY","MooR"), ("GRAY","MooR"), ("DUNG","DFND"), ("GRiM","GRiM"),
    ("DUNG","DUNG"), ("SiLK","SoNG"), ("PALE","KiNG"), ("KiNG","GRiM"),
    ("PATH","PAiN"), ("KiNG","SoUL"), ("VoiD","LACE"), ("LoST","LACE"),
    ("NiTE","GRiM"), ("MoTH","WiNG"), ("LAST","STAG"), ("KiNG","EDGE"),
    ("SiLK","VoiD"), ("VoiD","SiLK"), ("SoNG","SiLK"), ("WoRM","WAYS"),
    ("MooR","WiNG"), ("SiLK","SoAR"), ("PALE","WYRM"), ("PURE","VESS"),
    ("WYRM","KiNG"), ("SHAW","DASH"), ("VoiD","HERT"), ("SiLK","BiND"),
    ("LACE","VoiD"), ("SiLK","SiLK"), ("VoiD","VoiD"), ("LACE","LACE"),
    ("SHAW","SHAW"), ("NoSK","NoSK"), ("ZoTE","ZoTE"), ("WYRM","WYRM"),
    ("NAiL","NAiL"), ("STAG","STAG"),
];

// ============================================================
// LEET ENGINE
// ============================================================

const BS58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const POW58_4: u64 = 58 * 58 * 58 * 58; // 11,316,496

/// Compute the last 4 base58 characters of a 32-byte pubkey as lowercase bytes.
/// Uses N mod 58^4 — just 32 multiply-mod operations instead of full base58 encoding.
#[inline]
fn pubkey_suffix_fast(raw: &[u8]) -> [u8; 4] {
    let mut rem = 0u64;
    for &byte in raw.iter() {
        rem = (rem * 256 + byte as u64) % POW58_4;
    }
    let mut val = rem as u32;
    let mut suffix = [0u8; 4];
    for i in (0..4).rev() {
        suffix[i] = BS58_ALPHABET[(val % 58) as usize].to_ascii_lowercase();
        val /= 58;
    }
    suffix
}

const LEET_MAP: &[(char, char)] = &[
    ('A', '4'), ('B', '8'), ('E', '3'), ('G', '6'),
    ('i', '1'), ('S', '5'), ('T', '7'), ('Z', '2'),
];

/// Make a string base58-safe: O→o, I→i, l→L
fn bs58_safe(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'O' => 'o',
            'I' => 'i',
            'l' => 'L',
            _ => c,
        })
        .collect()
}

/// Generate all leet variants. lock_first=true for prefix mode (first char unchanged).
fn leet_expand(word: &str, lock_first: bool) -> Vec<String> {
    let safe = bs58_safe(word);
    let mut variants = vec![String::new()];
    for (i, ch) in safe.chars().enumerate() {
        let sub = if !(lock_first && i == 0) {
            LEET_MAP.iter().find(|(from, _)| *from == ch).map(|(_, to)| *to)
        } else {
            None
        };
        let prev = std::mem::take(&mut variants);
        for v in &prev {
            let mut with_orig = v.clone();
            with_orig.push(ch);
            variants.push(with_orig);
            if let Some(sub_ch) = sub {
                let mut with_sub = v.clone();
                with_sub.push(sub_ch);
                variants.push(with_sub);
            }
        }
    }
    variants
}

/// Cross-product prefix_variants × suffix_variants, lowercased, into the set.
fn cross_into(set: &mut HashSet<([u8; 4], [u8; 4])>, prefixes: &[String], suffixes: &[String]) {
    for p in prefixes {
        let pb = p.as_bytes();
        if pb.len() < 4 { continue; }
        let pk = [
            pb[0].to_ascii_lowercase(), pb[1].to_ascii_lowercase(),
            pb[2].to_ascii_lowercase(), pb[3].to_ascii_lowercase(),
        ];
        for s in suffixes {
            let sb = s.as_bytes();
            if sb.len() < 4 { continue; }
            set.insert((pk, [
                sb[0].to_ascii_lowercase(), sb[1].to_ascii_lowercase(),
                sb[2].to_ascii_lowercase(), sb[3].to_ascii_lowercase(),
            ]));
        }
    }
}

fn build_patterns() -> HashSet<([u8; 4], [u8; 4])> {
    let mut patterns = HashSet::new();

    // Hollow Knight pairs
    for (p, s) in HK_PAIRS {
        cross_into(&mut patterns, &leet_expand(p, true), &leet_expand(s, false));
    }

    // BUG{1-9}:NiTE (prefix is literal, not leet-expanded)
    let nite_suffixes = leet_expand("NiTE", false);
    for d in 1..=9u8 {
        let bug = vec![format!("BUG{d}")];
        cross_into(&mut patterns, &bug, &nite_suffixes);
    }

    // Name pairs (both directions)
    for (first, last) in NAME_PAIRS {
        for fp in first.prefix_forms {
            for ls in last.suffix_forms {
                cross_into(&mut patterns, &leet_expand(fp, true), &leet_expand(ls, false));
            }
        }
        for lp in last.prefix_forms {
            for fs in first.suffix_forms {
                cross_into(&mut patterns, &leet_expand(lp, true), &leet_expand(fs, false));
            }
        }
    }

    // Self-repeats
    for w in SELF_REPEATS {
        cross_into(&mut patterns, &leet_expand(w, true), &leet_expand(w, false));
    }

    // Landon specials: LAND × special words
    let land_prefixes = leet_expand("LAND", true);
    for s in LANDON_SPECIALS {
        cross_into(&mut patterns, &land_prefixes, &leet_expand(s, false));
    }

    // Pre-expand all words as prefix and suffix
    let all_words: Vec<&str> = POSITIVE.iter()
        .chain(ROAST.iter())
        .chain(TEAM_WORDS.iter())
        .copied()
        .collect();
    let all_pfx: Vec<String> = all_words.iter().flat_map(|w| leet_expand(w, true)).collect();
    let all_sfx: Vec<String> = all_words.iter().flat_map(|w| leet_expand(w, false)).collect();

    // First names × all words (both directions)
    for name in ALL_FIRST_NAMES {
        for form in name.prefix_forms {
            cross_into(&mut patterns, &leet_expand(form, true), &all_sfx);
        }
        for form in name.suffix_forms {
            cross_into(&mut patterns, &all_pfx, &leet_expand(form, false));
        }
    }

    // Last names × all words (both directions)
    for name in LAST_NAMES_WITH_WORDS {
        for form in name.prefix_forms {
            cross_into(&mut patterns, &leet_expand(form, true), &all_sfx);
        }
        for form in name.suffix_forms {
            cross_into(&mut patterns, &all_pfx, &leet_expand(form, false));
        }
    }

    patterns
}

// ============================================================
// MAIN
// ============================================================

fn main() {
    let default_num_threads = num_cpus::get().to_string();
    let pbkdf2_values = {
        let mut v = vec!["ring", "soft", "fused", "fused-bip32"];
        #[cfg(target_os = "macos")]
        v.push("commoncrypto");
        v
    };
    let matches = Command::new("vanity-grind")
        .about("Grind for vanity mnemonic keypairs")
        .arg(
            Arg::new("num_threads")
                .long("num-threads")
                .short('t')
                .value_name("NUMBER")
                .takes_value(true)
                .value_parser(value_parser!(usize))
                .default_value(&default_num_threads)
                .help("Number of grind threads"),
        )
        .arg(
            Arg::new("bench")
                .long("bench")
                .value_name("SECONDS")
                .takes_value(true)
                .value_parser(value_parser!(u64))
                .help("Run for N seconds then print throughput and exit"),
        )
        .arg(
            Arg::new("pbkdf2")
                .long("pbkdf2")
                .value_name("BACKEND")
                .takes_value(true)
                .default_value("fused-bip32")
                .possible_values(&pbkdf2_values)
                .help("PBKDF2 implementation: ring (BoringSSL asm), commoncrypto (macOS), soft (pure Rust)"),
        )
        .get_matches();

    let num_threads = *matches.get_one::<usize>("num_threads").unwrap();
    let bench_secs = matches.get_one::<u64>("bench").copied();
    let backend = match matches.get_one::<String>("pbkdf2").unwrap().as_str() {
        "ring" => Pbkdf2Backend::Ring,
        #[cfg(target_os = "macos")]
        "commoncrypto" => Pbkdf2Backend::CommonCrypto,
        "soft" => Pbkdf2Backend::Soft,
        "fused" => Pbkdf2Backend::Fused,
        "fused-bip32" => Pbkdf2Backend::FusedBip32,
        _ => unreachable!(),
    };
    let backend_name = matches.get_one::<String>("pbkdf2").unwrap().clone();

    let patterns = build_patterns();
    let suffix_set: HashSet<[u8; 4]> = patterns.iter().map(|(_, s)| *s).collect();

    println!("Generated {} patterns ({} unique suffixes, case-insensitive)",
        patterns.len(), suffix_set.len());
    println!("Mode: 24-word mnemonic, default derivation path, no passphrase");
    println!("PBKDF2: {}", backend_name);
    if let Some(secs) = bench_secs {
        println!("Benchmarking with {} threads for {}s...\n", num_threads, secs);
    } else {
        println!("Searching with {} threads (Ctrl+C to stop)...\n", num_threads);
    }

    let patterns = Arc::new(patterns);
    let suffix_set = Arc::new(suffix_set);
    let attempts = Arc::new(AtomicU64::new(1));
    let found = Arc::new(AtomicU64::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let start = Instant::now();

    let thread_handles: Vec<_> = (0..num_threads)
        .map(|_| {
            let patterns = patterns.clone();
            let suffix_set = suffix_set.clone();
            let attempts = attempts.clone();
            let found = found.clone();
            let done = done.clone();

            thread::spawn(move || {
                let mnemonic_type = MnemonicType::Words24;
                let language = Language::English;
                // m/44'/501'/0'/0' — Ledger-compatible path
                let derivation_path = Some(
                    DerivationPath::from_absolute_path_str("m/44'/501'/0'/0'").unwrap()
                );
                let mut bs58_buf = [0u8; 64];
                let mut local_count = 0u64;

                const BATCH: u64 = 8192;
                loop {
                    if local_count % BATCH == 0 {
                        if done.load(Ordering::Relaxed) { break; }
                        let attempt = attempts.fetch_add(BATCH, Ordering::Relaxed);
                        if (attempt / 1_000_000) != ((attempt + BATCH) / 1_000_000) {
                            println!(
                                "Searched {} keypairs in {}s. {} matches found.",
                                attempt + BATCH,
                                start.elapsed().as_secs(),
                                found.load(Ordering::Relaxed),
                            );
                        }
                    }
                    local_count += 1;

                    let mnemonic = Mnemonic::new(mnemonic_type, language);
                    let keypair = if matches!(backend, Pbkdf2Backend::FusedBip32) {
                        // Combined pipeline: fused PBKDF2 + lean BIP32
                        // Skips 4 unnecessary scalar multiplies in intermediate BIP32 levels
                        fused_pbkdf2::derive_keypair_fused(mnemonic.phrase().as_bytes())
                    } else {
                        let seed = derive_seed(&mnemonic, backend);
                        keypair_from_seed_and_derivation_path(
                            &seed,
                            derivation_path.clone(),
                        )
                        .unwrap()
                    };

                    // Fast suffix check on raw bytes — 32 multiply-mods, no base58 encode
                    let pubkey = keypair.pubkey();
                    let raw: &[u8] = pubkey.as_ref();
                    let suffix = pubkey_suffix_fast(raw);
                    if !suffix_set.contains(&suffix) { continue; }

                    // Rare suffix hit (~0.005%): full base58 encode to verify prefix
                    let len = bs58::encode(keypair.pubkey()).onto(&mut bs58_buf[..]).unwrap();
                    let pb = &bs58_buf[..len];
                    let prefix = [
                        pb[0].to_ascii_lowercase(), pb[1].to_ascii_lowercase(),
                        pb[2].to_ascii_lowercase(), pb[3].to_ascii_lowercase(),
                    ];

                    if patterns.contains(&(prefix, suffix)) {
                        found.fetch_add(1, Ordering::Relaxed);
                        if bench_secs.is_none() {
                            let phrase = mnemonic.phrase();
                            let divider = "=".repeat(phrase.len());
                            println!(
                                "{divider}\nFound matching key {}\n\
                                 \nSave this seed phrase to recover your new keypair:\n\
                                 {phrase}\n{divider}",
                                keypair.pubkey(),
                            );
                        }
                    }
                }
            })
        })
        .collect();

    if let Some(secs) = bench_secs {
        thread::sleep(Duration::from_secs(secs));
        done.store(true, Ordering::Relaxed);
        for handle in thread_handles {
            handle.join().unwrap();
        }
        let elapsed = start.elapsed().as_secs_f64();
        let total = attempts.load(Ordering::Relaxed);
        let matches = found.load(Ordering::Relaxed);
        println!("\n=== BENCHMARK RESULTS ===");
        println!("Threads:    {}", num_threads);
        println!("Duration:   {:.2}s", elapsed);
        println!("Attempts:   {}", total);
        println!("Throughput: {:.0} keys/sec", total as f64 / elapsed);
        println!("Matches:    {}", matches);
    } else {
        for handle in thread_handles {
            handle.join().unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::Seed;

    #[test]
    fn all_backends_match_bip39() {
        let backends = [
            Pbkdf2Backend::Ring,
            Pbkdf2Backend::Soft,
            Pbkdf2Backend::Fused,
        ];
        for _ in 0..10 {
            let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
            let bip39_seed = Seed::new(&mnemonic, "");
            for &backend in &backends {
                let seed = derive_seed(&mnemonic, backend);
                assert_eq!(bip39_seed.as_bytes(), &seed,
                    "Seed mismatch for backend {:?}, phrase: {}", backend as u8, mnemonic.phrase());
            }
        }
    }

    #[test]
    fn fused_bip32_matches_standard() {
        use solana_signer::Signer;

        // First: verify our HMAC-SHA512 matches reference
        {
            use hmac::{Hmac, Mac};
            use sha2::Sha512;
            for data_len in [12, 37, 64, 128, 200] {
                let key = b"test key material for hmac";
                let data: Vec<u8> = (0..data_len).map(|i| i as u8).collect();
                let mut ref_mac = <Hmac<Sha512>>::new_from_slice(key).unwrap();
                ref_mac.update(&data);
                let ref_result = ref_mac.finalize().into_bytes();
                let our_result = unsafe { fused_pbkdf2::hmac_sha512_for_test(key, &data) };
                assert_eq!(&ref_result[..], &our_result[..],
                    "HMAC-SHA512 mismatch for data_len={}", data_len);
            }
        }

        // Compare BIP32 intermediate values at each level — single mnemonic
        {
            let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
            let seed = derive_seed(&mnemonic, Pbkdf2Backend::Fused);

            // Reference: step through ed25519-dalek-bip32
            // m/44'/501'/0'/0' — Ledger-compatible (4 derivation levels)
            let ext0 = ed25519_dalek_bip32::ExtendedSigningKey::from_seed(&seed).unwrap();
            let ext1 = ext0.derive_child(ed25519_dalek_bip32::ChildIndex::Hardened(44)).unwrap();
            let ext2 = ext1.derive_child(ed25519_dalek_bip32::ChildIndex::Hardened(501)).unwrap();
            let ext3 = ext2.derive_child(ed25519_dalek_bip32::ChildIndex::Hardened(0)).unwrap();
            let ext4 = ext3.derive_child(ed25519_dalek_bip32::ChildIndex::Hardened(0)).unwrap();
            let ref_levels: Vec<[u8; 32]> = vec![
                ext0.signing_key.to_bytes(),
                ext1.signing_key.to_bytes(),
                ext2.signing_key.to_bytes(),
                ext3.signing_key.to_bytes(),
                ext4.signing_key.to_bytes(),
            ];

            let our_levels = unsafe { fused_pbkdf2::bip32_debug(&seed) };
            for (i, (r, o)) in ref_levels.iter().zip(our_levels.iter()).enumerate() {
                assert_eq!(r, o, "BIP32 level {} secret mismatch\n  ref: {:02x?}\n  our: {:02x?}", i, r, o);
            }

            // Also verify final pubkey — using m/44'/501'/0'/0'
            let full_path = DerivationPath::from_absolute_path_str("m/44'/501'/0'/0'").unwrap();
            let kp_std = keypair_from_seed_and_derivation_path(
                &seed, Some(full_path),
            ).unwrap();
            let kp_fused = solana_keypair::Keypair::new_from_array(*our_levels.last().unwrap());
            assert_eq!(kp_std.pubkey(), kp_fused.pubkey(), "Final pubkey mismatch");
        }
    }

    #[test]
    fn fast_suffix_matches_bs58() {
        use solana_keypair::Keypair;
        use solana_signer::Signer;
        for _ in 0..1000 {
            let keypair = Keypair::new();
            let pubkey = keypair.pubkey();
            let raw: &[u8] = pubkey.as_ref();

            // Full base58 encode
            let bs58_str = bs58::encode(raw).into_string();
            let bs58_bytes = bs58_str.as_bytes();
            let len = bs58_bytes.len();
            let expected = [
                bs58_bytes[len - 4].to_ascii_lowercase(),
                bs58_bytes[len - 3].to_ascii_lowercase(),
                bs58_bytes[len - 2].to_ascii_lowercase(),
                bs58_bytes[len - 1].to_ascii_lowercase(),
            ];

            // Fast path
            let fast = pubkey_suffix_fast(raw);
            assert_eq!(fast, expected, "Suffix mismatch for pubkey {}", bs58_str);
        }
    }
}
