//! Vanity pattern generation and matching for the Ledger derivation-path scanner.
//!
//! The default word bank below was curated by hand from `wordlist.txt` at the
//! repo root. `four_letter_words.txt` contains the optional full dictionary.
//!
//! Every word in the curated arrays is already base58-safe: no `0`, `O`, `I`,
//! or lowercase `l`. Optional dictionary entries are converted to the same
//! Base58-safe capitalization. Case becomes exact under `--case-sensitive`.

use std::collections::HashMap;

/// Unique four-letter ASCII entries from macOS `/usr/share/dict/web2`, which is
/// based on Webster's Second International dictionary.
const ALL_FOUR_LETTER_WORDS: &str = include_str!("four_letter_words.txt");

#[cfg(test)]
pub const BS58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// ============================================================
// WORD BANK  (190 words: 8 three-char, 182 four-char)
// ============================================================

const SELF: &[&str] = &["JoN", "JAG", "GAWR", "ETHR", "FUSE"];

const FURRY: &[&str] = &[
    "Bun", "Bny", "Fur", "oWo", "UWU", "Tibb", "Tibt", "Tbit", "Tibs", "Tiby", "Bunn", "Buny",
    "BunE", "Buns", "Bunz", "Bnny", "Boop", "Paws", "Pawz", "Ears", "Fuzz", "FLuf", "Furr", "Hops",
    "Hopp", "Hare", "Thmp", "Thum", "Lops", "Rabt", "Burr", "TaiL", "Cute", "Pets", "Hugs", "Bugs",
    "Awoo", "Yiff",
];

const POSITIVE: &[&str] = &[
    "BEST", "BoLD", "CASH", "CoDE", "CooL", "DANK", "DEAD", "DEEP", "DEVS", "DUDE", "DoPE", "EPiC",
    "EViL", "FAST", "FLEX", "FUNK", "FiLL", "FiRE", "GEEK", "GURU", "GoAT", "GoLD", "GoLF", "HACK",
    "HARD", "HERo", "HiGH", "HoDL", "HoLY", "JERK", "KiNG", "LoCK", "LoRD", "LoUD", "LoVE", "MARK",
    "MASS", "MiNE", "NERD", "NUKE", "PEAK", "PUNK", "PURE", "RAGE", "RARE", "RUNS", "RUST", "RiCH",
    "SAGE", "STUD", "SUDo", "SWAG", "SoLo", "TALL", "ViBE", "VoiD", "WiNS", "WiSE", "YEET", "YoLo",
];

const ROAST: &[&str] = &[
    "ANAL", "BANG", "BRRR", "BRUH", "BUTT", "BoMB", "BoNE", "BoNK", "BooB", "CRAP", "CoCK", "DAMN",
    "DUMB", "DiCK", "DiLF", "DoNG", "DoRK", "FUCK", "FooL", "HATE", "HELL", "KiLL", "LMAo", "NUDE",
    "NUTS", "PAiN", "PoRN", "SEXY", "SHiT", "SLUT", "SUCK", "TiTS", "WANG", "ooPS", "Kink", "Smut",
    "Lewd", "Lust", "nsfw", "bred", "hump", "bare", "naky", "bite", "bttm", "cake", "rump", "thic",
];

const HOLLOW_KNIGHT: &[&str] = &[
    "DUNG", "GRiM", "NEST", "NiTE", "NoSK", "PALE", "PATH", "SHAW", "STAG", "SiLK", "SoAR", "SoNG",
    "SoUL", "TEAR", "WYRM", "ZoTE", "GRUB", "GRUZ",
];

const STARGATE: &[&str] = &["SG1", "JAFA", "KREE", "TEAL", "ZATS", "REPL", "STAR"];

const CRYPTO: &[&str] = &["BULL", "MooN", "PUMP", "FoMo", "SAFU", "WAGM", "GAiN"];

const ANIME: &[&str] = &["KiRA", "SoMA", "WEEB", "BAKA", "NANi", "SENP"];

const ENGINEERING: &[&str] = &["SHiP"];

const BANKS: &[&[&str]] = &[
    SELF,
    FURRY,
    POSITIVE,
    ROAST,
    HOLLOW_KNIGHT,
    STARGATE,
    CRYPTO,
    ANIME,
    ENGINEERING,
];

// ============================================================
// LEET ENGINE
// ============================================================

/// Substitutions, applied case-insensitively. The first character of a word is
/// never substituted, so a match always opens with a real letter.
const LEET: &[(u8, u8)] = &[
    (b'a', b'4'),
    (b'b', b'8'),
    (b'e', b'3'),
    (b'g', b'6'),
    (b'i', b'1'),
    (b's', b'5'),
    (b't', b'7'),
    (b'z', b'2'),
];

fn leet_expand(word: &str) -> Vec<String> {
    let mut variants = vec![String::new()];
    for (i, ch) in word.chars().enumerate() {
        let sub = if i == 0 {
            None
        } else {
            let lower = ch.to_ascii_lowercase() as u8;
            LEET.iter()
                .find(|(from, _)| *from == lower)
                .map(|(_, to)| *to as char)
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

// ============================================================
// CASE FOLDING
// ============================================================

/// Canonical form for case-insensitive comparison.
///
/// Note this deliberately folds *up*, and the result is NOT itself base58:
/// `i` folds to `I` and `o` folds to `O`, neither of which is in the alphabet.
/// That is fine because both the pattern and the address get the same treatment,
/// but it is why you must never fold base58 *down* to canonicalize: `L` would
/// become `l`, which is not a base58 character either. Consistency is all that
/// matters, and `1` (a digit) never collides with `i` under this fold.
#[inline]
fn fold(b: u8, case_sensitive: bool) -> u8 {
    if case_sensitive {
        b
    } else {
        b.to_ascii_uppercase()
    }
}

// ============================================================
// CONFIG
// ============================================================

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Side {
    Prefix,
    Suffix,
}

impl Side {
    pub fn as_str(self) -> &'static str {
        match self {
            Side::Prefix => "prefix",
            Side::Suffix => "suffix",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sides {
    Prefix,
    Suffix,
    Both,
}

impl Sides {
    fn includes(self, s: Side) -> bool {
        matches!(
            (self, s),
            (Sides::Both, _) | (Sides::Prefix, Side::Prefix) | (Sides::Suffix, Side::Suffix)
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MatchConfig {
    pub min_len: usize,
    pub case_sensitive: bool,
    pub sides: Sides,
    pub leet: bool,
    pub all_four_letter_words: bool,
}

impl Default for MatchConfig {
    fn default() -> Self {
        Self {
            min_len: 3,
            case_sensitive: false,
            sides: Sides::Both,
            leet: true,
            all_four_letter_words: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatternSource {
    Curated,
    AllFourLetterWords,
}

/// A matched pattern. `pattern` is the configured leet variant, `word` is the
/// original form before leet substitutions, and `matched_text` preserves the
/// exact capitalization in the address.
#[derive(Clone, Debug)]
pub struct Hit {
    pub pattern: String,
    pub word: String,
    pub matched_text: String,
    pub source: PatternSource,
    pub side: Side,
    pub len: usize,
}

// ============================================================
// MATCHER
// ============================================================

#[derive(Clone)]
struct PatternEntry {
    pattern: String,
    word: String,
    source: PatternSource,
}

pub struct Matcher {
    prefixes: HashMap<Vec<u8>, PatternEntry>,
    suffixes: HashMap<Vec<u8>, PatternEntry>,
    /// Distinct pattern lengths, longest first, so the best match wins.
    lens: Vec<usize>,
    case_sensitive: bool,
}

fn add_word(
    base58_word: &str,
    display_word: &str,
    source: PatternSource,
    config: &MatchConfig,
    prefixes: &mut HashMap<Vec<u8>, PatternEntry>,
    suffixes: &mut HashMap<Vec<u8>, PatternEntry>,
) {
    if base58_word.len() < config.min_len {
        return;
    }
    let variants = if config.leet {
        leet_expand(base58_word)
    } else {
        vec![base58_word.to_string()]
    };
    for variant in variants {
        let key: Vec<u8> = variant
            .bytes()
            .map(|byte| fold(byte, config.case_sensitive))
            .collect();
        let entry = PatternEntry {
            pattern: variant,
            word: display_word.to_string(),
            source,
        };
        if config.sides.includes(Side::Prefix) {
            prefixes.entry(key.clone()).or_insert_with(|| entry.clone());
        }
        if config.sides.includes(Side::Suffix) {
            suffixes.entry(key).or_insert(entry);
        }
    }
}

fn create_hit(entry: &PatternEntry, matched_text: &str, side: Side) -> Hit {
    Hit {
        pattern: entry.pattern.clone(),
        word: entry.word.clone(),
        matched_text: matched_text.to_string(),
        source: entry.source,
        side,
        len: entry.pattern.len(),
    }
}

fn base58_safe_word(word: &str) -> String {
    word.bytes()
        .map(|byte| match byte.to_ascii_uppercase() {
            b'I' => 'i',
            b'O' => 'o',
            byte => byte as char,
        })
        .collect()
}

impl Matcher {
    pub fn new(cfg: &MatchConfig) -> Self {
        let mut prefixes = HashMap::new();
        let mut suffixes = HashMap::new();

        for bank in BANKS {
            for word in *bank {
                add_word(
                    word,
                    word,
                    PatternSource::Curated,
                    cfg,
                    &mut prefixes,
                    &mut suffixes,
                );
            }
        }
        if cfg.all_four_letter_words {
            for word in ALL_FOUR_LETTER_WORDS.lines() {
                let base58_word = base58_safe_word(word);
                let display_word = word.to_ascii_uppercase();
                add_word(
                    &base58_word,
                    &display_word,
                    PatternSource::AllFourLetterWords,
                    cfg,
                    &mut prefixes,
                    &mut suffixes,
                );
            }
        }

        let mut lens: Vec<usize> = prefixes
            .keys()
            .chain(suffixes.keys())
            .map(|k| k.len())
            .collect();
        lens.sort_unstable_by(|a, b| b.cmp(a));
        lens.dedup();

        Self {
            prefixes,
            suffixes,
            lens,
            case_sensitive: cfg.case_sensitive,
        }
    }

    /// Longest match wins; on a tie, prefix is reported before suffix.
    /// Three-character patterns may occupy either window inside the first or
    /// last four address characters.
    pub fn best(&self, address: &str) -> Option<Hit> {
        let bytes: Vec<u8> = address
            .bytes()
            .map(|b| fold(b, self.case_sensitive))
            .collect();
        for &len in &self.lens {
            if bytes.len() < len {
                continue;
            }
            if let Some(p) = self.prefixes.get(&bytes[..len]) {
                return Some(create_hit(p, &address[..len], Side::Prefix));
            }
            if len == 3 && bytes.len() >= 4 {
                if let Some(p) = self.prefixes.get(&bytes[1..4]) {
                    return Some(create_hit(p, &address[1..4], Side::Prefix));
                }
            }
            if let Some(p) = self.suffixes.get(&bytes[bytes.len() - len..]) {
                return Some(create_hit(p, &address[address.len() - len..], Side::Suffix));
            }
            if len == 3 && bytes.len() >= 4 {
                if let Some(p) = self.suffixes.get(&bytes[bytes.len() - 4..bytes.len() - 1]) {
                    return Some(create_hit(
                        p,
                        &address[address.len() - 4..address.len() - 1],
                        Side::Suffix,
                    ));
                }
            }
        }
        None
    }

    pub fn pattern_count(&self) -> usize {
        self.prefixes.len() + self.suffixes.len()
    }

    #[cfg(test)]
    pub fn distinct_lengths(&self) -> &[usize] {
        &self.lens
    }

    /// Expected number of derivations per hit, summing the probability of each
    /// checked window. Overlap between matches is small enough to ignore here.
    #[cfg(test)]
    pub fn expected_attempts(&self) -> f64 {
        let mut p = 0.0;
        for key in self.prefixes.keys() {
            p += self.p_prefix(key);
            if key.len() == 3 {
                p += self.p_suffix(key);
            }
        }
        for key in self.suffixes.keys() {
            p += self.p_suffix(key);
            if key.len() == 3 {
                p += self.p_suffix(key);
            }
        }
        if p <= 0.0 { f64::INFINITY } else { 1.0 / p }
    }

    /// Expected derivations per hit counting only patterns of `len` or longer.
    #[cfg(test)]
    pub fn expected_attempts_at_least(&self, len: usize) -> f64 {
        let mut p = 0.0;
        for key in self.prefixes.keys().filter(|k| k.len() >= len) {
            p += self.p_prefix(key);
            if key.len() == 3 {
                p += self.p_suffix(key);
            }
        }
        for key in self.suffixes.keys().filter(|k| k.len() >= len) {
            p += self.p_suffix(key);
            if key.len() == 3 {
                p += self.p_suffix(key);
            }
        }
        if p <= 0.0 { f64::INFINITY } else { 1.0 / p }
    }

    #[cfg(test)]
    fn p_suffix(&self, key: &[u8]) -> f64 {
        key.iter()
            .map(|&b| self.class_size(b) as f64 / 58.0)
            .product()
    }

    #[cfg(test)]
    fn p_prefix(&self, key: &[u8]) -> f64 {
        let mut p = p_first_folded(key[0], self.case_sensitive);
        for &b in &key[1..] {
            p *= self.class_size(b) as f64 / 58.0;
        }
        p
    }

    /// How many base58 characters share this folded value.
    #[cfg(test)]
    fn class_size(&self, folded: u8) -> usize {
        BS58_ALPHABET
            .iter()
            .filter(|&&c| fold(c, self.case_sensitive) == folded)
            .count()
    }
}

// ============================================================
// BASE58 FIRST-CHARACTER DISTRIBUTION
// ============================================================

/// 2^256 / 58^43. A 32-byte key encodes to 44 base58 characters when its value
/// is at least 58^43, which is 1 - 1/RATIO of the keyspace (94.196%).
#[cfg(test)]
const RATIO: f64 = 17.229_598_878_382_743;

/// Exact P(address starts with this base58 character).
///
/// A 44-character address has first-character index `floor(N / 58^43)`, which
/// spans 1..=17, so only `2`-`9`, `A`-`H` and `J` are reachable that way. Every
/// other opener requires a 43-character address, which is the 5.804% of the
/// keyspace below 58^43 and is spread evenly over all 58 characters.
///
/// `1` is the trap: it looks like a cheap digit but index 0 is unreachable for a
/// 44-character address, so `1` is as rare as `K`-`Z` at 0.10%.
#[cfg(test)]
fn p_first_exact(c: u8) -> f64 {
    let i = match BS58_ALPHABET.iter().position(|&x| x == c) {
        Some(i) => i,
        None => return 0.0,
    };
    let p44 = if i == 0 {
        0.0
    } else if i <= 16 {
        1.0 / RATIO
    } else if i == 17 {
        (RATIO - 17.0) / RATIO
    } else {
        0.0
    };
    let p43 = 1.0 / (58.0 * RATIO);
    p44 + p43
}

/// P(address starts with any character folding to `folded`).
#[cfg(test)]
fn p_first_folded(folded: u8, case_sensitive: bool) -> f64 {
    BS58_ALPHABET
        .iter()
        .filter(|&&c| fold(c, case_sensitive) == folded)
        .map(|&c| p_first_exact(c))
        .sum()
}

// ============================================================
// TESTS
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn all_words() -> Vec<&'static str> {
        BANKS.iter().flat_map(|b| b.iter().copied()).collect()
    }

    #[test]
    fn every_word_is_base58_and_well_formed() {
        let alpha: std::collections::HashSet<u8> = BS58_ALPHABET.iter().copied().collect();
        for w in all_words() {
            assert!(
                (3..=4).contains(&w.len()),
                "{w:?} has length {}, expected 3 or 4",
                w.len()
            );
            for b in w.bytes() {
                assert!(alpha.contains(&b), "{w:?} contains non-base58 byte {b:?}");
            }
        }
    }

    #[test]
    fn no_duplicate_words_ignoring_case() {
        let mut seen = HashMap::new();
        for w in all_words() {
            let key = w.to_ascii_uppercase();
            if let Some(prev) = seen.insert(key.clone(), w) {
                panic!("{w:?} duplicates {prev:?} (case-insensitively)");
            }
        }
    }

    #[test]
    fn full_four_letter_dictionary_is_valid_and_disabled_by_default() {
        let words: Vec<&str> = ALL_FOUR_LETTER_WORDS.lines().collect();
        assert_eq!(words.len(), 5_006);
        for word in words {
            assert_eq!(word.len(), 4, "{word:?}");
            assert!(word.bytes().all(|byte| byte.is_ascii_alphabetic()));
            let normalized = base58_safe_word(word);
            assert!(
                normalized.bytes().all(|byte| BS58_ALPHABET.contains(&byte)),
                "{word:?} normalized to invalid base58 {normalized:?}"
            );
        }

        let default_matcher = Matcher::new(&MatchConfig::default());
        assert!(default_matcher.best("ABACxxxxxxxx").is_none());

        let dictionary_matcher = Matcher::new(&MatchConfig {
            all_four_letter_words: true,
            ..Default::default()
        });
        let hit = dictionary_matcher.best("ABACxxxxxxxx").unwrap();
        assert_eq!(hit.pattern, "ABAC");
        assert_eq!(hit.word, "ABAC");
        assert_eq!(hit.source, PatternSource::AllFourLetterWords);
        assert_eq!(hit.len, 4);
        assert_eq!(hit.side, Side::Prefix);

        let hit = dictionary_matcher.best("A837xxxxxxxx").unwrap();
        assert_eq!(hit.pattern, "A837");
        assert_eq!(hit.matched_text, "A837");
        assert_eq!(hit.word, "ABET");
        assert_eq!(hit.source, PatternSource::AllFourLetterWords);
    }

    #[test]
    fn first_char_distribution_sums_to_one() {
        let total: f64 = BS58_ALPHABET.iter().map(|&c| p_first_exact(c)).sum();
        assert!((total - 1.0).abs() < 1e-12, "sums to {total}");
    }

    #[test]
    fn one_is_a_rare_opener_not_a_cheap_digit() {
        // The whole point of the RATIO table: '1' is not in the cheap set.
        assert!((p_first_exact(b'2') - 0.0590403).abs() < 1e-6);
        assert!((p_first_exact(b'H') - 0.0590403).abs() < 1e-6);
        assert!((p_first_exact(b'J') - 0.0143265).abs() < 1e-6);
        assert!((p_first_exact(b'1') - 0.0010007).abs() < 1e-6);
        assert!((p_first_exact(b'K') - 0.0010007).abs() < 1e-6);
        assert!(p_first_exact(b'1') < p_first_exact(b'2') / 50.0);
    }

    #[test]
    fn leet_locks_first_char_and_is_case_insensitive() {
        let v = leet_expand("BEST");
        assert_eq!(v.len(), 8, "{v:?}");
        assert!(v.contains(&"BEST".to_string()));
        assert!(v.contains(&"B357".to_string()));
        assert!(
            !v.iter().any(|s| s.starts_with('8')),
            "first char substituted"
        );

        // lowercase input must still expand
        let v = leet_expand("Paws");
        assert_eq!(v.len(), 4, "{v:?}");
        assert!(v.contains(&"P4w5".to_string()));

        // nothing substitutable after the first character
        assert_eq!(leet_expand("Bun"), vec!["Bun".to_string()]);
    }

    #[test]
    fn matches_prefix_and_suffix_case_insensitively() {
        let m = Matcher::new(&MatchConfig::default());

        // GoLD as a suffix, in a different case than the bank
        let hit = m
            .best("HxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxGold")
            .unwrap();
        assert_eq!(hit.side, Side::Suffix);
        assert_eq!(hit.len, 4);
        assert_eq!(hit.pattern, "GoLD", "reports bank capitalization");
        assert_eq!(hit.matched_text, "Gold", "reports address capitalization");

        // BEST as a prefix
        let hit = m
            .best("bestxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
            .unwrap();
        assert_eq!(hit.side, Side::Prefix);
        assert_eq!(hit.len, 4);
        assert_eq!(hit.matched_text, "best");

        // a leet form
        let hit = m
            .best("B357xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
            .unwrap();
        assert_eq!(hit.side, Side::Prefix);
        assert_eq!(hit.pattern, "B357");
        assert_eq!(hit.word, "BEST");
        assert_eq!(hit.source, PatternSource::Curated);
    }

    #[test]
    fn three_character_patterns_match_both_windows_inside_each_edge() {
        let matcher = Matcher::new(&MatchConfig::default());

        let hit = matcher.best("xJAGxxxxxxxx").unwrap();
        assert_eq!(hit.pattern, "JAG");
        assert_eq!(hit.side, Side::Prefix);

        let hit = matcher.best("xFurxxxxxxxx").unwrap();
        assert_eq!(hit.pattern, "Fur");
        assert_eq!(hit.side, Side::Prefix);

        let hit = matcher.best("xxxxxxxxFurx").unwrap();
        assert_eq!(hit.pattern, "Fur");
        assert_eq!(hit.side, Side::Suffix);

        assert!(matcher.best("xxFurxxxxxx").is_none());
    }

    #[test]
    fn prefers_the_longest_match() {
        let m = Matcher::new(&MatchConfig::default());
        let hit = m
            .best("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxFur")
            .unwrap();
        assert_eq!(hit.len, 3);
        let hit = m
            .best("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxFurr")
            .unwrap();
        assert_eq!(hit.len, 4, "4-char Furr must win over 3-char Fur");
    }

    #[test]
    fn no_match_returns_none() {
        let m = Matcher::new(&MatchConfig::default());
        assert!(
            m.best("QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ")
                .is_none()
        );
    }

    #[test]
    fn case_sensitive_mode_is_stricter() {
        let ci = Matcher::new(&MatchConfig::default());
        let cs = Matcher::new(&MatchConfig {
            case_sensitive: true,
            ..Default::default()
        });
        assert!(cs.expected_attempts() > ci.expected_attempts());
        // wrong case must not match under case-sensitive
        let addr = "GOLDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        assert!(ci.best(addr).is_some());
        assert!(cs.best(addr).is_none());
    }

    #[test]
    fn min_len_and_sides_are_respected() {
        let four_only = Matcher::new(&MatchConfig {
            min_len: 4,
            ..Default::default()
        });
        assert_eq!(four_only.distinct_lengths(), &[4]);
        assert!(
            four_only
                .best("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxFur")
                .is_none()
        );

        let sfx = Matcher::new(&MatchConfig {
            sides: Sides::Suffix,
            ..Default::default()
        });
        assert!(
            sfx.best("bestxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
                .is_none()
        );
        assert!(
            sfx.best("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxBEST")
                .is_some()
        );
    }

    #[test]
    fn longer_patterns_are_rarer() {
        let m = Matcher::new(&MatchConfig::default());
        assert!(m.expected_attempts_at_least(4) > m.expected_attempts_at_least(3));
        assert!(m.expected_attempts_at_least(3) >= m.expected_attempts());
    }
}
