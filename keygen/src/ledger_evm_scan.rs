//! Ledger EVM vanity-address search and saved-address search.
//!
//! The Ledger exports the extended public key at `m/44'/60'/0'/0` once. The
//! host then performs non-hardened BIP-32 public derivation for successive `N`
//! in `m/44'/60'/0'/0/N`. Private keys never leave the Ledger. The extended
//! public key can reveal this account's private keys if it is ever combined
//! with any derived private key, so this tool does not save it.

mod ledger_vanity;
mod patterns;

use {
    clap::{Arg, Command, value_parser},
    hmac::{Hmac, Mac},
    ledger_vanity::{
        address_file::MAX_INDEX,
        hid::{LedgerDevice, list_devices},
        query::{AddressScheme, add_query_arguments, run_query_if_requested},
    },
    libsecp256k1::{PublicKey, PublicKeyFormat, SecretKey},
    patterns::Alphabet,
    rayon::prelude::*,
    sha2::Sha512,
    sha3::{Digest, Keccak256},
    std::{
        cmp::min,
        fs::{self, File, OpenOptions},
        io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
        path::{Path, PathBuf},
        time::Instant,
    },
};

const HARDENED: u32 = 1 << 31;
const GET_PUBLIC_ADDRESS: u8 = 0x02;
const P1_NON_CONFIRM: u8 = 0x00;
const P2_NO_CHAIN_CODE: u8 = 0x00;
const P2_CHAIN_CODE: u8 = 0x01;
const DERIVATION_BATCH: u32 = 65_536;
const PROGRESS_EVERY: u64 = 10_000_000;
const MATCH_FILE_HEADER: &str = "n\tlayout\tphrase\tsafe_display\taddress\tderivation_path";

type HmacSha512 = Hmac<Sha512>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SafeLayout {
    FourAndFour,
    ThreeAndSix,
    FourAndSix,
}

impl SafeLayout {
    fn name(self) -> &'static str {
        match self {
            Self::FourAndFour => "4+4",
            Self::ThreeAndSix => "3+6",
            Self::FourAndSix => "4+6",
        }
    }

    fn prefix_length(self) -> usize {
        match self {
            Self::FourAndFour => 4,
            Self::ThreeAndSix => 3,
            Self::FourAndSix => 4,
        }
    }

    fn suffix_length(self) -> usize {
        match self {
            Self::FourAndFour => 4,
            Self::ThreeAndSix => 6,
            Self::FourAndSix => 6,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HexWord {
    word: &'static str,
    encoded: &'static str,
    value: u32,
}

const THREE_CHARACTER_WORDS: &[HexWord] = &[
    HexWord {
        word: "ACE",
        encoded: "ACE",
        value: 0xace,
    },
    HexWord {
        word: "BEE",
        encoded: "BEE",
        value: 0xbee,
    },
    HexWord {
        word: "DAD",
        encoded: "DAD",
        value: 0xdad,
    },
    HexWord {
        word: "DIE",
        encoded: "D1E",
        value: 0xd1e,
    },
    HexWord {
        word: "FOE",
        encoded: "F0E",
        value: 0xf0e,
    },
    HexWord {
        word: "GOD",
        encoded: "60D",
        value: 0x60d,
    },
    HexWord {
        word: "ICE",
        encoded: "1CE",
        value: 0x1ce,
    },
    HexWord {
        word: "ODD",
        encoded: "0DD",
        value: 0x0dd,
    },
    HexWord {
        word: "SAD",
        encoded: "5AD",
        value: 0x5ad,
    },
    HexWord {
        word: "SEA",
        encoded: "5EA",
        value: 0x5ea,
    },
    HexWord {
        word: "SOS",
        encoded: "505",
        value: 0x505,
    },
];

const FOUR_CHARACTER_WORDS: &[HexWord] = &[
    HexWord {
        word: "ABLE",
        encoded: "AB1E",
        value: 0xab1e,
    },
    HexWord {
        word: "ACED",
        encoded: "ACED",
        value: 0xaced,
    },
    HexWord {
        word: "BASE",
        encoded: "BA5E",
        value: 0xba5e,
    },
    HexWord {
        word: "BEST",
        encoded: "BE57",
        value: 0xbe57,
    },
    HexWord {
        word: "BIAS",
        encoded: "B1A5",
        value: 0xb1a5,
    },
    HexWord {
        word: "BOLD",
        encoded: "B01D",
        value: 0xb01d,
    },
    HexWord {
        word: "BOSS",
        encoded: "B055",
        value: 0xb055,
    },
    HexWord {
        word: "CASE",
        encoded: "CA5E",
        value: 0xca5e,
    },
    HexWord {
        word: "COLD",
        encoded: "C01D",
        value: 0xc01d,
    },
    HexWord {
        word: "COOL",
        encoded: "C001",
        value: 0xc001,
    },
    HexWord {
        word: "DEAF",
        encoded: "DEAF",
        value: 0xdeaf,
    },
    HexWord {
        word: "DEED",
        encoded: "DEED",
        value: 0xdeed,
    },
    HexWord {
        word: "DICE",
        encoded: "D1CE",
        value: 0xd1ce,
    },
    HexWord {
        word: "EASE",
        encoded: "EA5E",
        value: 0xea5e,
    },
    HexWord {
        word: "FACE",
        encoded: "FACE",
        value: 0xface,
    },
    HexWord {
        word: "FADE",
        encoded: "FADE",
        value: 0xfade,
    },
    HexWord {
        word: "FAST",
        encoded: "FA57",
        value: 0xfa57,
    },
    HexWord {
        word: "FATE",
        encoded: "FA7E",
        value: 0xfa7e,
    },
    HexWord {
        word: "FEEL",
        encoded: "FEE1",
        value: 0xfee1,
    },
    HexWord {
        word: "IDEA",
        encoded: "1DEA",
        value: 0x1dea,
    },
    HexWord {
        word: "IDLE",
        encoded: "1D1E",
        value: 0x1d1e,
    },
    HexWord {
        word: "LESS",
        encoded: "1E55",
        value: 0x1e55,
    },
    HexWord {
        word: "LIFE",
        encoded: "11FE",
        value: 0x11fe,
    },
    HexWord {
        word: "LOSS",
        encoded: "1055",
        value: 0x1055,
    },
    HexWord {
        word: "LOST",
        encoded: "1057",
        value: 0x1057,
    },
    HexWord {
        word: "SAFE",
        encoded: "5AFE",
        value: 0x5afe,
    },
    HexWord {
        word: "SEED",
        encoded: "5EED",
        value: 0x5eed,
    },
    HexWord {
        word: "SELF",
        encoded: "5E1F",
        value: 0x5e1f,
    },
    HexWord {
        word: "SOLE",
        encoded: "501E",
        value: 0x501e,
    },
    HexWord {
        word: "SOLO",
        encoded: "5010",
        value: 0x5010,
    },
];

const SIX_CHARACTER_WORDS: &[HexWord] = &[
    HexWord {
        word: "SOLACE",
        encoded: "501ACE",
        value: 0x501ace,
    },
    HexWord {
        word: "CLOSED",
        encoded: "C105ED",
        value: 0xc105ed,
    },
    HexWord {
        word: "FAILED",
        encoded: "FA11ED",
        value: 0xfa11ed,
    },
    HexWord {
        word: "FACADE",
        encoded: "FACADE",
        value: 0xfacade,
    },
    HexWord {
        word: "DEFILE",
        encoded: "DEF11E",
        value: 0xdef11e,
    },
    HexWord {
        word: "BIASED",
        encoded: "B1A5ED",
        value: 0xb1a5ed,
    },
    HexWord {
        word: "FOSSIL",
        encoded: "F05511",
        value: 0xf05511,
    },
    HexWord {
        word: "DECADE",
        encoded: "DECADE",
        value: 0xdecade,
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SpecialTarget {
    phrase: &'static str,
    encoded: &'static str,
    value: u32,
}

const SPECIAL_FOUR_AND_FOUR_TARGETS: &[SpecialTarget] = &[
    SpecialTarget {
        phrase: "OBSESSED",
        encoded: "0B5E55ED",
        value: 0x0b5e55ed,
    },
    SpecialTarget {
        phrase: "ADDICTED",
        encoded: "ADD1C7ED",
        value: 0xadd1c7ed,
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SafeMatch {
    WordPair {
        layout: SafeLayout,
        prefix: HexWord,
        suffix: HexWord,
    },
    Special(SpecialTarget),
}

impl SafeMatch {
    fn layout(self) -> SafeLayout {
        match self {
            Self::WordPair { layout, .. } => layout,
            Self::Special(_) => SafeLayout::FourAndFour,
        }
    }

    fn phrase(self) -> String {
        match self {
            Self::WordPair { prefix, suffix, .. } => {
                format!("{} / {}", prefix.word, suffix.word)
            }
            Self::Special(target) => target.phrase.to_string(),
        }
    }

    fn safe_display(self, address: &str) -> String {
        let layout = self.layout();
        let prefix_end = 2 + layout.prefix_length();
        let suffix_start = address.len() - layout.suffix_length();
        format!(
            "0x{}...{}",
            &address[2..prefix_end],
            &address[suffix_start..]
        )
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct AddressMatches {
    prefix_three: Option<u8>,
    prefix_four: Option<u8>,
    suffix_four: Option<u8>,
    suffix_six: Option<u8>,
    special_bits: u8,
}

impl AddressMatches {
    fn count(self) -> u32 {
        u32::from(self.prefix_three.is_some() && self.suffix_six.is_some())
            + u32::from(self.prefix_four.is_some() && self.suffix_four.is_some())
            + u32::from(self.prefix_four.is_some() && self.suffix_six.is_some())
            + self.special_bits.count_ones()
    }

    fn into_matches(self) -> Vec<SafeMatch> {
        let mut matches = Vec::with_capacity(self.count() as usize);
        if let (Some(prefix), Some(suffix)) = (self.prefix_three, self.suffix_six) {
            matches.push(SafeMatch::WordPair {
                layout: SafeLayout::ThreeAndSix,
                prefix: THREE_CHARACTER_WORDS[usize::from(prefix)],
                suffix: SIX_CHARACTER_WORDS[usize::from(suffix)],
            });
        }
        if let (Some(prefix), Some(suffix)) = (self.prefix_four, self.suffix_four) {
            matches.push(SafeMatch::WordPair {
                layout: SafeLayout::FourAndFour,
                prefix: FOUR_CHARACTER_WORDS[usize::from(prefix)],
                suffix: FOUR_CHARACTER_WORDS[usize::from(suffix)],
            });
        }
        if let (Some(prefix), Some(suffix)) = (self.prefix_four, self.suffix_six) {
            matches.push(SafeMatch::WordPair {
                layout: SafeLayout::FourAndSix,
                prefix: FOUR_CHARACTER_WORDS[usize::from(prefix)],
                suffix: SIX_CHARACTER_WORDS[usize::from(suffix)],
            });
        }
        for (index, target) in SPECIAL_FOUR_AND_FOUR_TARGETS.iter().enumerate() {
            if self.special_bits & (1 << index) != 0 {
                matches.push(SafeMatch::Special(*target));
            }
        }
        matches
    }
}

fn matching_targets(address: &[u8; 20]) -> AddressMatches {
    let prefix_three = u16::from(address[0]) << 4 | u16::from(address[1] >> 4);
    let prefix_four = u16::from_be_bytes([address[0], address[1]]);
    let suffix_four = u16::from_be_bytes([address[18], address[19]]);
    let suffix_six = u32::from_be_bytes([0, address[17], address[18], address[19]]);
    let special_value = u32::from(prefix_four) << 16 | u32::from(suffix_four);
    let special_bits = SPECIAL_FOUR_AND_FOUR_TARGETS
        .iter()
        .enumerate()
        .filter(|(_, target)| target.value == special_value)
        .fold(0, |bits, (index, _)| bits | (1 << index));

    AddressMatches {
        prefix_three: find_three_character_word(u32::from(prefix_three)),
        prefix_four: find_four_character_word(u32::from(prefix_four)),
        suffix_four: find_four_character_word(u32::from(suffix_four)),
        suffix_six: find_six_character_word(suffix_six),
        special_bits,
    }
}

fn find_three_character_word(value: u32) -> Option<u8> {
    match value {
        0xace => Some(0),
        0xbee => Some(1),
        0xdad => Some(2),
        0xd1e => Some(3),
        0xf0e => Some(4),
        0x60d => Some(5),
        0x1ce => Some(6),
        0x0dd => Some(7),
        0x5ad => Some(8),
        0x5ea => Some(9),
        0x505 => Some(10),
        _ => None,
    }
}

fn find_four_character_word(value: u32) -> Option<u8> {
    match value {
        0xab1e => Some(0),
        0xaced => Some(1),
        0xba5e => Some(2),
        0xbe57 => Some(3),
        0xb1a5 => Some(4),
        0xb01d => Some(5),
        0xb055 => Some(6),
        0xca5e => Some(7),
        0xc01d => Some(8),
        0xc001 => Some(9),
        0xdeaf => Some(10),
        0xdeed => Some(11),
        0xd1ce => Some(12),
        0xea5e => Some(13),
        0xface => Some(14),
        0xfade => Some(15),
        0xfa57 => Some(16),
        0xfa7e => Some(17),
        0xfee1 => Some(18),
        0x1dea => Some(19),
        0x1d1e => Some(20),
        0x1e55 => Some(21),
        0x11fe => Some(22),
        0x1055 => Some(23),
        0x1057 => Some(24),
        0x5afe => Some(25),
        0x5eed => Some(26),
        0x5e1f => Some(27),
        0x501e => Some(28),
        0x5010 => Some(29),
        _ => None,
    }
}

fn find_six_character_word(value: u32) -> Option<u8> {
    match value {
        0x501ace => Some(0),
        0xc105ed => Some(1),
        0xfa11ed => Some(2),
        0xfacade => Some(3),
        0xdef11e => Some(4),
        0xb1a5ed => Some(5),
        0xf05511 => Some(6),
        0xdecade => Some(7),
        _ => None,
    }
}

struct MatchFiles {
    output: BufWriter<File>,
    matches_path: PathBuf,
    checkpoint_path: PathBuf,
}

impl MatchFiles {
    fn open(
        directory: &Path,
        fingerprint: &str,
    ) -> Result<(Self, u32), Box<dyn std::error::Error>> {
        let matches_path = directory.join(format!("evm-matches-{fingerprint}.txt"));
        let checkpoint_path = directory.join(format!("evm-next-{fingerprint}.txt"));
        let files_exist = (matches_path.exists(), checkpoint_path.exists());
        let next_index = match files_exist {
            (false, false) => {
                let mut output = OpenOptions::new()
                    .create_new(true)
                    .append(true)
                    .open(&matches_path)?;
                writeln!(output, "{MATCH_FILE_HEADER}")?;
                output.flush()?;
                save_checkpoint(&checkpoint_path, 1)?;
                1
            }
            (true, true) => {
                verify_match_file(&matches_path)?;
                read_checkpoint(&checkpoint_path)?
            }
            (true, false) => {
                return Err(format!(
                    "{} exists but {} does not; restore the checkpoint or move the match file",
                    matches_path.display(),
                    checkpoint_path.display()
                )
                .into());
            }
            (false, true) => {
                return Err(format!(
                    "{} exists but {} does not; restore the match file or move the checkpoint",
                    checkpoint_path.display(),
                    matches_path.display()
                )
                .into());
            }
        };
        let output = BufWriter::new(OpenOptions::new().append(true).open(&matches_path)?);
        Ok((
            Self {
                output,
                matches_path,
                checkpoint_path,
            },
            next_index,
        ))
    }

    fn record(&mut self, index: u32, target: SafeMatch, address: &str) -> std::io::Result<()> {
        writeln!(
            self.output,
            "{}\t{}\t{}\t{}\t{}\t{}",
            index,
            target.layout().name(),
            target.phrase(),
            target.safe_display(address),
            address,
            EvmScheme::derivation_path(index),
        )
    }

    fn finish_batch(&mut self, next_index: u32) -> Result<(), Box<dyn std::error::Error>> {
        self.output.flush()?;
        save_checkpoint(&self.checkpoint_path, next_index)
    }
}

fn verify_match_file(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let length = file.metadata()?.len();
    if length == 0 {
        return Err(format!("{} is empty", path.display()).into());
    }
    file.seek(SeekFrom::End(-1))?;
    let mut final_byte = [0];
    file.read_exact(&mut final_byte)?;
    if final_byte[0] != b'\n' {
        return Err(format!("{} ends with an incomplete line", path.display()).into());
    }
    file.seek(SeekFrom::Start(0))?;
    let mut header = String::new();
    BufReader::new(file).read_line(&mut header)?;
    if header != format!("{MATCH_FILE_HEADER}\n") {
        return Err(format!("{} has an unexpected header", path.display()).into());
    }
    Ok(())
}

fn read_checkpoint(path: &Path) -> Result<u32, Box<dyn std::error::Error>> {
    let contents = fs::read_to_string(path)?;
    let encoded = contents
        .strip_suffix('\n')
        .ok_or_else(|| format!("{} does not end with a newline", path.display()))?;
    if encoded.contains('\n') {
        return Err(format!("{} contains more than one line", path.display()).into());
    }
    let next_index: u32 = encoded
        .parse()
        .map_err(|error| format!("{} is not a derivation index: {error}", path.display()))?;
    if !(1..=MAX_INDEX).contains(&next_index) {
        return Err(format!(
            "{} contains out-of-range index {next_index}",
            path.display()
        )
        .into());
    }
    Ok(next_index)
}

fn save_checkpoint(path: &Path, next_index: u32) -> Result<(), Box<dyn std::error::Error>> {
    let temporary_path = path.with_extension("tmp");
    fs::write(&temporary_path, format!("{next_index}\n"))?;
    fs::rename(temporary_path, path)?;
    Ok(())
}

struct EvmScheme;

impl AddressScheme for EvmScheme {
    fn chain_name() -> &'static str {
        "EVM"
    }

    fn file_prefix() -> &'static str {
        "evm"
    }

    fn alphabet() -> Alphabet {
        Alphabet::Hex
    }

    fn validate_address(address: &str) -> Result<(), String> {
        let encoded = address
            .strip_prefix("0x")
            .ok_or_else(|| "address must start with 0x".to_string())?;
        if encoded.len() != 40 {
            return Err(format!(
                "address has {} hex characters, expected 40",
                encoded.len()
            ));
        }
        let decoded = hex::decode(encoded).map_err(|error| error.to_string())?;
        let canonical = checksum_address(decoded.as_slice().try_into().unwrap());
        if address != canonical {
            return Err(format!("EIP-55 form is {canonical}"));
        }
        Ok(())
    }

    fn matching_text(address: &str) -> &str {
        address.strip_prefix("0x").expect("validated EVM address")
    }

    fn shortened_address(address: &str) -> String {
        format!("0x{}...{}", &address[2..6], &address[address.len() - 4..])
    }

    fn derivation_path(index: u32) -> String {
        format!("m/44'/60'/0'/0/{index}")
    }
}

#[derive(Clone)]
struct ExtendedPublicKey {
    public_key: PublicKey,
    chain_code: [u8; 32],
}

impl ExtendedPublicKey {
    fn address_at(&self, index: u32) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        Ok(checksum_address(&self.raw_address_at(index)?))
    }

    fn raw_address_at(
        &self,
        index: u32,
    ) -> Result<[u8; 20], Box<dyn std::error::Error + Send + Sync>> {
        if index >= MAX_INDEX {
            return Err(format!("index {index} is hardened").into());
        }

        let mut data = [0u8; 37];
        data[..33].copy_from_slice(&self.public_key.serialize_compressed());
        data[33..].copy_from_slice(&index.to_be_bytes());
        let mut hmac = HmacSha512::new_from_slice(&self.chain_code)
            .expect("HMAC accepts every chain-code length");
        hmac.update(&data);
        let digest = hmac.finalize().into_bytes();
        let tweak = SecretKey::parse_slice(&digest[..32]).map_err(|error| {
            format!("BIP-32 produced an invalid scalar at index {index}: {error:?}")
        })?;
        let mut child = self.public_key;
        child.tweak_add_assign(&tweak).map_err(|error| {
            format!("BIP-32 produced an invalid child at index {index}: {error:?}")
        })?;
        Ok(raw_address_from_public_key(&child))
    }
}

struct EthereumPublicKeyResponse {
    public_key: PublicKey,
    address: String,
    chain_code: Option<[u8; 32]>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let command = Command::new("ledger-evm-vanity-scan")
        .about("Search standard EVM Ledger addresses for phrases visible in Safe")
        .arg(
            Arg::new("count")
                .long("count")
                .value_name("N")
                .takes_value(true)
                .value_parser(value_parser!(u64))
                .help("Stop after checking this many addresses (default: run until interrupted)"),
        )
        .arg(
            Arg::new("device")
                .long("device")
                .value_name("INDEX")
                .takes_value(true)
                .value_parser(value_parser!(usize))
                .default_value("0")
                .help("Which detected Ledger to use"),
        )
        .arg(
            Arg::new("expect_seed")
                .long("expect-seed")
                .value_name("ADDRESS")
                .takes_value(true)
                .help("Abort unless m/44'/60'/0'/0/0 has this address"),
        )
        .arg(
            Arg::new("bench")
                .long("bench")
                .value_name("N")
                .takes_value(true)
                .value_parser(value_parser!(u64))
                .help("Time N derivations and Safe target checks without writing a file"),
        )
        .arg(
            Arg::new("list_targets")
                .long("list-targets")
                .help("Print every configured Safe target and exit"),
        )
        .arg(
            Arg::new("dry_run")
                .long("dry-run")
                .help("Use a fixed fake extended public key instead of a Ledger"),
        )
        .arg(
            Arg::new("list_devices")
                .long("list-devices")
                .help("List detected Ledgers and exit"),
        );
    let matches = add_query_arguments(command).get_matches();

    if matches.is_present("list_devices") {
        return list_devices();
    }
    if matches.is_present("list_targets") {
        print_targets();
        return Ok(());
    }
    if run_query_if_requested::<EvmScheme>(&matches)? {
        return Ok(());
    }

    let device_index = *matches.get_one::<usize>("device").unwrap();
    let (extended_public_key, device_path) = if matches.is_present("dry_run") {
        (stub_extended_public_key(), "dry-run".to_string())
    } else {
        read_extended_public_key(device_index)?
    };
    let fingerprint = extended_public_key
        .address_at(0)
        .map_err(|error| -> Box<dyn std::error::Error> { error })?;
    if let Some(expected) = matches.get_one::<String>("expect_seed") {
        if expected != &fingerprint {
            return Err(format!(
                "seed fingerprint mismatch: device reports {fingerprint}, --expect-seed said {expected}"
            )
            .into());
        }
    }

    if let Some(count) = matches.get_one::<u64>("bench").copied() {
        return benchmark(&extended_public_key, count);
    }

    let current_directory = std::env::current_dir()?;
    let (mut match_files, mut index) = MatchFiles::open(&current_directory, &fingerprint)?;
    println!("Device:       {device_path}");
    println!("Fingerprint:  {fingerprint}   (m/44'/60'/0'/0/0)");
    println!("Match file:    {}", match_files.matches_path.display());
    println!("Checkpoint:    {}", match_files.checkpoint_path.display());
    println!(
        "Targets:       {} using 3+6, {} using 4+4, {} using 4+6, {} special 4+4",
        three_and_six_count(),
        four_and_four_count(),
        four_and_six_count(),
        SPECIAL_FOUR_AND_FOUR_TARGETS.len(),
    );
    println!("Next index:    {index}");
    println!();

    let limit = matches.get_one::<u64>("count").copied();
    let started = Instant::now();
    let mut done = 0u64;
    let mut hits = 0u64;
    let mut next_progress = PROGRESS_EVERY;
    while limit.is_none_or(|limit| done < limit) && index < MAX_INDEX {
        let remaining = limit.map_or(DERIVATION_BATCH as u64, |limit| limit - done);
        let batch_length = min(DERIVATION_BATCH as u64, remaining) as u32;
        let end = index.saturating_add(batch_length).min(MAX_INDEX);
        let addresses: Vec<_> = (index..end)
            .into_par_iter()
            .map(|child_index| {
                extended_public_key
                    .raw_address_at(child_index)
                    .map(|address| (child_index, address, matching_targets(&address)))
            })
            .collect();

        for result in addresses {
            let (child_index, raw_address, address_matches) =
                result.map_err(|error| -> Box<dyn std::error::Error> { error })?;
            if address_matches.count() != 0 {
                let address = checksum_address(&raw_address);
                for target in address_matches.into_matches() {
                    let phrase = target.phrase();
                    match_files.record(child_index, target, &address)?;
                    hits += 1;
                    println!(
                        "hit  n={child_index:<10} phrase={:<11} layout={}  {} ({address})  {}",
                        phrase,
                        target.layout().name(),
                        target.safe_display(&address),
                        EvmScheme::derivation_path(child_index),
                    );
                }
            }
        }
        done += (end - index) as u64;
        index = end;
        match_files.finish_batch(index)?;
        if done >= next_progress {
            let rate = done as f64 / started.elapsed().as_secs_f64();
            println!("     n={index:<10} {done} addresses checked, {hits} hits, {rate:.1}/sec");
            while next_progress <= done {
                next_progress += PROGRESS_EVERY;
            }
        }
    }

    print_summary(done, hits, index, started);
    Ok(())
}

fn read_extended_public_key(
    device_index: usize,
) -> Result<(ExtendedPublicKey, String), Box<dyn std::error::Error>> {
    let device = LedgerDevice::open(device_index)?;
    let parent_path = [44 | HARDENED, 60 | HARDENED, HARDENED, 0];
    let response = get_public_key(&device, &parent_path, true).map_err(|error| {
        format!(
            "could not read m/44'/60'/0'/0 from the Ledger: {error}. Is the Ethereum app open and the device unlocked?"
        )
    })?;
    let chain_code = response
        .chain_code
        .expect("chain code was requested from the Ledger");
    let extended_public_key = ExtendedPublicKey {
        public_key: response.public_key,
        chain_code,
    };

    let child_path = [44 | HARDENED, 60 | HARDENED, HARDENED, 0, 0];
    let ledger_child = get_public_key(&device, &child_path, false)?;
    let computed_child = extended_public_key
        .address_at(0)
        .map_err(|error| -> Box<dyn std::error::Error> { error })?;
    if ledger_child.address != computed_child {
        return Err(format!(
            "public derivation check failed: Ledger returned {}, Mac computed {computed_child}",
            ledger_child.address
        )
        .into());
    }
    Ok((extended_public_key, device.path().to_string()))
}

fn get_public_key(
    device: &LedgerDevice,
    path: &[u32],
    request_chain_code: bool,
) -> Result<EthereumPublicKeyResponse, Box<dyn std::error::Error>> {
    let path_data = encode_path(path)?;
    let response = device.exchange(
        GET_PUBLIC_ADDRESS,
        P1_NON_CONFIRM,
        if request_chain_code {
            P2_CHAIN_CODE
        } else {
            P2_NO_CHAIN_CODE
        },
        &path_data,
    )?;
    parse_public_key_response(&response, request_chain_code)
}

fn encode_path(path: &[u32]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let length: u8 = path
        .len()
        .try_into()
        .map_err(|_| "derivation path has more than 255 components")?;
    let mut encoded = Vec::with_capacity(1 + path.len() * 4);
    encoded.push(length);
    for component in path {
        encoded.extend_from_slice(&component.to_be_bytes());
    }
    Ok(encoded)
}

fn parse_public_key_response(
    response: &[u8],
    expect_chain_code: bool,
) -> Result<EthereumPublicKeyResponse, Box<dyn std::error::Error>> {
    let public_key_length = *response
        .first()
        .ok_or("empty Ethereum public-key response")? as usize;
    if public_key_length != 65 || response.len() < 1 + public_key_length + 1 {
        return Err(format!("invalid Ethereum public-key length {public_key_length}").into());
    }
    let public_key_end = 1 + public_key_length;
    let public_key =
        PublicKey::parse_slice(&response[1..public_key_end], Some(PublicKeyFormat::Full))
            .map_err(|error| format!("invalid Ethereum public key: {error:?}"))?;

    let address_length = response[public_key_end] as usize;
    let address_start = public_key_end + 1;
    let address_end = address_start + address_length;
    if address_length != 40 || response.len() < address_end {
        return Err(format!("invalid Ethereum address length {address_length}").into());
    }
    let address_text = std::str::from_utf8(&response[address_start..address_end])?;
    let address = format!("0x{address_text}");
    let computed_address = address_from_public_key(&public_key);
    if address != computed_address {
        return Err(format!(
            "Ledger public key maps to {computed_address}, but response contained {address}"
        )
        .into());
    }

    let remaining = &response[address_end..];
    let chain_code = if expect_chain_code {
        let parsed: [u8; 32] = remaining
            .try_into()
            .map_err(|_| format!("chain code has {} bytes, expected 32", remaining.len()))?;
        Some(parsed)
    } else {
        if !remaining.is_empty() {
            return Err(format!(
                "unexpected {} bytes after Ethereum address",
                remaining.len()
            )
            .into());
        }
        None
    };
    Ok(EthereumPublicKeyResponse {
        public_key,
        address,
        chain_code,
    })
}

fn address_from_public_key(public_key: &PublicKey) -> String {
    checksum_address(&raw_address_from_public_key(public_key))
}

fn raw_address_from_public_key(public_key: &PublicKey) -> [u8; 20] {
    let uncompressed = public_key.serialize();
    let hash = Keccak256::digest(&uncompressed[1..]);
    hash[12..].try_into().expect("Keccak-256 is 32 bytes")
}

fn checksum_address(address: &[u8; 20]) -> String {
    let lower = hex::encode(address);
    let checksum = Keccak256::digest(lower.as_bytes());
    let mut result = String::with_capacity(42);
    result.push_str("0x");
    for (index, byte) in lower.bytes().enumerate() {
        let nibble = if index.is_multiple_of(2) {
            checksum[index / 2] >> 4
        } else {
            checksum[index / 2] & 0x0f
        };
        if byte.is_ascii_alphabetic() && nibble >= 8 {
            result.push((byte as char).to_ascii_uppercase());
        } else {
            result.push(byte as char);
        }
    }
    result
}

fn stub_extended_public_key() -> ExtendedPublicKey {
    let mut secret = [0u8; 32];
    secret[31] = 1;
    let public_key = PublicKey::from_secret_key(&SecretKey::parse(&secret).unwrap());
    ExtendedPublicKey {
        public_key,
        chain_code: [2u8; 32],
    }
}

fn print_targets() {
    print_word_list("3-character prefix words", THREE_CHARACTER_WORDS);
    println!();
    print_word_list("4-character prefix and suffix words", FOUR_CHARACTER_WORDS);
    println!();
    print_word_list("6-character suffix words", SIX_CHARACTER_WORDS);
    println!();
    println!("Special 4+4 targets:");
    for target in SPECIAL_FOUR_AND_FOUR_TARGETS {
        println!("  {:<8} {}", target.phrase, target.encoded);
    }
    println!();
    println!(
        "Combinations: {} using 3+6, {} using 4+4, {} using 4+6, {} special 4+4",
        three_and_six_count(),
        four_and_four_count(),
        four_and_six_count(),
        SPECIAL_FOUR_AND_FOUR_TARGETS.len(),
    );
}

fn print_word_list(title: &str, words: &[HexWord]) {
    println!("{title}:");
    for word in words {
        println!("  {:<6} {}", word.word, word.encoded);
    }
}

fn three_and_six_count() -> usize {
    THREE_CHARACTER_WORDS.len() * SIX_CHARACTER_WORDS.len()
}

fn four_and_four_count() -> usize {
    FOUR_CHARACTER_WORDS.len() * FOUR_CHARACTER_WORDS.len()
}

fn four_and_six_count() -> usize {
    FOUR_CHARACTER_WORDS.len() * SIX_CHARACTER_WORDS.len()
}

fn target_count() -> usize {
    three_and_six_count()
        + four_and_four_count()
        + four_and_six_count()
        + SPECIAL_FOUR_AND_FOUR_TARGETS.len()
}

fn benchmark(
    extended_public_key: &ExtendedPublicKey,
    count: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    if count > MAX_INDEX as u64 {
        return Err(format!("--bench must be at most {MAX_INDEX}").into());
    }
    let started = Instant::now();
    let results: Vec<_> = (0..count as u32)
        .into_par_iter()
        .map(|index| {
            extended_public_key
                .raw_address_at(index)
                .map(|address| matching_targets(&address))
        })
        .collect();
    let mut hits = 0u64;
    for result in results {
        hits += u64::from(
            result
                .map_err(|error| -> Box<dyn std::error::Error> { error })?
                .count(),
        );
    }
    let elapsed = started.elapsed().as_secs_f64();
    println!(
        "{count} addresses and {} Safe targets in {elapsed:.3}s = {:.1} addresses/sec; {hits} hits",
        target_count(),
        count as f64 / elapsed
    );
    Ok(())
}

fn print_summary(done: u64, hits: u64, next_index: u32, started: Instant) {
    let elapsed = started.elapsed().as_secs_f64();
    println!();
    if done == 0 {
        println!("Checked:      0");
    } else {
        println!(
            "Checked:      {done} in {elapsed:.1}s ({:.1}/sec)",
            done as f64 / elapsed
        );
    }
    println!("Hits:         {hits}");
    println!("Next index:   {next_index}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_derivation_matches_bip32_test_vector_one() {
        let parent = decode_xpub(
            "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
        );
        let child = decode_xpub(
            "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
        );
        let derived = derive_public_key(&parent, 1).unwrap();
        assert_eq!(
            derived.serialize_compressed(),
            child.public_key.serialize_compressed()
        );
    }

    #[test]
    fn ethereum_address_and_checksum_match_eip55_vectors() {
        let raw: [u8; 20] = hex::decode("52908400098527886e0f7030069857d2e4169ee7")
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            checksum_address(&raw),
            "0x52908400098527886E0F7030069857D2E4169EE7"
        );
        assert!(EvmScheme::validate_address("0x52908400098527886E0F7030069857D2E4169EE7").is_ok());
    }

    #[test]
    fn line_index_maps_to_standard_path() {
        assert_eq!(
            EvmScheme::derivation_path(1_837_201),
            "m/44'/60'/0'/0/1837201"
        );
    }

    #[test]
    fn word_lists_have_valid_unique_encodings() {
        assert_valid_words(THREE_CHARACTER_WORDS, 3, find_three_character_word);
        assert_valid_words(FOUR_CHARACTER_WORDS, 4, find_four_character_word);
        assert_valid_words(SIX_CHARACTER_WORDS, 6, find_six_character_word);

        let removed = ["COFFEE", "DEFACE", "EFFACE", "DEBASE", "ACCEDE"];
        assert!(
            SIX_CHARACTER_WORDS
                .iter()
                .all(|word| !removed.contains(&word.word))
        );

        let mut special_values = std::collections::HashSet::new();
        for target in SPECIAL_FOUR_AND_FOUR_TARGETS {
            assert_eq!(target.encoded.len(), 8, "{}", target.phrase);
            assert_eq!(
                u32::from_str_radix(target.encoded, 16).unwrap(),
                target.value,
                "{}",
                target.phrase
            );
            assert!(special_values.insert(target.value));
        }
        assert_eq!(target_count(), 1_230);
    }

    #[test]
    fn word_pairs_match_each_safe_layout() {
        let three_and_six_address = raw_address_with_edges("ACE", "501ACE");
        let three_and_six = matching_targets(&three_and_six_address).into_matches();
        assert_eq!(three_and_six.len(), 1);
        assert_eq!(three_and_six[0].layout(), SafeLayout::ThreeAndSix);
        assert_eq!(three_and_six[0].phrase(), "ACE / SOLACE");

        let four_and_four_address = raw_address_with_edges("FACE", "1E55");
        let four_and_four = matching_targets(&four_and_four_address).into_matches();
        assert_eq!(four_and_four.len(), 1);
        assert_eq!(four_and_four[0].layout(), SafeLayout::FourAndFour);
        assert_eq!(four_and_four[0].phrase(), "FACE / LESS");

        let four_and_six_address = raw_address_with_edges("FACE", "FACADE");
        let four_and_six = matching_targets(&four_and_six_address).into_matches();
        assert_eq!(four_and_six.len(), 1);
        assert_eq!(four_and_six[0].layout(), SafeLayout::FourAndSix);
        assert_eq!(four_and_six[0].phrase(), "FACE / FACADE");
    }

    #[test]
    fn only_obsessed_and_addicted_are_special_targets() {
        assert_eq!(SPECIAL_FOUR_AND_FOUR_TARGETS.len(), 2);
        assert_eq!(SPECIAL_FOUR_AND_FOUR_TARGETS[0].phrase, "OBSESSED");
        assert_eq!(SPECIAL_FOUR_AND_FOUR_TARGETS[1].phrase, "ADDICTED");

        let address = raw_address_with_edges("0B5E", "55ED");
        let targets = matching_targets(&address).into_matches();
        assert_eq!(
            targets,
            [SafeMatch::Special(SPECIAL_FOUR_AND_FOUR_TARGETS[0])]
        );
        assert!(
            targets[0]
                .safe_display(&checksum_address(&address))
                .eq_ignore_ascii_case("0x0B5E...55ED")
        );

        let addicted = raw_address_with_edges("ADD1", "C7ED");
        let targets = matching_targets(&addicted).into_matches();
        assert_eq!(
            targets,
            [SafeMatch::Special(SPECIAL_FOUR_AND_FOUR_TARGETS[1])]
        );
    }

    #[test]
    fn old_broken_nine_character_phrase_does_not_match() {
        let address = raw_address_with_edges("CEA", "5E1E55");
        assert_eq!(matching_targets(&address).count(), 0);
    }

    #[test]
    fn match_files_resume_from_checkpoint() {
        let directory = tempfile::tempdir().unwrap();
        let fingerprint = "0x52908400098527886E0F7030069857D2E4169EE7";
        let (mut files, next_index) = MatchFiles::open(directory.path(), fingerprint).unwrap();
        assert_eq!(next_index, 1);

        let address = checksum_address(&raw_address_with_edges("0B5E", "55ED"));
        files
            .record(
                123,
                SafeMatch::Special(SPECIAL_FOUR_AND_FOUR_TARGETS[0]),
                &address,
            )
            .unwrap();
        files.finish_batch(124).unwrap();
        let matches_path = files.matches_path.clone();
        drop(files);

        let (_, next_index) = MatchFiles::open(directory.path(), fingerprint).unwrap();
        assert_eq!(next_index, 124);
        let contents = std::fs::read_to_string(matches_path).unwrap();
        let lines: Vec<_> = contents.lines().collect();
        assert_eq!(lines[0], MATCH_FILE_HEADER);
        assert_eq!(lines.len(), 2);
        assert!(lines[1].contains("\t4+4\tOBSESSED\t"));
        assert!(lines[1].contains("\tm/44'/60'/0'/0/123"));
    }

    fn assert_valid_words(words: &[HexWord], encoded_length: usize, find: fn(u32) -> Option<u8>) {
        let mut values = std::collections::HashSet::new();
        for (index, word) in words.iter().enumerate() {
            assert_eq!(word.encoded.len(), encoded_length, "{}", word.word);
            assert!(
                word.encoded
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)),
                "{} has invalid encoding {}",
                word.word,
                word.encoded
            );
            assert_eq!(
                u32::from_str_radix(word.encoded, 16).unwrap(),
                word.value,
                "{}",
                word.word
            );
            assert!(
                values.insert(word.value),
                "duplicate encoding {}",
                word.encoded
            );
            assert_eq!(
                find(word.value),
                Some(index.try_into().unwrap()),
                "{}",
                word.word
            );
        }
    }

    fn raw_address_with_edges(prefix: &str, suffix: &str) -> [u8; 20] {
        let middle = "0".repeat(40 - prefix.len() - suffix.len());
        hex::decode(format!("{prefix}{middle}{suffix}"))
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn decode_xpub(encoded: &str) -> ExtendedPublicKey {
        let decoded = bs58::decode(encoded).into_vec().unwrap();
        assert_eq!(decoded.len(), 82);
        ExtendedPublicKey {
            chain_code: decoded[13..45].try_into().unwrap(),
            public_key: PublicKey::parse_slice(&decoded[45..78], Some(PublicKeyFormat::Compressed))
                .unwrap(),
        }
    }

    fn derive_public_key(
        extended_public_key: &ExtendedPublicKey,
        index: u32,
    ) -> Result<PublicKey, Box<dyn std::error::Error + Send + Sync>> {
        let address = extended_public_key.address_at(index)?;
        let mut data = [0u8; 37];
        data[..33].copy_from_slice(&extended_public_key.public_key.serialize_compressed());
        data[33..].copy_from_slice(&index.to_be_bytes());
        let mut hmac = HmacSha512::new_from_slice(&extended_public_key.chain_code).unwrap();
        hmac.update(&data);
        let digest = hmac.finalize().into_bytes();
        let tweak = SecretKey::parse_slice(&digest[..32]).unwrap();
        let mut child = extended_public_key.public_key;
        child.tweak_add_assign(&tweak).unwrap();
        assert_eq!(address, address_from_public_key(&child));
        Ok(child)
    }
}
