//! Ledger public-key collector and offline vanity-address search.
//!
//! Asks a Ledger for the public key at `m/44'/501'/N'` for successive `N` and
//! saves each address in `seed-<fingerprint>.txt`. Line 1 contains `N=1`, so
//! the line number is always the derivation index. `--query` searches a saved
//! file using the hardcoded pattern bank in `patterns.rs` without a Ledger.
//!
//! The seed never leaves the device. Hardened derivation means the host cannot
//! compute anything, so scanning paths is the only available search dimension.
//! This binary contains no signing code path of any kind: the only APDUs it ever
//! sends are GET_APP_CONFIGURATION (via `read_device`) and GET_PUBKEY with
//! `confirm_key = false`, which requires no button press.
//!
//! Single-threaded by design. A device accepts one outstanding APDU at a time,
//! so there is nothing to pipeline.

mod patterns;

use {
    clap::{Arg, Command, value_parser},
    patterns::{MatchConfig, Matcher, PatternSource, Sides},
    solana_derivation_path::DerivationPath,
    solana_pubkey::Pubkey,
    solana_remote_wallet::{
        ledger::{LedgerWallet, is_valid_ledger},
        ledger_error::LedgerError,
        remote_wallet::{RemoteWallet, RemoteWalletError, is_valid_hid_device},
    },
    std::{
        fs::{File, OpenOptions},
        io::{BufRead, BufReader, BufWriter, IsTerminal, Read, Seek, SeekFrom, Write},
        path::{Path, PathBuf},
        thread,
        time::{Duration, Instant},
    },
};

/// Hardened child indices must fit in 31 bits.
const MAX_INDEX: u32 = 1 << 31;

const PROGRESS_EVERY: u64 = 100;
const FOLLOW_POLL_INTERVAL: Duration = Duration::from_millis(100);

// ============================================================
// PUBKEY SOURCE
// ============================================================

/// Where addresses come from. The stub exercises the collection loop without
/// hardware.
trait PubkeySource {
    fn label(&self) -> String;
    fn pubkey_at(&self, n: u32) -> Result<Pubkey, RemoteWalletError>;
}

struct LedgerSource {
    wallet: LedgerWallet,
    path: String,
}

impl PubkeySource for LedgerSource {
    fn label(&self) -> String {
        self.path.clone()
    }
    fn pubkey_at(&self, n: u32) -> Result<Pubkey, RemoteWalletError> {
        let path = DerivationPath::new_bip44(Some(n), None);
        self.wallet.get_pubkey(&path, false)
    }
}

/// Deterministic fake device for `--dry-run`. SplitMix64 over the index gives
/// uniformly distributed 32-byte values, so address length and first-character
/// distribution both come out realistic.
struct StubSource {
    seed: u64,
}

impl PubkeySource for StubSource {
    fn label(&self) -> String {
        format!("dry-run(seed={})", self.seed)
    }
    fn pubkey_at(&self, n: u32) -> Result<Pubkey, RemoteWalletError> {
        let mut state = self.seed ^ ((n as u64) << 1 | 1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let mut next = || {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        let mut raw = [0u8; 32];
        for chunk in raw.chunks_mut(8) {
            chunk.copy_from_slice(&next().to_le_bytes());
        }
        Ok(Pubkey::new_from_array(raw))
    }
}

// ============================================================
// ERROR CLASSIFICATION
// ============================================================

enum Disposition {
    /// Solana app is not open (or the dashboard is). Operator action needed.
    AppNotOpen,
    /// Retry the same index after a pause. Includes 0x5515 device-locked, which
    /// `parse_status` collapses into `Protocol("Unknown error")` because the
    /// status word has no `LedgerError` variant and the numeric value is thrown
    /// away. We cannot tell it apart from any other unmapped status word, so we
    /// retry rather than pretend to identify it.
    Retry(String),
    /// Transport died. Reopen the device.
    Reconnect(String),
    /// Should be unreachable in non-confirm mode.
    Fatal(String),
}

fn classify(err: &RemoteWalletError) -> Disposition {
    match err {
        RemoteWalletError::LedgerError(LedgerError::NoAppResponse)
        | RemoteWalletError::LedgerError(LedgerError::InvalidCla)
        | RemoteWalletError::LedgerError(LedgerError::UnimplementedInstruction) => {
            Disposition::AppNotOpen
        }
        RemoteWalletError::LedgerError(LedgerError::UserCancel)
        | RemoteWalletError::LedgerError(LedgerError::NoApduReceived) => Disposition::Fatal(
            format!("{err} (unexpected in non-confirm mode; refusing to continue blindly)"),
        ),
        RemoteWalletError::Hid(m) => Disposition::Reconnect(m.clone()),
        RemoteWalletError::Protocol(m) => Disposition::Retry(format!(
            "{m} (may be 0x5515 device locked; the status word is not recoverable)"
        )),
        other => Disposition::Retry(other.to_string()),
    }
}

// ============================================================
// ADDRESS FILE
// ============================================================

fn cli_url(n: u32) -> String {
    format!("usb://ledger?key={n}")
}

#[cfg(test)]
fn derivation_string(n: u32) -> String {
    format!("m/44'/501'/{n}'")
}

fn address_file_path(fingerprint: &Pubkey) -> PathBuf {
    PathBuf::from(format!("seed-{fingerprint}.txt"))
}

struct AddressFile {
    out: BufWriter<File>,
}

impl AddressFile {
    fn open(path: &Path) -> Result<(Self, u32), Box<dyn std::error::Error>> {
        let mut next_n = 1;
        if path.exists() {
            let mut file = File::open(path)?;
            let length = file.metadata()?.len();
            if length > 0 {
                file.seek(SeekFrom::End(-1))?;
                let mut final_byte = [0];
                file.read_exact(&mut final_byte)?;
                if final_byte[0] != b'\n' {
                    return Err(format!(
                        "{} ends with an incomplete line; repair or move the file before resuming",
                        path.display()
                    )
                    .into());
                }

                file.seek(SeekFrom::Start(0))?;
                let mut reader = BufReader::new(file);
                let mut line_count = 0u64;
                loop {
                    let buffer = reader.fill_buf()?;
                    if buffer.is_empty() {
                        break;
                    }
                    line_count += buffer.iter().filter(|&&byte| byte == b'\n').count() as u64;
                    let length = buffer.len();
                    reader.consume(length);
                }
                if line_count >= (MAX_INDEX - 1) as u64 {
                    return Err(
                        format!("{} contains the entire derivation range", path.display()).into(),
                    );
                }
                next_n = line_count as u32 + 1;
            }
        }

        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok((
            Self {
                out: BufWriter::new(file),
            },
            next_n,
        ))
    }

    fn record(&mut self, address: &str) -> std::io::Result<()> {
        writeln!(self.out, "{address}")?;
        self.out.flush()
    }
}

// ============================================================
// OFFLINE SEARCH
// ============================================================

/// A matching saved address, ranked for human selection.
struct Candidate {
    n: u32,
    pubkey: String,
    pattern: String,
    matched_text: String,
    word: String,
    source: PatternSource,
    side: String,
    match_len: usize,
}

/// Ranking is by match length first, then by whether the matched text reads
/// cleanly: an all-alphabetic pattern beats one carrying leet digits, and
/// matching the word bank's own capitalization beats a case-folded match.
/// Higher score sorts first.
fn score(c: &Candidate) -> (usize, u8, u8) {
    let has_digit = c.pattern.bytes().any(|b| b.is_ascii_digit());
    let alpha = u8::from(!has_digit);

    let exact_case = c.matched_text == c.pattern;
    (c.match_len, alpha, u8::from(exact_case))
}

fn shortened_address(address: &str) -> String {
    format!("{}...{}", &address[..4], &address[address.len() - 4..])
}

fn print_candidate_line(line: &str, source: PatternSource) {
    if source == PatternSource::AllFourLetterWords && std::io::stdout().is_terminal() {
        println!("\x1b[90m{line}\x1b[0m");
    } else {
        println!("{line}");
    }
}

fn print_candidates(candidates: &mut [Candidate], top: usize) {
    candidates.sort_by(|a, b| score(b).cmp(&score(a)).then(a.n.cmp(&b.n)));

    if candidates.is_empty() || top == 0 {
        return;
    }

    println!();
    println!(
        "{:<5} {:<6} {:<6} {:<7} {:>10}  {:<58}  {}",
        "rank", "word", "match", "side", "n", "address", "cli_url"
    );
    for (rank, candidate) in candidates.iter().take(top).enumerate() {
        let address = format!(
            "{} ({})",
            shortened_address(&candidate.pubkey),
            candidate.pubkey
        );
        let line = format!(
            "{:<5} {:<6} {:<6} {:<7} {:>10}  {:<58}  {}",
            rank + 1,
            candidate.word,
            candidate.matched_text,
            candidate.side,
            candidate.n,
            address,
            cli_url(candidate.n),
        );
        print_candidate_line(&line, candidate.source);
    }
    println!();
    println!("To use the top pick:");
    println!("  solana-keygen pubkey \"{}\"", cli_url(candidates[0].n));
    println!("  (quote the URL; zsh strips the ? otherwise)");
}

fn print_live_candidate(candidate: &Candidate) -> std::io::Result<()> {
    let line = format!(
        "hit  n={:<10} word={:<4} match={:<4} {:<7} {} ({})  {}",
        candidate.n,
        candidate.word,
        candidate.matched_text,
        candidate.side,
        shortened_address(&candidate.pubkey),
        candidate.pubkey,
        cli_url(candidate.n),
    );
    print_candidate_line(&line, candidate.source);
    std::io::stdout().flush()
}

fn fingerprint_from_address_file(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{} does not have a UTF-8 file name", path.display()))?;
    let fingerprint = name
        .strip_prefix("seed-")
        .and_then(|name| name.strip_suffix(".txt"))
        .ok_or_else(|| format!("{} must be named seed-<fingerprint>.txt", path.display()))?;
    let parsed: Pubkey = fingerprint.parse().map_err(|error| {
        format!(
            "{} contains an invalid seed fingerprint: {error}",
            path.display()
        )
    })?;
    Ok(parsed.to_string())
}

fn query(
    path: &Path,
    top: usize,
    config: &MatchConfig,
    follow: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let fingerprint = fingerprint_from_address_file(path)?;
    let matcher = Matcher::new(config);
    if matcher.pattern_count() == 0 {
        return Err("no patterns after applying filters".into());
    }

    let file =
        File::open(path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut candidates = Vec::new();
    let mut line_number = 0u32;
    let mut matches = 0u64;
    let mut line = String::new();

    println!("Address file:      {}", path.display());
    println!("Seed fingerprint:  {fingerprint}");
    if follow {
        println!("Following complete lines. Press Ctrl-C to stop.");
        std::io::stdout().flush()?;
    }

    loop {
        let bytes_read = reader.read_line(&mut line)?;
        if bytes_read == 0 {
            if follow {
                thread::sleep(FOLLOW_POLL_INTERVAL);
                continue;
            }
            if !line.is_empty() {
                return Err(
                    format!("{} line {} is incomplete", path.display(), line_number + 1).into(),
                );
            }
            break;
        }
        if !line.ends_with('\n') {
            if follow {
                continue;
            }
            return Err(
                format!("{} line {} is incomplete", path.display(), line_number + 1).into(),
            );
        }
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }

        if line_number >= MAX_INDEX - 1 {
            return Err(format!(
                "{} has a line outside the hardened derivation range",
                path.display()
            )
            .into());
        }
        line_number += 1;
        let address = std::mem::take(&mut line);
        let pubkey: Pubkey = address.parse().map_err(|error| {
            format!(
                "{} line {line_number} is not a Solana public key: {error}",
                path.display()
            )
        })?;
        if pubkey.to_string() != address {
            return Err(format!(
                "{} line {line_number} is not a canonical Solana public key",
                path.display()
            )
            .into());
        }

        if let Some(hit) = matcher.best(&address) {
            let candidate = Candidate {
                n: line_number,
                pubkey: address,
                pattern: hit.pattern,
                matched_text: hit.matched_text,
                word: hit.word,
                source: hit.source,
                side: hit.side.as_str().to_string(),
                match_len: hit.len,
            };
            matches += 1;
            if follow {
                print_live_candidate(&candidate)?;
            } else {
                candidates.push(candidate);
            }
        }
    }

    println!("Addresses:         {line_number}");
    println!("Matches:           {matches}");
    print_candidates(&mut candidates, top);
    Ok(())
}

// ============================================================
// MAIN
// ============================================================

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("ledger-vanity-scan")
        .about("Collect Ledger public keys and search the saved addresses")
        .arg(
            Arg::new("count")
                .long("count")
                .value_name("N")
                .takes_value(true)
                .value_parser(value_parser!(u64))
                .help("Stop after this many derivations (default: run until interrupted)"),
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
                .value_name("PUBKEY")
                .takes_value(true)
                .help(
                    "Abort unless the key at m/44'/501'/0' equals this. Guards against \
                   scanning the wrong Ledger",
                ),
        )
        .arg(
            Arg::new("min_len")
                .long("min-len")
                .value_name("N")
                .takes_value(true)
                .value_parser(value_parser!(usize))
                .default_value("3")
                .help("Shortest pattern length for --query"),
        )
        .arg(
            Arg::new("case_sensitive")
                .long("case-sensitive")
                .help("Require exact word-bank capitalization in --query"),
        )
        .arg(
            Arg::new("no_leet")
                .long("no-leet")
                .help("Disable digit substitutions in --query"),
        )
        .arg(
            Arg::new("sides")
                .long("sides")
                .value_name("WHICH")
                .takes_value(true)
                .default_value("both")
                .possible_values(["both", "prefix", "suffix"])
                .help("Match the start, end, or either in --query"),
        )
        .arg(
            Arg::new("bench")
                .long("bench")
                .value_name("N")
                .takes_value(true)
                .value_parser(value_parser!(u64))
                .help("Time N derivations, report keys/sec, and exit"),
        )
        .arg(
            Arg::new("print_all")
                .long("print-all")
                .help("Print every derivation index, shortened address, and full address"),
        )
        .arg(
            Arg::new("dry_run")
                .long("dry-run")
                .help("Use a deterministic fake device to exercise collection without hardware"),
        )
        .arg(
            Arg::new("list_devices")
                .long("list-devices")
                .help("List detected Ledgers and exit"),
        )
        .arg(
            Arg::new("query")
                .long("query")
                .value_name("PATH")
                .takes_value(true)
                .help("Search a seed-<fingerprint>.txt file without a Ledger"),
        )
        .arg(
            Arg::new("all_four_letter_words")
                .long("all-four-letter-words")
                .requires("query")
                .help("Include the bundled 5,006-word four-letter dictionary"),
        )
        .arg(
            Arg::new("follow")
                .long("follow")
                .requires("query")
                .help("Keep reading complete lines appended to the --query file"),
        )
        .arg(
            Arg::new("top")
                .long("top")
                .value_name("N")
                .takes_value(true)
                .value_parser(value_parser!(usize))
                .default_value("20")
                .help("How many candidates --query should show"),
        )
        .get_matches();

    if matches.is_present("list_devices") {
        return list_devices();
    }

    if let Some(path) = matches.get_one::<String>("query") {
        let config = MatchConfig {
            min_len: *matches.get_one::<usize>("min_len").unwrap(),
            case_sensitive: matches.is_present("case_sensitive"),
            leet: !matches.is_present("no_leet"),
            all_four_letter_words: matches.is_present("all_four_letter_words"),
            sides: match matches.get_one::<String>("sides").unwrap().as_str() {
                "prefix" => Sides::Prefix,
                "suffix" => Sides::Suffix,
                _ => Sides::Both,
            },
        };
        return query(
            Path::new(path),
            *matches.get_one::<usize>("top").unwrap(),
            &config,
            matches.is_present("follow"),
        );
    }

    let dry_run = matches.is_present("dry_run");
    let device_index = *matches.get_one::<usize>("device").unwrap();
    let mut source: Box<dyn PubkeySource> = if dry_run {
        Box::new(StubSource { seed: 0x5EED_1234 })
    } else {
        Box::new(open_ledger(device_index)?)
    };

    // ---- seed fingerprint ----
    let fingerprint = source.pubkey_at(0).map_err(|e| {
        format!(
            "could not read m/44'/501'/0': {e}. Is the Solana app open and the device unlocked?"
        )
    })?;
    if let Some(expected) = matches.get_one::<String>("expect_seed") {
        if &fingerprint.to_string() != expected {
            return Err(format!(
                "seed fingerprint mismatch: device reports {fingerprint}, --expect-seed said {expected}. \
                 Wrong Ledger, or a different seed."
            )
            .into());
        }
    }

    // ---- bench ----
    if let Some(n) = matches.get_one::<u64>("bench").copied() {
        return bench(source.as_ref(), n);
    }

    let address_path = address_file_path(&fingerprint);
    let (mut address_file, mut n) = AddressFile::open(&address_path)?;

    println!("Device:       {}", source.label());
    println!("Fingerprint:  {fingerprint}   (m/44'/501'/0')");
    println!(
        "Address file:  {}",
        std::env::current_dir()?.join(&address_path).display()
    );
    println!("Next index:    {n}");
    println!();

    let limit = matches.get_one::<u64>("count").copied();
    let started = Instant::now();
    let mut done = 0u64;
    let print_all = matches.is_present("print_all");

    while limit.is_none_or(|l| done < l) {
        if n >= MAX_INDEX {
            println!("reached the end of the hardened index space at n={n}");
            break;
        }

        let pubkey = match source.pubkey_at(n) {
            Ok(p) => p,
            Err(e) => match classify(&e) {
                Disposition::Fatal(m) => return Err(m.into()),
                Disposition::AppNotOpen => {
                    eprintln!(
                        "\n  the Solana app does not appear to be open ({e}). \
                         Open it on the device; retrying n={n} in 5s."
                    );
                    thread::sleep(Duration::from_secs(5));
                    continue;
                }
                Disposition::Retry(m) => {
                    eprintln!("\n  {m}. Retrying n={n} in 5s. If the device is locked, unlock it.");
                    thread::sleep(Duration::from_secs(5));
                    continue;
                }
                Disposition::Reconnect(m) => {
                    eprintln!("\n  transport error: {m}. Reopening device.");
                    let reopened = reopen(device_index)?;
                    let reopened_fingerprint = reopened.pubkey_at(0).map_err(|error| {
                        format!("could not verify the reopened Ledger seed: {error}")
                    })?;
                    if reopened_fingerprint != fingerprint {
                        return Err(format!(
                            "reopened Ledger seed mismatch: expected {fingerprint}, got \
                             {reopened_fingerprint}"
                        )
                        .into());
                    }
                    source = Box::new(reopened);
                    continue;
                }
            },
        };

        let address = pubkey.to_string();
        address_file.record(&address)?;
        if print_all {
            let head = &address[..4];
            let tail = &address[address.len() - 4..];
            println!("{n:<10} {head}...{tail}  {address}");
        }

        done += 1;
        n = n.saturating_add(1);

        if done.is_multiple_of(PROGRESS_EVERY) {
            let rate = done as f64 / started.elapsed().as_secs_f64();
            println!("     n={n:<10} {done} addresses, {rate:.1}/sec");
        }
    }

    let elapsed = started.elapsed().as_secs_f64();
    println!();
    if done == 0 {
        println!("Addresses:    0");
    } else {
        println!(
            "Addresses:    {done} in {elapsed:.1}s ({:.1}/sec)",
            done as f64 / elapsed
        );
    }
    println!("Next index:   {n}");
    Ok(())
}

// ============================================================
// DEVICE PLUMBING
// ============================================================

fn list_devices() -> Result<(), Box<dyn std::error::Error>> {
    let api = hidapi::HidApi::new()?;
    let mut found = 0;
    let mut infos: Vec<_> = api
        .device_list()
        .filter(|d| {
            is_valid_ledger(d.vendor_id(), d.product_id())
                && is_valid_hid_device(d.usage_page(), d.interface_number())
        })
        .collect();
    infos.sort_by_key(|d| d.path().to_owned());
    for (i, d) in infos.iter().enumerate() {
        println!(
            "[{i}] {}  vid={:04x} pid={:04x} serial={:?}",
            d.path().to_string_lossy(),
            d.vendor_id(),
            d.product_id(),
            d.serial_number().unwrap_or("?"),
        );
        found += 1;
    }
    if found == 0 {
        println!("no Ledger devices found (is Ledger Live holding the handle?)");
    }
    Ok(())
}

fn open_ledger(index: usize) -> Result<LedgerSource, Box<dyn std::error::Error>> {
    let api = hidapi::HidApi::new()?;
    let mut infos: Vec<_> = api
        .device_list()
        .filter(|d| {
            is_valid_ledger(d.vendor_id(), d.product_id())
                && is_valid_hid_device(d.usage_page(), d.interface_number())
        })
        .collect();
    infos.sort_by_key(|d| d.path().to_owned());

    if infos.is_empty() {
        return Err(
            "no Ledger devices found. Close Ledger Live (it holds the HID handle) \
                    and confirm the device is plugged in and unlocked."
                .into(),
        );
    }
    let info = infos.get(index).ok_or_else(|| {
        format!(
            "--device {index} out of range; {} detected. Use --list-devices.",
            infos.len()
        )
    })?;

    let path = info.path().to_string_lossy().to_string();
    let hid = info.open_device(&api)?;
    let mut wallet = LedgerWallet::new(hid);

    // read_device does three jobs at once: it sets `version` (a fresh
    // LedgerWallet is 0.0.0, and `outdated_app()` is `version < 0.2.0`, so
    // without this every APDU would silently use the deprecated framing), it
    // confirms the Solana app is open, and it returns the root pubkey.
    if let Err(e) = wallet.read_device(info) {
        return Err(describe_open_failure(&path, &e).into());
    }

    Ok(LedgerSource { wallet, path })
}

/// Turn a first-contact failure into something an operator can act on.
///
/// The status word is often unrecoverable: `parse_status` maps anything it does
/// not recognise to `Protocol("Unknown error")` and discards the number, and
/// 0x5515 (device locked) is the most common arrival in that bucket. So rather
/// than guess, list the causes in order of likelihood.
fn describe_open_failure(path: &str, err: &RemoteWalletError) -> String {
    let hint = match classify(err) {
        Disposition::AppNotOpen => "The Solana app is not open. Open it on the device and retry.",
        Disposition::Retry(_) => {
            "The device reported a status this crate cannot name, and by far the most \
             likely cause is that it is locked. Check, in order:\n  \
             1. the device is unlocked (enter the PIN)\n  \
             2. the Solana app is open, not the dashboard\n  \
             3. Ledger Live is closed, since it holds the HID handle"
        }
        Disposition::Reconnect(_) => {
            "The transport dropped. Replug the device and retry; a charge-only cable \
             will enumerate but carry no data."
        }
        Disposition::Fatal(_) => "The device refused the request outright.",
    };
    format!("could not talk to the Ledger at {path}\n  cause: {err}\n  {hint}")
}

fn reopen(index: usize) -> Result<LedgerSource, Box<dyn std::error::Error>> {
    for attempt in 0..6 {
        let backoff = Duration::from_secs(1 << attempt.min(4));
        thread::sleep(backoff);
        match open_ledger(index) {
            Ok(s) => return Ok(s),
            Err(e) => eprintln!("  reopen attempt {} failed: {e}", attempt + 1),
        }
    }
    Err("gave up reopening the device".into())
}

fn bench(source: &dyn PubkeySource, n: u64) -> Result<(), Box<dyn std::error::Error>> {
    println!("benchmarking {n} derivations on {}...", source.label());
    let start = Instant::now();
    for i in 0..n {
        source.pubkey_at(i as u32)?;
    }
    let elapsed = start.elapsed().as_secs_f64();
    let rate = n as f64 / elapsed;
    println!("{n} derivations in {elapsed:.2}s = {rate:.2} keys/sec");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_url_matches_derivation_path() {
        assert_eq!(cli_url(1_837_201), "usb://ledger?key=1837201");
        assert_eq!(derivation_string(1_837_201), "m/44'/501'/1837201'");
    }

    /// The collector's index-to-path mapping must agree with what the Solana
    /// CLI resolves from the URL printed by `--query`.
    #[test]
    fn emitted_url_round_trips_through_derivation_path() {
        for n in [0u32, 1, 44, 501, 1_837_201, MAX_INDEX - 1] {
            let ours = DerivationPath::new_bip44(Some(n), None);
            let url = cli_url(n);
            let uri = uriparse::URIReference::try_from(url.as_str()).unwrap();
            let parsed = DerivationPath::from_uri_key_query(&uri).unwrap().unwrap();
            assert_eq!(ours, parsed, "n={n}");
        }
    }

    #[test]
    fn stub_source_is_deterministic_and_well_distributed() {
        let s = StubSource { seed: 42 };
        assert_eq!(s.pubkey_at(7).unwrap(), s.pubkey_at(7).unwrap());
        assert_ne!(s.pubkey_at(7).unwrap(), s.pubkey_at(8).unwrap());

        // ~94% of random 32-byte values encode to 44 base58 characters.
        let long = (0..2000)
            .filter(|i| s.pubkey_at(*i).unwrap().to_string().len() == 44)
            .count();
        assert!(
            (1800..=1960).contains(&long),
            "got {long}/2000 at length 44"
        );
    }

    fn candidate(pubkey: &str, pattern: &str, side: &str, len: usize) -> Candidate {
        let matched_text = if side == "prefix" {
            pubkey[..len].to_string()
        } else {
            pubkey[pubkey.len() - len..].to_string()
        };
        Candidate {
            n: 1,
            pubkey: pubkey.into(),
            pattern: pattern.into(),
            matched_text,
            word: pattern.into(),
            source: PatternSource::Curated,
            side: side.into(),
            match_len: len,
        }
    }

    #[test]
    fn ranking_prefers_longer_matches() {
        let four = candidate("GoLDxx", "GoLD", "prefix", 4);
        let three = candidate("Furxxx", "Fur", "prefix", 3);
        assert!(score(&four) > score(&three));
    }

    #[test]
    fn query_shortens_addresses_to_four_characters_per_side() {
        assert_eq!(shortened_address("123456789ABCDEFG"), "1234...DEFG");
    }

    #[test]
    fn ranking_prefers_clean_letters_over_leet() {
        let clean = candidate("xxxxBEST", "BEST", "suffix", 4);
        let leet = candidate("xxxxB357", "B357", "suffix", 4);
        assert!(score(&clean) > score(&leet));
    }

    #[test]
    fn ranking_prefers_the_word_banks_own_capitalization() {
        // Both match case-insensitively; only one reads as the intended word.
        let exact = candidate("GoLDaaaaaa", "GoLD", "prefix", 4);
        let folded = candidate("goldaaaaaa", "GoLD", "prefix", 4);
        assert!(score(&exact) > score(&folded));

        let exact_sfx = candidate("aaaaaaGoLD", "GoLD", "suffix", 4);
        let folded_sfx = candidate("aaaaaagOlD", "GoLD", "suffix", 4);
        assert!(score(&exact_sfx) > score(&folded_sfx));
    }

    #[test]
    fn address_file_line_number_is_derivation_index() {
        let dir = tempfile::tempdir().unwrap();
        let fp = Pubkey::new_from_array([7u8; 32]);
        let path = dir.path().join(address_file_path(&fp));
        let first = Pubkey::new_from_array([1u8; 32]).to_string();
        let second = Pubkey::new_from_array([2u8; 32]).to_string();

        let (mut addresses, next_n) = AddressFile::open(&path).unwrap();
        assert_eq!(next_n, 1);
        addresses.record(&first).unwrap();
        addresses.record(&second).unwrap();
        drop(addresses);

        let lines: Vec<String> = BufReader::new(File::open(&path).unwrap())
            .lines()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(lines, [first, second]);

        let (_, next_n) = AddressFile::open(&path).unwrap();
        assert_eq!(next_n, 3);
    }

    #[test]
    fn address_file_refuses_an_incomplete_final_line() {
        let dir = tempfile::tempdir().unwrap();
        let fp = Pubkey::new_from_array([1u8; 32]);
        let path = dir.path().join(address_file_path(&fp));
        std::fs::write(&path, Pubkey::new_from_array([2u8; 32]).to_string()).unwrap();

        let error = match AddressFile::open(&path) {
            Ok(_) => panic!("incomplete line was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("incomplete line"));
    }

    #[test]
    fn seed_fingerprint_round_trips_through_address_file_name() {
        let fp = Pubkey::new_from_array([3u8; 32]);
        let path = address_file_path(&fp);
        assert_eq!(
            fingerprint_from_address_file(&path).unwrap(),
            fp.to_string()
        );
    }
}
