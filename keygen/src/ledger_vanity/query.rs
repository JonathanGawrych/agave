use {
    crate::patterns::{Alphabet, MatchConfig, Matcher, PatternSource},
    clap::{Arg, ArgMatches, Command, value_parser},
    std::{
        fs::File,
        io::{BufRead, BufReader, IsTerminal, Write},
        path::{Path, PathBuf},
        thread,
        time::Duration,
    },
};

use super::address_file::MAX_INDEX;

const FOLLOW_POLL_INTERVAL: Duration = Duration::from_millis(100);

pub trait AddressScheme {
    fn chain_name() -> &'static str;
    fn file_prefix() -> &'static str;
    fn alphabet() -> Alphabet;
    fn validate_address(address: &str) -> Result<(), String>;
    fn matching_text(address: &str) -> &str;
    fn shortened_address(address: &str) -> String;
    fn derivation_path(index: u32) -> String;
}

#[allow(dead_code)]
pub fn address_file_path<S: AddressScheme>(fingerprint: &str) -> PathBuf {
    PathBuf::from(format!("{}-seed-{fingerprint}.txt", S::file_prefix()))
}

pub fn add_query_arguments(command: Command<'static>) -> Command<'static> {
    command
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
                .help("Require exact capitalization in --query"),
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
                .help("Match the first four, last four, or either in --query"),
        )
        .arg(
            Arg::new("query")
                .long("query")
                .value_name("PATH")
                .takes_value(true)
                .help("Search a saved address file without a Ledger"),
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
}

pub fn run_query_if_requested<S: AddressScheme>(
    matches: &ArgMatches,
) -> Result<bool, Box<dyn std::error::Error>> {
    let Some(path) = matches.get_one::<String>("query") else {
        return Ok(false);
    };
    let config = MatchConfig {
        min_len: *matches.get_one::<usize>("min_len").unwrap(),
        case_sensitive: matches.is_present("case_sensitive"),
        leet: !matches.is_present("no_leet"),
        all_four_letter_words: matches.is_present("all_four_letter_words"),
        sides: match matches.get_one::<String>("sides").unwrap().as_str() {
            "prefix" => crate::patterns::Sides::Prefix,
            "suffix" => crate::patterns::Sides::Suffix,
            _ => crate::patterns::Sides::Both,
        },
    };
    query::<S>(
        Path::new(path),
        *matches.get_one::<usize>("top").unwrap(),
        &config,
        matches.is_present("follow"),
    )?;
    Ok(true)
}

struct Candidate {
    index: u32,
    address: String,
    pattern: String,
    matched_text: String,
    word: String,
    source: PatternSource,
    side: String,
    match_length: usize,
}

fn score(candidate: &Candidate) -> (usize, u8, u8) {
    let has_digit = candidate.pattern.bytes().any(|byte| byte.is_ascii_digit());
    let exact_case = candidate.matched_text == candidate.pattern;
    (
        candidate.match_length,
        u8::from(!has_digit),
        u8::from(exact_case),
    )
}

fn print_candidate_line(line: &str, source: PatternSource) {
    if source == PatternSource::AllFourLetterWords && std::io::stdout().is_terminal() {
        println!("\x1b[90m{line}\x1b[0m");
    } else {
        println!("{line}");
    }
}

fn print_candidates<S: AddressScheme>(candidates: &mut [Candidate], top: usize) {
    candidates.sort_by(|left, right| {
        score(right)
            .cmp(&score(left))
            .then(left.index.cmp(&right.index))
    });
    if candidates.is_empty() || top == 0 {
        return;
    }

    println!();
    println!(
        "{:<5} {:<6} {:<6} {:<7} {:>10}  {:<68}  derivation_path",
        "rank", "word", "match", "side", "n", "address"
    );
    for (rank, candidate) in candidates.iter().take(top).enumerate() {
        let address = format!(
            "{} ({})",
            S::shortened_address(&candidate.address),
            candidate.address
        );
        let line = format!(
            "{:<5} {:<6} {:<6} {:<7} {:>10}  {:<68}  {}",
            rank + 1,
            candidate.word,
            candidate.matched_text,
            candidate.side,
            candidate.index,
            address,
            S::derivation_path(candidate.index),
        );
        print_candidate_line(&line, candidate.source);
    }
    println!();
    println!(
        "Top derivation path: {}",
        S::derivation_path(candidates[0].index)
    );
}

fn print_live_candidate<S: AddressScheme>(candidate: &Candidate) -> std::io::Result<()> {
    let line = format!(
        "hit  n={:<10} word={:<4} match={:<4} {:<7} {} ({})  {}",
        candidate.index,
        candidate.word,
        candidate.matched_text,
        candidate.side,
        S::shortened_address(&candidate.address),
        candidate.address,
        S::derivation_path(candidate.index),
    );
    print_candidate_line(&line, candidate.source);
    std::io::stdout().flush()
}

fn fingerprint_from_address_file<S: AddressScheme>(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let prefix = format!("{}-seed-", S::file_prefix());
    let fingerprint = name
        .strip_prefix(&prefix)
        .and_then(|name| name.strip_suffix(".txt"))?;
    S::validate_address(fingerprint).ok()?;
    Some(fingerprint.to_string())
}

fn query<S: AddressScheme>(
    path: &Path,
    top: usize,
    config: &MatchConfig,
    follow: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let fingerprint = fingerprint_from_address_file::<S>(path);
    let matcher = Matcher::new_for_alphabet(config, S::alphabet());
    if matcher.pattern_count() == 0 {
        return Err("no patterns can be represented in this address alphabet".into());
    }

    let file =
        File::open(path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut candidates = Vec::new();
    let mut line_number = 0u32;
    let mut matches = 0u64;
    let mut line = String::new();

    println!("Address file:      {}", path.display());
    if let Some(fingerprint) = fingerprint {
        println!("Seed fingerprint:  {fingerprint}");
    }
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
            return Err(
                format!("{} has a line outside the derivation range", path.display()).into(),
            );
        }
        line_number += 1;

        let address = std::mem::take(&mut line);
        S::validate_address(&address).map_err(|error| {
            format!(
                "{} line {line_number} is not a canonical {} address: {error}",
                path.display(),
                S::chain_name()
            )
        })?;
        if let Some(hit) = matcher.best(S::matching_text(&address)) {
            let candidate = Candidate {
                index: line_number,
                address,
                pattern: hit.pattern,
                matched_text: hit.matched_text,
                word: hit.word,
                source: hit.source,
                side: hit.side.as_str().to_string(),
                match_length: hit.len,
            };
            matches += 1;
            if follow {
                print_live_candidate::<S>(&candidate)?;
            } else {
                candidates.push(candidate);
            }
        }
    }

    println!("Addresses:         {line_number}");
    println!("Matches:           {matches}");
    print_candidates::<S>(&mut candidates, top);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestScheme;

    impl AddressScheme for TestScheme {
        fn chain_name() -> &'static str {
            "test"
        }

        fn file_prefix() -> &'static str {
            "test"
        }

        fn alphabet() -> Alphabet {
            Alphabet::Base32
        }

        fn validate_address(address: &str) -> Result<(), String> {
            if address.len() == 8 {
                Ok(())
            } else {
                Err("wrong length".to_string())
            }
        }

        fn matching_text(address: &str) -> &str {
            address
        }

        fn shortened_address(address: &str) -> String {
            format!("{}...{}", &address[..2], &address[address.len() - 2..])
        }

        fn derivation_path(index: u32) -> String {
            format!("m/{index}")
        }
    }

    #[test]
    fn fingerprint_round_trips_through_file_name() {
        let path = address_file_path::<TestScheme>("ABCDEFGH");
        assert_eq!(
            fingerprint_from_address_file::<TestScheme>(&path),
            Some("ABCDEFGH".to_string())
        );
    }

    #[test]
    fn arbitrary_file_name_has_no_fingerprint() {
        let path = PathBuf::from("addresses-follow.txt");
        assert_eq!(fingerprint_from_address_file::<TestScheme>(&path), None);
    }
}
