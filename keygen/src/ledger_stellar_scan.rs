//! Ledger Stellar address collector and saved-address search.
//!
//! The Stellar Ledger app accepts only `m/44'/148'/N'`. Every `N` is hardened,
//! so the host asks the Ledger for each public key. The private keys never leave
//! the device. Line 1 in the saved file contains `N=1`.

mod ledger_vanity;
mod patterns;

use {
    clap::{Arg, Command, value_parser},
    data_encoding::BASE32_NOPAD,
    ledger_vanity::{
        address_file::{AddressFile, MAX_INDEX},
        hid::{Error as LedgerError, LedgerDevice, list_devices},
        query::{AddressScheme, add_query_arguments, address_file_path, run_query_if_requested},
    },
    patterns::Alphabet,
    std::{
        thread,
        time::{Duration, Instant},
    },
};

const HARDENED: u32 = 1 << 31;
const GET_PUBLIC_KEY: u8 = 0x02;
const P1_NON_CONFIRM: u8 = 0x00;
const P2_NON_CONFIRM: u8 = 0x00;
const PROGRESS_EVERY: u64 = 100;

struct StellarScheme;

impl AddressScheme for StellarScheme {
    fn chain_name() -> &'static str {
        "Stellar"
    }

    fn file_prefix() -> &'static str {
        "stellar"
    }

    fn alphabet() -> Alphabet {
        Alphabet::Base32
    }

    fn validate_address(address: &str) -> Result<(), String> {
        if address.len() != 56 {
            return Err(format!(
                "address has {} characters, expected 56",
                address.len()
            ));
        }
        let decoded = BASE32_NOPAD
            .decode(address.as_bytes())
            .map_err(|error| error.to_string())?;
        if decoded.len() != 35 {
            return Err(format!(
                "address decodes to {} bytes, expected 35",
                decoded.len()
            ));
        }
        if decoded[0] != 6 << 3 {
            return Err(format!("version byte is {}, expected 48", decoded[0]));
        }
        if decoded[33..] != crc16_xmodem(&decoded[..33]) {
            return Err("CRC16-XModem checksum does not match".to_string());
        }
        if BASE32_NOPAD.encode(&decoded) != address {
            return Err("address is not canonical unpadded Base32".to_string());
        }
        Ok(())
    }

    fn matching_text(address: &str) -> &str {
        address
    }

    fn shortened_address(address: &str) -> String {
        format!("{}...{}", &address[..4], &address[address.len() - 4..])
    }

    fn derivation_path(index: u32) -> String {
        format!("m/44'/148'/{index}'")
    }
}

enum StellarSource {
    Ledger {
        device: LedgerDevice,
        device_index: usize,
    },
    Stub,
}

impl StellarSource {
    fn label(&self) -> &str {
        match self {
            Self::Ledger { device, .. } => device.path(),
            Self::Stub => "dry-run",
        }
    }

    fn address_at(&self, index: u32) -> Result<String, LedgerError> {
        match self {
            Self::Ledger { device, .. } => read_stellar_address(device, index),
            Self::Stub => Ok(stub_address(index)),
        }
    }

    fn reconnect(&mut self, fingerprint: &str) -> Result<(), Box<dyn std::error::Error>> {
        let device_index = match self {
            Self::Ledger { device_index, .. } => *device_index,
            Self::Stub => return Ok(()),
        };
        for attempt in 0..6 {
            thread::sleep(Duration::from_secs(1 << attempt.min(4)));
            let reopened = match LedgerDevice::open(device_index) {
                Ok(device) => device,
                Err(error) => {
                    eprintln!("  reopen attempt {} failed: {error}", attempt + 1);
                    continue;
                }
            };
            match read_stellar_address(&reopened, 0) {
                Ok(reopened_fingerprint) if reopened_fingerprint == fingerprint => {
                    *self = Self::Ledger {
                        device: reopened,
                        device_index,
                    };
                    return Ok(());
                }
                Ok(reopened_fingerprint) => {
                    return Err(format!(
                        "reopened Ledger seed mismatch: expected {fingerprint}, got {reopened_fingerprint}"
                    )
                    .into());
                }
                Err(error) => {
                    eprintln!("  reopen attempt {} failed: {error}", attempt + 1);
                }
            }
        }
        Err("gave up reopening the Ledger".into())
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let command = Command::new("ledger-stellar-vanity-scan")
        .about("Collect Stellar Ledger addresses and search the saved file")
        .arg(
            Arg::new("count")
                .long("count")
                .value_name("N")
                .takes_value(true)
                .value_parser(value_parser!(u64))
                .help("Stop after this many Ledger derivations (default: run until interrupted)"),
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
                .help("Abort unless m/44'/148'/0' has this address"),
        )
        .arg(
            Arg::new("bench")
                .long("bench")
                .value_name("N")
                .takes_value(true)
                .value_parser(value_parser!(u64))
                .help("Time N Ledger derivations without writing a file"),
        )
        .arg(
            Arg::new("print_all")
                .long("print-all")
                .help("Print every derivation index, shortened address, and full address"),
        )
        .arg(
            Arg::new("dry_run")
                .long("dry-run")
                .help("Use deterministic fake public keys instead of a Ledger"),
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
    if run_query_if_requested::<StellarScheme>(&matches)? {
        return Ok(());
    }

    let device_index = *matches.get_one::<usize>("device").unwrap();
    let mut source = if matches.is_present("dry_run") {
        StellarSource::Stub
    } else {
        StellarSource::Ledger {
            device: LedgerDevice::open(device_index)?,
            device_index,
        }
    };
    let fingerprint = source.address_at(0).map_err(|error| {
        format!(
            "could not read m/44'/148'/0' from the Ledger: {error}. Is the Stellar app open and the device unlocked?"
        )
    })?;
    if let Some(expected) = matches.get_one::<String>("expect_seed") {
        if expected != &fingerprint {
            return Err(format!(
                "seed fingerprint mismatch: device reports {fingerprint}, --expect-seed said {expected}"
            )
            .into());
        }
    }

    if let Some(count) = matches.get_one::<u64>("bench").copied() {
        return benchmark(&source, count);
    }

    let path = address_file_path::<StellarScheme>(&fingerprint);
    let (mut address_file, mut index) = AddressFile::open(&path)?;
    println!("Device:       {}", source.label());
    println!("Fingerprint:  {fingerprint}   (m/44'/148'/0')");
    println!(
        "Address file:  {}",
        std::env::current_dir()?.join(&path).display()
    );
    println!("Next index:    {index}");
    println!();

    let limit = matches.get_one::<u64>("count").copied();
    let print_all = matches.is_present("print_all");
    let started = Instant::now();
    let mut done = 0u64;
    while limit.is_none_or(|limit| done < limit) && index < MAX_INDEX {
        let address = match source.address_at(index) {
            Ok(address) => address,
            Err(error @ LedgerError::Hid(_)) => {
                eprintln!("\n  {error}. Reopening the Ledger before retrying n={index}.");
                source.reconnect(&fingerprint)?;
                continue;
            }
            Err(LedgerError::Status(status)) => {
                eprintln!(
                    "\n  Ledger returned 0x{status:04x}. Confirm it is unlocked and the Stellar app is open. Retrying n={index} in 5s."
                );
                thread::sleep(Duration::from_secs(5));
                continue;
            }
            Err(error) => return Err(error.into()),
        };

        address_file.record(&address)?;
        address_file.flush()?;
        if print_all {
            println!(
                "{index:<10} {}  {address}",
                StellarScheme::shortened_address(&address)
            );
        }
        done += 1;
        index += 1;
        if done.is_multiple_of(PROGRESS_EVERY) {
            let rate = done as f64 / started.elapsed().as_secs_f64();
            println!("     n={index:<10} {done} addresses, {rate:.1}/sec");
        }
    }

    print_summary(done, index, started);
    Ok(())
}

fn read_stellar_address(device: &LedgerDevice, index: u32) -> Result<String, LedgerError> {
    if index >= MAX_INDEX {
        return Err(LedgerError::Protocol(format!(
            "index {index} is out of range"
        )));
    }
    let mut path = Vec::with_capacity(13);
    path.push(3);
    for component in [44 | HARDENED, 148 | HARDENED, index | HARDENED] {
        path.extend_from_slice(&component.to_be_bytes());
    }
    let response = device.exchange(GET_PUBLIC_KEY, P1_NON_CONFIRM, P2_NON_CONFIRM, &path)?;
    let public_key: [u8; 32] = response.try_into().map_err(|response: Vec<u8>| {
        LedgerError::Protocol(format!(
            "Stellar public-key response has {} bytes, expected 32",
            response.len()
        ))
    })?;
    Ok(stellar_address(&public_key))
}

fn stellar_address(public_key: &[u8; 32]) -> String {
    let mut payload = [0u8; 35];
    payload[0] = 6 << 3;
    payload[1..33].copy_from_slice(public_key);
    let checksum = crc16_xmodem(&payload[..33]);
    payload[33..].copy_from_slice(&checksum);
    BASE32_NOPAD.encode(&payload)
}

fn crc16_xmodem(data: &[u8]) -> [u8; 2] {
    let mut crc = 0u16;
    for byte in data {
        crc ^= (*byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc.to_le_bytes()
}

fn stub_address(index: u32) -> String {
    let mut state = 0x5EED_1234u64 ^ ((index as u64) << 1 | 1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let mut next = || {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = state;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    };
    let mut public_key = [0u8; 32];
    for chunk in public_key.chunks_mut(8) {
        chunk.copy_from_slice(&next().to_le_bytes());
    }
    stellar_address(&public_key)
}

fn benchmark(source: &StellarSource, count: u64) -> Result<(), Box<dyn std::error::Error>> {
    if count > MAX_INDEX as u64 {
        return Err(format!("--bench must be at most {MAX_INDEX}").into());
    }
    let started = Instant::now();
    for index in 0..count as u32 {
        source.address_at(index)?;
    }
    let elapsed = started.elapsed().as_secs_f64();
    println!(
        "{count} addresses in {elapsed:.3}s = {:.2} addresses/sec",
        count as f64 / elapsed
    );
    Ok(())
}

fn print_summary(done: u64, next_index: u32, started: Instant) {
    let elapsed = started.elapsed().as_secs_f64();
    println!();
    if done == 0 {
        println!("Addresses:    0");
    } else {
        println!(
            "Addresses:    {done} in {elapsed:.1}s ({:.2}/sec)",
            done as f64 / elapsed
        );
    }
    println!("Next index:   {next_index}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_matches_xmodem_check_value() {
        assert_eq!(crc16_xmodem(b"123456789"), [0xc3, 0x31]);
    }

    #[test]
    fn strkey_matches_stellar_test_vector() {
        let public_key: [u8; 32] =
            hex::decode("3f0c34bf93ad0d9971d04ccc90f705511c838aad9734a4a2fb0d7a03fc7fe89a")
                .unwrap()
                .try_into()
                .unwrap();
        let address = stellar_address(&public_key);
        assert_eq!(
            address,
            "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"
        );
        assert!(StellarScheme::validate_address(&address).is_ok());
    }

    #[test]
    fn line_index_maps_to_stellar_path() {
        assert_eq!(
            StellarScheme::derivation_path(1_837_201),
            "m/44'/148'/1837201'"
        );
    }
}
