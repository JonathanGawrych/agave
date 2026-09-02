use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::Path,
};

pub const MAX_INDEX: u32 = 1 << 31;

pub struct AddressFile {
    out: BufWriter<File>,
}

impl AddressFile {
    pub fn open(path: &Path) -> Result<(Self, u32), Box<dyn std::error::Error>> {
        let mut next_index = 1;
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
                next_index = line_count as u32 + 1;
            }
        }

        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok((
            Self {
                out: BufWriter::new(file),
            },
            next_index,
        ))
    }

    pub fn record(&mut self, address: &str) -> std::io::Result<()> {
        writeln!(self.out, "{address}")
    }

    pub fn flush(&mut self) -> std::io::Result<()> {
        self.out.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_number_is_derivation_index() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("addresses.txt");
        let (mut addresses, next_index) = AddressFile::open(&path).unwrap();
        assert_eq!(next_index, 1);
        addresses.record("first").unwrap();
        addresses.record("second").unwrap();
        drop(addresses);

        let lines: Vec<String> = BufReader::new(File::open(&path).unwrap())
            .lines()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(lines, ["first", "second"]);

        let (_, next_index) = AddressFile::open(&path).unwrap();
        assert_eq!(next_index, 3);
    }

    #[test]
    fn incomplete_final_line_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("addresses.txt");
        std::fs::write(&path, "incomplete").unwrap();

        let error = match AddressFile::open(&path) {
            Ok(_) => panic!("incomplete line was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("incomplete line"));
    }
}
