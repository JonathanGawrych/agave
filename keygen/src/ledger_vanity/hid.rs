use {
    solana_remote_wallet::{ledger::is_valid_ledger, remote_wallet::is_valid_hid_device},
    std::{cmp::min, fmt},
};

const APDU_TAG: u8 = 0x05;
const APDU_CLASS: u8 = 0xe0;
const TRANSPORT_HEADER_LENGTH: usize = 5;
const APDU_HEADER_LENGTH: usize = 7;
const MAX_APDU_DATA_LENGTH: usize = 255;

#[cfg(windows)]
const HID_PREFIX_LENGTH: usize = 1;
#[cfg(not(windows))]
const HID_PREFIX_LENGTH: usize = 0;

const HID_PACKET_LENGTH: usize = 64 + HID_PREFIX_LENGTH;

#[derive(Debug)]
pub enum Error {
    Hid(hidapi::HidError),
    Status(u16),
    Protocol(String),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hid(error) => write!(formatter, "USB error: {error}"),
            Self::Status(status) => write!(formatter, "Ledger status 0x{status:04x}"),
            Self::Protocol(message) => write!(formatter, "Ledger protocol error: {message}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<hidapi::HidError> for Error {
    fn from(error: hidapi::HidError) -> Self {
        Self::Hid(error)
    }
}

pub struct LedgerDevice {
    device: hidapi::HidDevice,
    path: String,
}

impl LedgerDevice {
    pub fn open(index: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let api = hidapi::HidApi::new()?;
        let mut devices: Vec<_> = api
            .device_list()
            .filter(|device| {
                is_valid_ledger(device.vendor_id(), device.product_id())
                    && is_valid_hid_device(device.usage_page(), device.interface_number())
            })
            .collect();
        devices.sort_by_key(|device| device.path().to_owned());

        if devices.is_empty() {
            return Err(
                "no Ledger devices found. Close Ledger Live, then confirm the device is plugged in and unlocked"
                    .into(),
            );
        }
        let device = devices.get(index).ok_or_else(|| {
            format!(
                "--device {index} is out of range; {} detected. Use --list-devices",
                devices.len()
            )
        })?;
        let path = device.path().to_string_lossy().to_string();
        let handle = device.open_device(&api)?;
        Ok(Self {
            device: handle,
            path,
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn exchange(
        &self,
        instruction: u8,
        parameter1: u8,
        parameter2: u8,
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.write(instruction, parameter1, parameter2, data)?;
        self.read()
    }

    fn write(
        &self,
        instruction: u8,
        parameter1: u8,
        parameter2: u8,
        data: &[u8],
    ) -> Result<(), Error> {
        if data.len() > MAX_APDU_DATA_LENGTH {
            return Err(Error::Protocol(format!(
                "APDU data is {} bytes; maximum is {MAX_APDU_DATA_LENGTH}",
                data.len()
            )));
        }

        let mut offset = 0;
        let mut sequence_number = 0u16;
        while sequence_number == 0 || offset < data.len() {
            let header_length = if sequence_number == 0 {
                TRANSPORT_HEADER_LENGTH + APDU_HEADER_LENGTH
            } else {
                TRANSPORT_HEADER_LENGTH
            };
            let size = min(64 - header_length, data.len() - offset);
            let mut packet = [0u8; HID_PACKET_LENGTH];
            let packet_without_prefix = &mut packet[HID_PREFIX_LENGTH..];
            packet_without_prefix[..TRANSPORT_HEADER_LENGTH].copy_from_slice(&[
                0x01,
                0x01,
                APDU_TAG,
                (sequence_number >> 8) as u8,
                sequence_number as u8,
            ]);
            if sequence_number == 0 {
                let apdu_length = data.len() + 5;
                packet_without_prefix[5..12].copy_from_slice(&[
                    (apdu_length >> 8) as u8,
                    apdu_length as u8,
                    APDU_CLASS,
                    instruction,
                    parameter1,
                    parameter2,
                    data.len() as u8,
                ]);
            }
            packet_without_prefix[header_length..header_length + size]
                .copy_from_slice(&data[offset..offset + size]);

            let written = self.device.write(&packet)?;
            if written < header_length + size {
                return Err(Error::Protocol("short HID write".to_string()));
            }
            offset += size;
            sequence_number = sequence_number
                .checked_add(1)
                .ok_or_else(|| Error::Protocol("too many HID packets".to_string()))?;
        }
        Ok(())
    }

    fn read(&self) -> Result<Vec<u8>, Error> {
        let mut message_length = None;
        let mut message = Vec::new();
        for sequence_number in 0u16..=u16::MAX {
            let mut packet = [0u8; HID_PACKET_LENGTH];
            let packet_length = self.device.read(&mut packet)?;
            if packet_length < TRANSPORT_HEADER_LENGTH
                || packet[0] != 0x01
                || packet[1] != 0x01
                || packet[2] != APDU_TAG
            {
                return Err(Error::Protocol("unexpected HID packet header".to_string()));
            }
            let received_sequence = u16::from_be_bytes([packet[3], packet[4]]);
            if received_sequence != sequence_number {
                return Err(Error::Protocol(format!(
                    "expected HID packet {sequence_number}, got {received_sequence}"
                )));
            }

            let mut offset = TRANSPORT_HEADER_LENGTH;
            if sequence_number == 0 {
                if packet_length < 7 {
                    return Err(Error::Protocol("short first HID packet".to_string()));
                }
                message_length = Some(u16::from_be_bytes([packet[5], packet[6]]) as usize);
                offset += 2;
            }
            message.extend_from_slice(&packet[offset..packet_length]);
            let expected_length = message_length.expect("first packet sets message length");
            message.truncate(expected_length);
            if message.len() == expected_length {
                break;
            }
        }

        if message.len() < 2 {
            return Err(Error::Protocol("response has no status word".to_string()));
        }
        let status_offset = message.len() - 2;
        let status = u16::from_be_bytes([message[status_offset], message[status_offset + 1]]);
        if status != 0x9000 {
            return Err(Error::Status(status));
        }
        message.truncate(status_offset);
        Ok(message)
    }
}

pub fn list_devices() -> Result<(), Box<dyn std::error::Error>> {
    let api = hidapi::HidApi::new()?;
    let mut devices: Vec<_> = api
        .device_list()
        .filter(|device| {
            is_valid_ledger(device.vendor_id(), device.product_id())
                && is_valid_hid_device(device.usage_page(), device.interface_number())
        })
        .collect();
    devices.sort_by_key(|device| device.path().to_owned());
    for (index, device) in devices.iter().enumerate() {
        println!(
            "[{index}] model={:?} path={} vid={:04x} pid={:04x} serial={:?}",
            device.product_string().unwrap_or("?"),
            device.path().to_string_lossy(),
            device.vendor_id(),
            device.product_id(),
            device.serial_number().unwrap_or("?"),
        );
    }
    if devices.is_empty() {
        println!("no Ledger devices found (is Ledger Live holding the handle?)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_nano_s_plus_product_ids() {
        assert!(is_valid_ledger(0x2c97, 0x0005));
        for product_id in 0x5000..=0x501f {
            assert!(is_valid_ledger(0x2c97, product_id));
        }
        assert!(!is_valid_ledger(0x2c97, 0x5020));
    }
}
