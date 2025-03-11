use std::{fmt::Debug, io::Cursor};

use byteorder::{LittleEndian, WriteBytesExt};
use crc32fast;
use rand;

pub trait ProtocolExtender: Send + Debug {
    // tokio_kcp needs this beforehand when caculate mtu
    fn header_len(&self) -> u16;

    // When receive udp datagram, firstly call recv() to modify the data, then pass it to kcp.
    fn recv(&mut self, data: Vec<u8>) -> Vec<u8>;

    // When kcp tries to send data, firstly call send() to modify the data, then pass it to udp socket.
    fn send(&mut self, data: Vec<u8>) -> Vec<u8>;
}

const CRYPT_NONCE: u16 = 16;
const CRYPT_CRC: u16 = 4;
const CRYPT: u16 = CRYPT_NONCE + CRYPT_CRC;
const FEC: u16 = 0; // TODO
const OVERHEAD: u16 = CRYPT + FEC;

#[derive(Debug, Clone, Copy)]
pub struct KcpTun {}

impl KcpTun {
    pub fn new() -> Self {
        Self {}
    }
}

impl ProtocolExtender for KcpTun {
    fn header_len(&self) -> u16 {
        OVERHEAD
    }

    // trip
    fn recv(&mut self, data: Vec<u8>) -> Vec<u8> {
        let d = data[(OVERHEAD as usize)..].to_vec();
        // TODO use checksum result
        d
    }

    // extend
    fn send(&mut self, mut data: Vec<u8>) -> Vec<u8> {
        let mut d = vec![0u8; OVERHEAD as usize];
        d.append(&mut data);
        let mut cur = Cursor::new(d);

        // No ops for FEC because we don't support yet.

        // write nonce
        let _ = WriteBytesExt::write_u64::<LittleEndian>(&mut cur, rand::random::<u64>());

        // write checksum
        let d_slice = cur.get_ref().as_slice();
        let checksum = crc32fast::hash(&d_slice[(CRYPT as usize)..]);
        cur.set_position(CRYPT_NONCE as u64);
        let _ = WriteBytesExt::write_u32::<LittleEndian>(&mut cur, checksum);

        cur.into_inner()
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_extender() {
        let ret = crc32fast::hash("hello".as_bytes());

        println!("ret {}", ret);

        let data: u64 = rand::random();
        println!("data {}", data);
    }
}
