use std::env;
use std::cmp;
use std::fmt;
use std::num::ParseIntError;
use std::str;
use std::str::FromStr;
use std::fs::File;
use std::io::prelude::*;
use std::error::Error;

/// Represents the registers used for RC6-32/20/b encryption
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Rc6 {
    /// Each u32 nicely represents a register
    reg_a: u32,
    reg_b: u32,
    reg_c: u32,
    reg_d: u32,
}

impl Rc6 {
    pub fn new(a: u32, b: u32, c: u32, d: u32) -> Self {
        Rc6 { reg_a: a, reg_b: b, reg_c: c, reg_d: d }
    }

    /// Generate the key schedule based off of the userkey
    fn key_schedule(key: &Vec<u32>) -> Box<[u32]> {
        let r = 20;
        let sched_size = 2*r+4;
        // Constant from paper
        let qw = 0x9E37_79B9u32;
        let c = key.len();
        let mut sched = vec![0u32; sched_size].into_boxed_slice();
        // Constant from paper
        sched[0] = 0xB7E1_5163u32;

        for i in 1..sched_size {
            sched[i] = sched[i-1].wrapping_add(qw);
        }

        let (mut a, mut b, mut i, mut j) = (0u32, 0u32, 0, 0);
        let mut key_buffer = key.as_slice().to_owned();
        let v = 3 * cmp::max(c, sched_size);
        let mask = (1u32 << 5) - 1;
        for _ in 0..v {
            let t = sched[i].wrapping_add(a)
                .wrapping_add(b)
                .rotate_left(3);
            a = t;
            sched[i] = t;

            let u = key_buffer[j].wrapping_add(a)
                .wrapping_add(b)
                .rotate_left(a.wrapping_add(b) & mask);
            b = u;
            key_buffer[j] = u;

            i = (i+1) % sched_size;
            j = (j+1) % c;
        }
        sched
    }

    /// Uses the current registers to run RC6 encryption using key,
    /// returns a new set of registers
    pub fn encrypt(&self, key: &Vec<u32>) -> Self {
        let r = 20;
        let mut e_rc6 = *self; // Copy
        let sched = Self::key_schedule(key);
        let mask = (1u32 << 5) - 1;
        e_rc6.reg_b = e_rc6.reg_b.wrapping_add(sched[0]);
        e_rc6.reg_d = e_rc6.reg_d.wrapping_add(sched[1]);
        for i in 1..r+1 {
            let t = Self::round(e_rc6.reg_b);
            let u = Self::round(e_rc6.reg_d);
            e_rc6.reg_a = (e_rc6.reg_a ^ t).rotate_left(u & mask)
                .wrapping_add(sched[2*i]);
            e_rc6.reg_c = (e_rc6.reg_c ^ u).rotate_left(t & mask)
                .wrapping_add(sched[2*i+1]);

            let a_temp = e_rc6.reg_a;
            e_rc6.reg_a = e_rc6.reg_b;
            e_rc6.reg_b = e_rc6.reg_c;
            e_rc6.reg_c = e_rc6.reg_d;
            e_rc6.reg_d = a_temp;
        }
        e_rc6.reg_a = e_rc6.reg_a.wrapping_add(sched[2*r+2]);
        e_rc6.reg_c = e_rc6.reg_c.wrapping_add(sched[2*r+3]);
        e_rc6
    }

    /// Uses the current set of registers to run RC6 decryption using
    /// key, returns a new set of registers
    pub fn decrypt(&self, key: &Vec<u32>) -> Self {
        let r = 20;
        let mut d_rc6 = *self;
        let sched = Self::key_schedule(key);
        d_rc6.reg_c = d_rc6.reg_c.wrapping_sub(sched[2*r+3]);
        d_rc6.reg_a = d_rc6.reg_a.wrapping_sub(sched[2*r+2]);

        for i in (1..r+1).rev() {
            // Rotate the registers
            let d_temp = d_rc6.reg_d;
            d_rc6.reg_d = d_rc6.reg_c;
            d_rc6.reg_c = d_rc6.reg_b;
            d_rc6.reg_b = d_rc6.reg_a;
            d_rc6.reg_a = d_temp;

            let u = Self::round(d_rc6.reg_d);
            let t = Self::round(d_rc6.reg_b);
            d_rc6.reg_c = d_rc6.reg_c.wrapping_sub(sched[2*i+1]).rotate_right(t) ^ u;
            d_rc6.reg_a = d_rc6.reg_a.wrapping_sub(sched[2*i]).rotate_right(u) ^ t;
        }

        d_rc6.reg_d = d_rc6.reg_d.wrapping_sub(sched[1]);
        d_rc6.reg_b = d_rc6.reg_b.wrapping_sub(sched[0]);

        d_rc6
    }

    /// Underlying rounding function, f(x) = x*(2x + 1) mod 2^32
    fn round(reg: u32) -> u32 {
        let rot = 5; // lg(32)
        let t = (reg << 1) + 1;
        reg.wrapping_mul(t).rotate_left(rot)
    }

}

impl FromStr for Rc6 {
    type Err = ParseIntError;

    fn from_str(plaintext: &str) -> Result<Self, <Self as FromStr>::Err> {
        let bytes: Vec<_> = plaintext.split_whitespace()
            .map(|s| u8::from_str_radix(s, 16))
            .collect();
        let mut regs = [0u32; 4];
        for (i, chunk) in bytes.chunks(4).enumerate() {
            for b in chunk {
                let r = try!(b.to_owned()) as u32;
                regs[i] = (regs[i] << 8) | r;
            }
            regs[i] = regs[i].swap_bytes();
        }
        Ok(Self::new(regs[0], regs[1], regs[2], regs[3]))
    }
}

impl fmt::Debug for Rc6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Rc6 {{ reg_a: {:#x}, reg_b: {:#x}, reg_c: {:#x}, reg_d: {:#x} }}",
               self.reg_a, self.reg_b, self.reg_c, self.reg_d)
    }
}

impl fmt::Display for Rc6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut bytes = Vec::new();
        for r in &[self.reg_a, self.reg_b, self.reg_c, self.reg_d] {
            for i in 0..4 {
                let b = (r >> (8*i)) as u8;
                bytes.push(format!("{:02x}", b));
            }
        }
        write!(f, "{}", bytes.join(" "))
    }
}

fn main() {
    let mut args = env::args().skip(1);
    let input_file = args.next().unwrap();
    let output_file = args.next().unwrap();

    let mut input = match File::open(&input_file) {
        Ok(f) => f,
        Err(why) => panic!("Could not open {}: {}", input_file, why.description())
    };

    let mut contents = String::new();
    input.read_to_string(&mut contents).expect("Couldn't load file contents");

    let mut outfile = File::create(output_file).expect("Couldn't open output file");

    let mut lines = contents.lines();
    if let Some(mode) = lines.next() {
        if mode == "Encryption" {
            outfile.write_all(encrypt(lines).as_bytes())
                .expect("Couldn't write encrypted message to file.");
        } else if mode == "Decryption" {
            outfile.write_all(decrypt(lines).as_bytes())
                .expect("Couldn't write decrypted message to file.");
        } else {
            panic!("Couldn't figure out whether to encrypt or decrypt: {}", mode);
        }
    }
}

fn encrypt(mut data: str::Lines) -> String {
    let plaintext = data.next()
        .expect("Couldn't read plaintext")
        .trim_left_matches("plaintext: ")
        .parse::<Rc6>()
        .expect("Couldn't parse plaintext as valid RC6 input");
    let keytext = data.next()
        .expect("Couldn't read key")
        .trim_left_matches("userkey: ");
    let key = read_key(keytext).expect("Couldn't parse key");

    format!("ciphertext: {}\n", plaintext.encrypt(&key))
}

fn decrypt(mut data: str::Lines) -> String {
    let ciphertext = data.next()
        .expect("Couldn't read ciphertext")
        .trim_left_matches("ciphertext: ")
        .parse::<Rc6>()
        .expect("Couldn't parse ciphertext as valid RC6 input");
    let keytext = data.next()
        .expect("Couldn't read key")
        .trim_left_matches("userkey: ");
    let key = read_key(keytext).expect("Couldn't parse key");

    format!("plaintext: {}\n", ciphertext.decrypt(&key))

}

pub fn read_key(key_str: &str) -> Result<Vec<u32>, ParseIntError> {
    let bytes: Vec<_> = key_str.split_whitespace()
        .map(|s| u8::from_str_radix(s, 16))
        .collect();
    let mut words = Vec::new();
    for chunk in bytes.chunks(4) {
        let mut word = 0u32;
        for b in chunk {
            let r = try!(b.to_owned()) as u32;
            word = (word << 8) | r;
        }
        words.push(word.swap_bytes());
    }
    Ok(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt() {
        let rc6 = Rc6::new(0, 0, 0, 0);
        let key = vec![0u32; 4];
        let enc = rc6.encrypt(&key);
        let res = "8f c3 a5 36 56 b1 f7 78 c1 29 df 4e 98 48 a4 1e";
        assert_eq!(enc.to_string(), res);

        let key2 = vec![0x67452301, 0xefcdab89, 0x34231201, 0x78675645];
        let enc2 = "02 13 24 35 46 57 68 79 8a 9b ac bd ce df e0 f1".parse::<Rc6>().unwrap().encrypt(&key2);
        let res2 = "52 4e 19 2f 47 15 c6 23 1f 51 f6 36 7e a4 3f 18";
        assert_eq!(enc2.to_string(), res2);
    }

    #[test]
    fn string_parse() {
        let s1 = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
        let rc6 = Rc6::new(0, 0, 0, 0);
        assert_eq!(Ok(rc6), s1.parse::<Rc6>());

        let s2 = "02 13 24 35 46 57 68 79 8a 9b ac bd ce df e0 f1";
        let rc6_2 = Rc6::new(0x35241302, 0x79685746, 0xbdac9b8a, 0xf1e0dfce);
        assert_eq!(Ok(rc6_2), s2.parse::<Rc6>());

        let bad = "ff ee dd cc gg 00 00 00 10 00 ce 01 00 00 00 00";
        assert!(bad.parse::<Rc6>().is_err());

    }

    #[test]
    fn inverse() {
        // Encrypt and decrypt should be inverses of each other
        let rc6 = Rc6::new(0, 0, 0, 0);
        let key = vec![0u32; 4];
        assert_eq!(rc6, rc6.encrypt(&key).decrypt(&key));

        let s2 = "02 13 24 35 46 57 68 79 8a 9b ac bd ce df e0 f1";
        let rc6_2 = s2.parse::<Rc6>();
        match rc6_2 {
            Ok(v) => assert_eq!(v, v.encrypt(&key).decrypt(&key)),
            _ => assert!(false)
        }
    }

    #[test]
    fn decrypt() {
        let key = vec![0u32; 4];
        let dec = "8f c3 a5 36 56 b1 f7 78 c1 29 df 4e 98 48 a4 1e".parse::<Rc6>().unwrap().decrypt(&key);
        let res = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
        assert_eq!(dec.to_string(), res);

        let key2 = vec![0x67452301, 0xefcdab89, 0x34231201, 0x78675645];
        let dec2 = "52 4e 19 2f 47 15 c6 23 1f 51 f6 36 7e a4 3f 18".parse::<Rc6>().unwrap().decrypt(&key2);
        let res2 = "02 13 24 35 46 57 68 79 8a 9b ac bd ce df e0 f1";
        assert_eq!(dec2.to_string(), res2);

    }

    #[test]
    fn test_key() {
        let k1 = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
        let k1_vec = vec![0u32; 4];
        assert_eq!(k1_vec, read_key(k1).unwrap());

        let k2 = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
        let k2_vec = vec![0u32; 6];
        assert_eq!(k2_vec, read_key(k2).unwrap());
    }
}
