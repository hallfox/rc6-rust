use std::env;
use std::cmp;
use std::fmt;
use std::num::ParseIntError;
use std::str::FromStr;

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Rc6 {
    /// Represents the registers used for RC6-32/20/b encryption
    reg_a: u32,
    reg_b: u32,
    reg_c: u32,
    reg_d: u32,
}

impl Rc6 {
    pub fn new(a: u32, b: u32, c: u32, d: u32) -> Self {
        Rc6 { reg_a: a, reg_b: b, reg_c: c, reg_d: d }
    }
    
    fn key_schedule(key: &Vec<u32>) -> Box<[u32]> {
        let r = 20;
        let sched_size = 2*r+4;
        let qw = 0x9E37_79B9u32;
        let c = key.len();
        let mut sched = vec![0u32; sched_size].into_boxed_slice();
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

    println!("Input: {}", input_file);
    println!("Output: {}", output_file);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt() {
        let rc6 = Rc6::new(0, 0, 0, 0);
        let key: Vec<u32> = vec![0, 0, 0, 0];
        let enc = rc6.encrypt(&key);
        let res = "8f c3 a5 36 56 b1 f7 78 c1 29 df 4e 98 48 a4 1e";
        assert_eq!(enc.text(), res);
    }

    #[test]
    fn test_bad_string() {
        let s1 = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
        let rc6 = Rc6::new(0, 0, 0, 0);
        assert_eq!(Ok(rc6), s1.parse::<Rc6>());

        let s2 = "ff ee dd cc 00 00 00 00 10 00 ce 01 00 00 00 00";
        let rc6_2 = Rc6::new(0xccddeeff, 0, 0x01ce0010, 0);
        assert_eq!(Ok(rc6_2), s2.parse::<Rc6>());

        let bad = "ff ee dd cc gg 00 00 00 10 00 ce 01 00 00 00 00";
        assert!(bad.parse::<Rc6>().is_err());

    }
}
