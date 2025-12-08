use std::fs::File;
use std::io::{BufReader, Read};
use std::iter::{Enumerate, Peekable};

const INVALID: u32 = 0xffffffff;

fn decode_bits<'a>(
    bitpos: &mut Peekable<Enumerate<impl Iterator<Item = &'a bool>>>,
    minval: u8,
    bit_sizes: Vec<u8>,
) -> u32 {
    let mut val: u32 = minval.into();
    let mut bit: bool;
    let mut bit_sizes_it = bit_sizes.iter().peekable();
    while let Some(bit_size) = bit_sizes_it.next() {
        if bit_sizes_it.peek().is_some() {
            if bitpos.peek().is_none() {
                break;
            }
            bit = *bitpos.next().unwrap().1;
        } else {
            bit = false;
        }
        if bit {
            val += 1 << bit_size;
        } else {
            for b in 0..*bit_size {
                if bitpos.peek().is_none() {
                    return INVALID;
                }
                bit = *bitpos.next().unwrap().1;
                if bit {
                    val += 1 << (bit_size - 1 - b);
                }
            }
            return val;
        }
    }
    INVALID
}

#[derive(PartialEq)]
enum Instruction {
    Return = 0,
    Jump = 1,
    Match = 2,
    Default = 3,
    End = 4,
}

impl TryFrom<u32> for Instruction {
    type Error = ();

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        match v {
            x if x == Instruction::Return as u32 => Ok(Instruction::Return),
            x if x == Instruction::Jump as u32 => Ok(Instruction::Jump),
            x if x == Instruction::Match as u32 => Ok(Instruction::Match),
            x if x == Instruction::Default as u32 => Ok(Instruction::Default),
            x if x == Instruction::End as u32 => Ok(Instruction::End),
            _ => Err(()),
        }
    }
}

const TYPE_BIT_SIZES: [u8; 3] = [0, 0, 1];
fn decode_type<'a>(
    bitpos: &mut Peekable<Enumerate<impl Iterator<Item = &'a bool>>>,
) -> Instruction {
    Instruction::try_from(decode_bits(bitpos, 0, Vec::from(TYPE_BIT_SIZES))).unwrap()
}

const ASN_BIT_SIZES: [u8; 10] = [15, 16, 17, 18, 19, 20, 21, 22, 23, 24];
fn decode_asn<'a>(bitpos: &mut Peekable<Enumerate<impl Iterator<Item = &'a bool>>>) -> u32 {
    decode_bits(bitpos, 1, Vec::from(ASN_BIT_SIZES))
}

const MATCH_BIT_SIZES: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
fn decode_match<'a>(bitpos: &mut Peekable<Enumerate<impl Iterator<Item = &'a bool>>>) -> u32 {
    decode_bits(bitpos, 2, Vec::from(MATCH_BIT_SIZES))
}

const JUMP_BIT_SIZES: [u8; 26] = [
    5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
    30,
];
fn decode_jump<'a>(bitpos: &mut Peekable<Enumerate<impl Iterator<Item = &'a bool>>>) -> u32 {
    decode_bits(bitpos, 17, Vec::from(JUMP_BIT_SIZES))
}

pub fn interpret(asmap: &[bool], ip: Vec<bool>) -> u32 {
    let mut pos = asmap.iter().enumerate().peekable();
    let mut bits = ip.len();
    let mut asn = 0;
    while pos.peek().is_some() {
        let opcode = decode_type(&mut pos);
        match opcode {
            Instruction::Return => {
                asn = decode_asn(&mut pos);
                if asn == INVALID {
                    break;
                }
                return asn;
            }
            Instruction::Jump => {
                let jump = decode_jump(&mut pos);
                if jump == INVALID || bits == 0 {
                    break;
                }
                if ip[ip.len() - bits] {
                    let actual_jump = jump - 1;
                    pos.nth(actual_jump.try_into().unwrap());
                }
                bits -= 1;
            }
            Instruction::Match => {
                let matched = decode_match(&mut pos);
                if matched == INVALID {
                    break;
                }
                let matchedlen = u32::BITS - matched.leading_zeros() - 1;
                if bits < matchedlen.try_into().unwrap() {
                    break;
                }
                for bit in 0..matchedlen {
                    if ip[ip.len() - bits] != ((matched >> (matchedlen - 1 - bit)) & 1 == 1) {
                        return asn;
                    }
                    bits -= 1;
                }
            }
            Instruction::Default => {
                asn = decode_asn(&mut pos);
                if asn == INVALID {
                    break;
                }
            }
            _ => {
                break;
            }
        }
    }

    panic!();
}

fn sanity_check_asmap(asmap: &[bool], mut bits: usize) -> bool {
    let mut iter = asmap.iter().enumerate().peekable();
    let mut jumps = Vec::<(usize, usize)>::with_capacity(bits);
    let mut prev_opcode = Instruction::Jump;
    let mut had_incomplete_match = false;
    while iter.peek().is_some() {
        let mut offset = iter.peek().unwrap().0;
        if !jumps.is_empty() && offset >= jumps.last().unwrap().0 {
            return false;
        }
        let opcode = decode_type(&mut iter);
        match opcode {
            Instruction::Return => {
                if prev_opcode == Instruction::Default {
                    return false;
                }
                let asn = decode_asn(&mut iter);
                if asn == INVALID {
                    return false;
                }
                if jumps.is_empty() {
                    for _ in 0..8 {
                        if let Some(i) = iter.next() {
                            if *i.1 {
                                return false;
                            }
                        }
                    }
                    if iter.next().is_some() {
                        return false;
                    }
                    return true;
                } else {
                    offset = iter.peek().unwrap().0;
                    if offset != jumps.last().unwrap().0 {
                        return false;
                    }
                    bits = jumps.last().unwrap().1;
                    jumps.pop();
                    prev_opcode = Instruction::Jump;
                }
            }
            Instruction::Jump => {
                let jump = decode_jump(&mut iter) as usize;
                if jump == INVALID.try_into().unwrap() {
                    return false;
                }
                if jump > asmap.len() - iter.peek().unwrap().0 {
                    return false;
                }
                if bits == 0 {
                    return false;
                }
                bits -= 1;
                let jump_offset = iter.peek().unwrap().0 + jump;
                if !jumps.is_empty() && jump_offset >= jumps.last().unwrap().0 {
                    return false;
                }
                jumps.push((jump_offset, bits));
                prev_opcode = Instruction::Jump;
            }
            Instruction::Match => {
                let matched = decode_match(&mut iter);
                if matched == INVALID {
                    return false;
                }
                let matchedlen = (u32::BITS - matched.leading_zeros() - 1) as usize;
                if prev_opcode != Instruction::Match {
                    had_incomplete_match = false;
                }
                if matchedlen < 8 && had_incomplete_match {
                    return false;
                }
                had_incomplete_match = matchedlen < 8;
                if bits < matchedlen {
                    return false;
                }
                bits -= matchedlen;
                prev_opcode = Instruction::Match;
            }
            Instruction::Default => {
                if prev_opcode == Instruction::Default {
                    return false;
                }
                let asn = decode_asn(&mut iter);
                if asn == INVALID {
                    break;
                }
                prev_opcode = Instruction::Default;
            }
            _ => {
                return false;
            }
        }
    }
    false
}

pub fn decode_asmap(path: &str) -> Vec<bool> {
    let mut bits = Vec::<bool>::new();
    let f = BufReader::new(File::open(path).unwrap());
    for b in f.bytes() {
        let byte = b.unwrap();
        for bit in 0..8 {
            bits.push(((byte >> bit) & 1) == 1);
        }
    }
    if !sanity_check_asmap(&bits, 128) {
        panic!("Invalid ASMap");
    }
    bits
}
