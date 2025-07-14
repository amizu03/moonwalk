#![feature(optimize_attribute, vec_pop_if, let_chains, unsigned_signed_diff)]
#![allow(unused_variables, dead_code, warnings)]

mod analyze;
mod bin;
mod error;
mod function;
mod mapper;
mod obfuscator;
mod pdb;
mod prelude;

use std::{collections::HashMap, fs::File};

use function::{decode_single_instruction, fmt_flags};
use iced_x86::{Decoder, DecoderOptions, code_asm::CodeAssembler};

use crate::prelude::*;

fn main() -> Result<()> {
    use bin::Bin;
    use obfuscator::Obfuscator;

    let mut analyzed = Bin::load("input/lotus_kmd.dll")?.analyze();

    let mut asm = CodeAssembler::new(64).unwrap();

    let out = Obfuscator::new(0x0).scatter(&analyzed, &[0x1A3A])?;

    std::fs::write("input/lotus_kmd.bin", out).unwrap();

    Ok(())
}
