use pdb::{FallibleIterator, PDB, SymbolData};
use std::{collections::HashMap, fs::File, time::Instant};

use crate::{analyze::AnalyzedBin, bin::Bin, function::align_up, prelude::*};

#[derive(Debug, Default, Clone)]
pub struct Symbols {
    pub code: HashMap<usize, Box<str>>,
    pub data: HashMap<usize, Box<str>>,
}

impl Symbols {
    pub fn from_file(file: File) -> Self {
        let mut pdb = PDB::open(file).unwrap();

        let dbi = pdb.debug_information().unwrap();

        // Read the tables once and reuse them
        let address_map = pdb.address_map().unwrap();

        let symbol_table = pdb.global_symbols().unwrap();
        let mut symbols = symbol_table.iter();

        let mut sym_table = Symbols::default();

        while let Some(symbol) = symbols.next().unwrap() {
            match symbol.parse() {
                Ok(SymbolData::Data(data)) => {
                    let rva = data.offset.to_rva(&address_map).unwrap();

                    sym_table
                        .data
                        .insert(rva.0 as usize, data.name.to_string().into());
                }
                Ok(SymbolData::Public(data)) if data.function => {
                    let rva = data.offset.to_rva(&address_map).unwrap();

                    sym_table
                        .code
                        .insert(rva.0 as usize, data.name.to_string().into());
                }
                // Ok(SymbolData::ProcedureReference(data)) => {
                //     // let symbol_table = pdb.global_symbols().unwrap();
                //     // let mut symbols = symbol_table.iter();
                //     // let s = symbols.skip_to(data.symbol_index);

                //     // dbg!(s, data.name);

                //     // dbg!(data.symbol_index.0, data.module, data.name);
                //     // let mut it = symbol_table.iter();
                //     // let sym = it.skip_to(data.symbol_index).unwrap();

                //     // dbg!(sym);

                //     // data.symbol_index
                //     //
                //     // data.symbol_index
                //     // let rva = data.offset.to_rva(&address_map).unwrap();

                //     // sym_table.code.insert(
                //     //     data.symbol_index.0 as usize,
                //     //     data.name.unwrap().to_string().into(),
                //     // );

                //     // dbg!(data.name.unwrap());
                // }
                _ => {}
            }
        }

        sym_table
    }
}
