#![recursion_limit="1024"]

extern crate proc_macro;
extern crate quote;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn, Path};

use crate::generator::CodeGenerator;

mod generator;
mod tcgen;
mod parser;

#[proc_macro]
pub fn target(tokens: TokenStream) -> TokenStream {
    let target = parse_macro_input!(tokens as parser::Target);
    println!("{:?}", target);
    let body = CodeGenerator::new(&target).generate_fuzzer();
    println!("{}", body);
    body.into()
}

#[proc_macro_attribute]
pub fn print_corpus(attr: TokenStream, item: TokenStream) -> TokenStream {
    let func: ItemFn = parse_macro_input!(item);
    let path: Path = parse_macro_input!(attr);
    let body = tcgen::TcTracer::new(&path, &func).compile();
    println!("{}", body);
    body.into()
}
