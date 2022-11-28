#![recursion_limit="1024"]

extern crate proc_macro;
extern crate quote;

use proc_macro::TokenStream;
use quote::quote;
use syn::parse_macro_input;

use crate::generator::CodeGenerator;

mod generator;
mod parser;

#[proc_macro]
pub fn target(tokens: TokenStream) -> TokenStream {
    let target = parse_macro_input!(tokens as parser::Target);
    println!("{:?}", target);
    let body = CodeGenerator::new(&target).generate_fuzzer();
    println!("{}", body);
    body.into()

}
