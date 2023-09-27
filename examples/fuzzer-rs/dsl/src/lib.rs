#![recursion_limit="1024"]

extern crate proc_macro;
extern crate quote;

use proc_macro::TokenStream;
use quote::{quote, TokenStreamExt};
use syn::{parse_macro_input, ItemFn, Path, DeriveInput, parse::Parser, Ident};
use tcgen::TcTracer;
use crate::{generator::CodeGenerator, tcgen::{TcGenerator, TcgenCtorArgs}};

mod generator;
mod tcgen;
mod parser;

#[proc_macro]
pub fn target(tokens: TokenStream) -> TokenStream {
    let target = parse_macro_input!(tokens as parser::Target);
    println!("{:?}", target);
    let mut body = CodeGenerator::new(&target).generate_fuzzer();
    println!("{}", body);
    let tcs = TcGenerator::new(&target).generate();
    println!("{}", tcs);
    body.append_all(tcs);
    body.into()
}

#[proc_macro]
pub fn impl_id(tokens: TokenStream) -> TokenStream {
    let cls = parse_macro_input!(tokens as Ident);

    quote! {
        impl Id for #cls {
            fn __set_id__(&mut self) {
                self.__id__ = TcAssembler::take().alloc_id(Apis::#cls);
            }

            fn __get_id__(&self) -> usize {
                self.__id__
            }
        }
    }.into()
}

#[proc_macro_attribute]
pub fn tcgen_ctor(attr: TokenStream, item: TokenStream) -> TokenStream {
    let func: ItemFn = parse_macro_input!(item);
    let args: TcgenCtorArgs = parse_macro_input!(attr);
    let body = TcTracer::new(&args.cls, &func, Some(&args.path)).compile_ctor();
    println!("{}", body);
    body.into()
}

#[proc_macro_attribute]
pub fn tcgen_member(attr: TokenStream, item: TokenStream) -> TokenStream {
    let func: ItemFn = parse_macro_input!(item);
    let ident: Ident = parse_macro_input!(attr);
    let body = TcTracer::new(&ident, &func, None).compile_member();
    println!("{}", body);
    body.into()
}

#[proc_macro_attribute]
pub fn tcgen_record(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let func = parse_macro_input!(item as ItemFn);

    let ItemFn {
        attrs,
        vis,
        sig,
        block
    } = func;

    let name = format!("{}", &sig.ident);

    quote! {
        #(#attrs)* #vis #sig {
            TcAssembler::take().enter(#name);
            let mut __ret__ = { #block };
            TcAssembler::take().leave();
            __ret__
        }
    }.into()
}

#[proc_macro_attribute]
pub fn add_id_field(_args: TokenStream, item: TokenStream) -> TokenStream {
    let mut ast = parse_macro_input!(item as DeriveInput);
    match &mut ast.data {
        syn::Data::Struct(ref mut struct_data) => {
            match &mut struct_data.fields {
                syn::Fields::Named(fields) => {
                    fields
                        .named
                        .push(syn::Field::parse_named.parse2(quote!{ __id__: usize }).unwrap());
                }
                _ => {
                    ()
                }
            }

            return quote! {
                #ast
            }.into();
        }
        _ => panic!("`add_id_field` has to be used with structs "),
    }
}
