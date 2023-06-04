use std::{fs, path::PathBuf, str::FromStr};

use crate::{parser::{Expression, Function, Target, ImportLine, Api}, tcgen::TcGenerator};
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{quote, TokenStreamExt, ToTokens};
use syn::{Ident, parse_file, File, token, Path};

#[derive(Debug)]
pub(super) struct ExpressionCompiler {
    it: usize,
    tokens: TokenStream2,
    post: TokenStream2
}

impl ExpressionCompiler {
    pub fn new() -> Self {
        Self {
            it: 0usize,
            tokens: TokenStream2::new(),
            post: TokenStream2::new()
        }
    }

    fn next_label(&mut self) -> Ident {
        let name = format!("__var_{}", self.it);
        self.it += 1;
        Ident::new(&name, Span::call_site())
    }

    pub fn to_code(self) -> (TokenStream2, TokenStream2) {
        (self.tokens, self.post)
    }

    pub fn compile_expr(&mut self, expr: &Expression) -> Ident {
        let label = self.next_label();
        let value = match expr {
            Expression::U8 => quote! { buffer.get_u8()? },
            Expression::U16 => quote! { buffer.get_u16()? },
            Expression::U32 => quote! { buffer.get_u32()? },
            Expression::Usize => quote! { buffer.get_usize()? },
            Expression::Literal(expr) => quote! { #expr },
            Expression::Ref(expr) => {
                let expr = self.compile_expr(expr);
                quote! { &#expr }
            }
            Expression::Vector(size) => {
                let size = self.compile_expr(&size);
                quote! { buffer.vec(#size as usize)? }
            }
            Expression::Slice(size) => {
                let size = self.compile_expr(&size);
                quote! { buffer.slice(#size as usize)? }
            }
            Expression::Eval(eval) => {
                let values: Vec<Ident> = eval
                    .bindings
                    .iter()
                    .map(|i| self.compile_expr(i.value.as_ref()))
                    .collect();
                let names: Vec<&Ident> = eval.bindings.iter().map(|i| &i.name).collect();

                let closure = quote! {
                    #(let mut #names = #values;)*
                };
                self.tokens.append_all(closure);

                let expr = self.compile_expr(&eval.value);
                quote! { #expr }
            }
            Expression::OneOf(list) => {
                let values: Vec<Ident> = list.iter().map(|i| self.compile_expr(&i)).collect();
                let len = list.len() as u8;
                let indexes = 0..len;

                quote! {
                    match buffer.get_u8()? % #len {
                        #(
                            #indexes => #values,
                        )*
                        _ => unreachable!()
                    }
                }
            }
            Expression::Api(name) => {
                let idx_label = self.next_label();
                let val_label = self.next_label();

                self.post.append_all(quote! {
                    buffer.add_cache(Apis::#name, Box::new(Objects::#name(#label)), Some(#idx_label));
                });

                self.tokens.append_all(quote! {
                    let (#val_label, #idx_label) = {
                        let idx = buffer.get_u8()? as usize;
                        let mut __o__ = buffer.get_cache(&Apis::#name, idx);
                        if let None = __o__ {
                            target.fuzz_api(Apis::#name, buffer)?;
                            __o__ = buffer.get_cache(&Apis::#name, idx);
                        }
                        let (obj, el) = __o__.unwrap();
                        if let Objects::#name(__o) = *obj {
                            (__o, el)
                        } else {
                            return Err(FuzzerError::ObjectIsOfInvalidType)
                        }
                    };
                });

                quote! {
                    #val_label
                }
            },
            Expression::EmptyVector => quote! { std::vec::Vec::new() },
            Expression::VectorWithCap(cap, val) => {
                let cap = self.compile_expr(&cap);
                let val = self.compile_expr(&val);

                quote! {
                    {
                        let mut __v = std::vec::Vec::with_capacity(#cap as usize);
                        __v.resize(#cap as usize, #val);
                        __v
                    }
                }
            }
            Expression::RandomVector(_) => {
                // let size = self.compile_expr(&size);

                quote! {
                    // TODO: implement RNG
                }
            }
            Expression::Mut(expr) => {
                let expr = self.compile_expr(&expr);

                quote! { #expr }
            }
            Expression::UsizeArray(size) => {
                let size = self.compile_expr(&size);

                quote! { buffer.usize_array(#size as usize)? }
            }
            Expression::AsSlice(expr) => {
                let expr = self.compile_expr(&expr);

                quote! { #expr.as_slice() }
            }
            Expression::AsMutSlice(expr) => {
                let expr = self.compile_expr(&expr);

                quote! { #expr.as_mut_slice() }
            }
            Expression::Mod(a, b) => {
                let a = self.compile_expr(&a);
                let b = self.compile_expr(&b);

                quote! { #a % #b }
            }
            Expression::Str(size) => {
                let size = self.compile_expr(&size);

                quote! {
                    std::str::from_utf8(buffer.slice(#size as usize)?)
                        .map_err(|_| FuzzerError::Utf8Decoding)?
                        .to_string()
                }
            }
            Expression::StaticStr(size) => {
                let size = self.compile_expr(&size);

                quote! { unsafe { core::mem::transmute<&str, &'static str>(core::str::from_utf8_unchecked(buffer.slice(#size as usize)?)) } }
            }
            Expression::TPMKey() => {
                quote! {
                    buffer.slice(32)?.try_into().unwrap()
                }
            }
        };

        let code = if let Expression::Mut(_) = expr {
            quote! { let mut #label = #value; }
        } else {
            quote! { let #label = #value; }
        };
        self.tokens.append_all(code);

        label
    }
}

impl Into<TokenStream2> for ExpressionCompiler {
    fn into(self) -> TokenStream2 {
        self.tokens
    }
}

impl ToTokens for ExpressionCompiler {
    fn to_tokens(&self, tokens: &mut TokenStream2) {
        tokens.append_all(self.tokens.clone());
    }
}

#[derive(Debug)]
pub(super) struct CodeGenerator<'a> {
    target: &'a Target
}

impl<'a> CodeGenerator<'a> {
    pub fn new(target: &'a Target) -> Self {
        Self { target }
    }

    pub fn generate_fuzzer(self) -> TokenStream2 {
        let name = &self.target.name;
        let imports = self.generate_imports();
        let enums = self.generate_enums();
        let target = self.generate_target();
        let internal = self.generate_internal_module();
        let tcgen = self.generate_tc_generator();

        quote! {
            pub mod #name {
                use optee_utee::trace_println;

                pub mod internal {
                    #internal
                }
                pub use internal::*;
                #enums
                #imports
                #target

                pub fn fuzz(tc: &[u8]) -> Result<(), FuzzerError> {
                    let target = compile();
                    let mut buffer = Buffer::new(tc);
                    target.fuzz(&mut buffer)
                }

                #tcgen
            }
        }
    }

    fn generate_tc_generator(&self) -> TokenStream2 {
        if self.target.opts.tcgen {
            TcGenerator::new(&self.target)
                .generate()
                .into()
        } else {
            quote! {}
        }
    }

    fn generate_ctor_name(&self, name: &Path) -> String {
        format!("{}", name.clone().into_token_stream())
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .replace("::", "_")
    }

    fn generate_ctors_encoding_enum(&self, api: &Api) -> TokenStream2 {
        let names = api.ctors.iter()
            .map(|ctor| Ident::new(&self.generate_ctor_name(&ctor.name).as_str(), Span::call_site()))
            .collect::<Vec<Ident>>();
        let idx = 0isize..names.len() as isize;
        let cls = format!("__ctors_{}", api.name);
        let label = Ident::new(cls.as_str(), Span::call_site());

        quote! {
            #[derive(Debug, Clone, Copy)]
            pub enum #label {
                #(
                    #names = #idx,
                )*
            }
        }
    }

    fn generate_member_encoding_enum(&self, api: &Api) -> TokenStream2 {
        let names = api.functions.iter().map(|func| &func.name).collect::<Vec<&Path>>();
        let idx = 0isize..names.len() as isize;
        let cls = format!("__members_{}", api.name);
        let label = Ident::new(cls.as_str(), Span::call_site());

        quote! {
            #[derive(Debug, Clone, Copy)]
            pub enum #label {
                #(
                    #names = #idx,
                )*
            }
        }
    }

    fn generate_enums(&self) -> TokenStream2 {
        let apis: Vec<&Ident> = self.target.apis.iter().map(|i| &i.name).collect();
        let objs = apis.clone();
        let names = objs.clone();
        let indexes = 0isize..apis.len() as isize;

        let ctor_enums = self.target.apis.iter()
            .map(|api| self.generate_ctors_encoding_enum(api))
            .collect::<Vec<TokenStream2>>();

        let member_enums = self.target.apis.iter()
            .map(|api| self.generate_member_encoding_enum(api))
            .collect::<Vec<TokenStream2>>();

        quote! {
            #[derive(Debug)]
            pub enum Objects {
                #(#apis(#objs)),*,
                None
            }

            #[derive(Debug, Eq, PartialEq, Hash, Copy, Clone)]
            pub enum Apis {
                #(#names = #indexes),*
            }

            pub mod encodings {
                #(
                    #ctor_enums
                )*

                #(
                    #member_enums
                )*
            }
        }
    }

    fn generate_import_line(&self, line: &ImportLine) -> TokenStream2 {
        match line {
            ImportLine::Single(segment, rest) => {
                if let ImportLine::Empty = rest.as_ref() {
                    quote! { #segment }
                } else {
                    let rest = self.generate_import_line(&rest);
                    quote! { #segment::#rest }
                }
            }
            ImportLine::List(list) => {
                let list: Vec<TokenStream2> =
                    list.iter()
                    .map(|i| self.generate_import_line(&i))
                    .collect();

                quote! { { #(#list),* } }
            }
            ImportLine::Glob => quote! { * },
            ImportLine::Super(rest) => {
                let rest = self.generate_import_line(&rest);

                quote! { super::#rest }
            }
            ImportLine::Empty => unreachable!(),
        }
    }

    fn generate_imports(&self) -> TokenStream2 {
        if let Some(imports) = self.target.imports.as_ref() {
            let imports: Vec<TokenStream2> =
                imports
                .list
                .iter()
                .map(|i| self.generate_import_line(&i))
                .collect();

            quote! {
                #(use #imports;)*
            }
        } else {
            quote! {}
        }
    }

    fn generate_trace(&self, obj_name: Option<&Ident>, func: &Function, params: &Vec<Ident>) -> (TokenStream2, TokenStream2) {
        if !self.target.opts.trace {
            return (quote! {}, quote! {});
        }

        let func_name = &func.name;
        let args_fmt = "{:?}, ".repeat(params.len());
        let name = if let Some(obj) = obj_name {
            format!("{}::{}", obj, func_name.clone().into_token_stream())
        } else {
            func_name.clone().into_token_stream().to_string()
        };

        let fmt1: String = [
            "[[TRACE]] [BEGIN] : ",
            name.as_str(),
            "(",
            args_fmt.as_str(),
            ")",
            " => <unfinished>"
        ].into_iter().collect();

        let fmt2: String = [
            "[[TRACE]] [END] : ",
            name.as_str(),
            " => {:?}"
        ].into_iter().collect();

        (
            quote! { unsafe { trace_println!(#fmt1 #(, &#params)*); } },
            quote! { unsafe { trace_println!(#fmt2, ret) } }
        )
    }

    fn generate_ctor(&self, obj_name: &Ident, func: &Function) -> TokenStream2 {
        let mut compiler = ExpressionCompiler::new();
        let params: Vec<Ident> = func.params.iter().map(|i| compiler.compile_expr(&i)).collect();
        let ctor = &func.name;

        let unpack_obj = if func.wrap_ok.is_some() {
            quote! { Ok(Objects::#obj_name(ret)) }
        } else {
            quote! {
                match ret {
                    Ok(o) => Ok(Objects::#obj_name(o)),
                    Err(e) => {
                        unsafe { trace_println!("Failed to create object, reason: {:?}", e); };
                        Err(FuzzerError::FailedToCreateObject)
                    }
                }
            }
        };
        let (trace_begin, trace_end) = self.generate_trace(None, func, &params);
        let (init, deinit) = compiler.to_code();

        quote! {
            |target: &Target, buffer: &mut Buffer| {
                #init
                #trace_begin
                let ret = #ctor(#(#params),*);
                #trace_end
                #deinit
                #unpack_obj
            }
        }
    }

    fn generate_member_function(&self, api_name: &Ident, func: &Function) -> TokenStream2 {
        let func_name = &func.name;
        let mut compiler = ExpressionCompiler::new();
        let params: Vec<Ident> = func.params.iter().map(|i| compiler.compile_expr(&i)).collect();

        let return_value = if func.assign_self.is_some() {
            quote! {
                match ret {
                    Ok(v) => Ok(Objects::#api_name(v)),
                    Err(_) => Ok(Objects::None)
                }
            }
        } else {
            quote! { Ok(Objects::None) }
        };

        let (trace_begin, trace_end) = self.generate_trace(Some(api_name), func, &params);
        let (init, deinit) = compiler.to_code();

        quote! {
            |target: &Target, obj: &mut Objects, buffer: &mut Buffer| {
                if let Objects::#api_name(__o) = obj {
                    #init
                    #trace_begin
                    let ret = #api_name::#func_name(__o #(, #params)*);
                    #trace_end
                    #deinit
                    #return_value
                } else {
                    unsafe { trace_println!("Passed object type does not match expected {}", stringify!(#api_name)); }
                    Err(FuzzerError::ObjectIsOfInvalidType)
                }
            }
        }
    }

    fn generate_nonmember_function(&self, func: &Function) -> TokenStream2 {
        let name = &func.name;
        let mut compiler = ExpressionCompiler::new();
        let params: Vec<Ident> = func.params.iter().map(|i| compiler.compile_expr(&i)).collect();
        let (trace_begin, trace_end) = self.generate_trace(None, func, &params);
        let (init, deinit) = compiler.to_code();

        quote! {
            |target: &Target, buffer: &mut Buffer| {
                #init
                #trace_begin
                let ret = #name(#(#params),*);
                #trace_end
                #deinit
                Ok(())
            }
        }
    }

    fn generate_api(&self, api: &Api) -> TokenStream2 {
        let ctors: Vec<TokenStream2> = api.ctors.iter().map(|i| self.generate_ctor(&api.name, i)).collect();
        let functions: Vec<TokenStream2> = api.functions.iter().map(|i| self.generate_member_function(&api.name, i)).collect();
        let name = &api.name;

        quote! {
            Api::new(
                Apis::#name,
                vec![
                    #(#ctors),*
                ],
                vec![
                    #(#functions),*
                ]
            )
        }
    }

    fn generate_target(&self) -> TokenStream2 {
        let apis: Vec<TokenStream2> = self.target.apis.iter().map(|i| self.generate_api(i)).collect();
        let functions: Vec<TokenStream2> = self.target.funcs.iter().map(|i| self.generate_nonmember_function(i)).collect();

        quote! {
            pub fn compile() -> Target {
                Target::new(
                    vec![
                        #(#apis),*
                    ],
                    vec![
                        #(#functions),*
                    ]
                )
            }
        }
    }

    fn generate_internal_module(&self) -> TokenStream2 {
        let mut path = PathBuf::from_str(file!()).unwrap();
        path.pop();
        path.push("internal.rs");

        let internal = fs::read_to_string(path).expect("Failed to read `internal.rs`");
        let syntax: File = parse_file(&internal.as_str()).expect("Failed to parse `internal.rs`");
        syntax.into_token_stream()
    }
}
