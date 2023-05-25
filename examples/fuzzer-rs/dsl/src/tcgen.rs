use proc_macro2::{TokenStream as TokenStream2, Ident, Span};
use quote::{quote, TokenStreamExt, ToTokens};
use syn::{ItemFn, FnArg, Path, Pat, FnDecl, token::Token};
use crate::{parser::{Target, Api, Function, Expression}, generator::ExpressionCompiler};

struct ExpressionReverser {
    code: TokenStream2,
    it: usize
}

impl ExpressionReverser {
    pub fn new() -> Self {
        Self { code: TokenStream2::new(), it: 0usize }
    }

    fn next_label(&mut self) -> Ident {
        let name = format!("__r_var_{}", self.it);
        self.it += 1;
        Ident::new(&name, Span::call_site())
    }

    fn assign(&mut self, tokens: TokenStream2) -> Ident {
        let label = self.next_label();
        self.code.append_all(quote! { let #label = #tokens; });
        label
    }

    fn reverse_len(&mut self, val: Ident, len: &Box<Expression>) -> Ident {
        let label = self.assign(quote! { #val.len() });
        self.reverse_expr(label, len)
    }

    fn reverse_expr(&mut self, val: Ident, expr: &Box<Expression>) -> Ident {
        let label = self.next_label();
        match &*expr.as_ref() {
            Expression::Literal(e) => unreachable!(),
            Expression::U8 => self.assign(quote! { (#val as u8).to_le_bytes() }),
            Expression::U16 => self.assign(quote! { (#val as u16).to_le_bytes() }),
            Expression::U32 => self.assign(quote! { (#val as u32).to_le_bytes() }),
            Expression::Usize => self.assign(quote! { (#val as usize).to_le_bytes() }),
            Expression::Ref(expr) => {
                self.reverse_expr(val, &expr)
            },
            Expression::Vector(size) => self.reverse_len(val, &size),
            Expression::Slice(size) => self.reverse_len(val, &size),
            Expression::Eval(_) => unreachable!(),
            Expression::OneOf(list) => {
                let mut compiler = ExpressionCompiler::new();
                let vals = list.iter()
                    .map(|el| compiler.compile_expr(&el))
                    .collect::<Vec<Ident>>();
                let indexes = 0..vals.len();
                let tokens: TokenStream2 = compiler.into();
                self.code.append_all(tokens);
                self.assign(quote! {
                    match #val {
                        #(
                            #vals => #indexes,
                        )*
                    }
                })
            },
            Expression::Api(name) => self.assign(quote! { Apis::#name as u8 }),
            Expression::EmptyVector => todo!(),
            Expression::VectorWithCap(cap, _) => self.reverse_len(val, &cap),
            Expression::RandomVector(size) => self.reverse_len(val, &size),
            Expression::Mut(expr) => self.reverse_expr(val, &expr),
            Expression::UsizeArray(size) => self.reverse_len(val, &size),
            Expression::AsSlice(expr) => self.reverse_expr(val, &expr),
            Expression::AsMutSlice(expr) => self.reverse_expr(val, &expr),
            Expression::Mod(a, _) => self.reverse_expr(val, &a),
            Expression::Str(size) => self.reverse_len(val, &size),
            Expression::StaticStr(size) => self.reverse_len(val, &size),
            Expression::TPMKey() => self.assign(quote! { &val as &[u8] }),
        }
    }
}

impl Into<TokenStream2> for ExpressionReverser {
    fn into(self) -> TokenStream2 {
        self.code
    }
}

pub(super) struct TcGenerator<'a> {
    target: &'a Target
}

impl<'a> TcGenerator<'a> {
    pub fn new(target: &'a Target) -> Self { Self { target } }

    fn generate_argument(&self, func_name: &String, expr: &Box<Expression>, index: usize) -> TokenStream2 {
        let mut reverser = ExpressionReverser::new();
        let code = reverser.reverse_expr(Ident::new("arg", Span::call_site()), expr);
        let macro_label = Ident::new(format!("__func_{}_arg_{}__", func_name, index).as_str(), Span::call_site());

        quote! {
            #[macro_export]
            macro_rules! #macro_label {
                #code
            }
        }
    }

    fn generate_function(&self, func: &Function) -> TokenStream2 {
        let mut func_name_tokens = TokenStream2::new();
        func.name.to_tokens(&mut func_name_tokens);
        let func_name = format!("{}", func_name_tokens)
            .replace("::", "_");
        let args = func.params.iter()
            .enumerate()
            .map(|(ind, arg)| self.generate_argument(&func_name, arg, ind))
            .collect::<Vec<TokenStream2>>();

        quote! {
            #(#args)*
        }
    }

    fn generate_api(&self, api: &Api) -> TokenStream2 {
        let name = &api.name;
        let funcs = api.functions.iter()
            .map(|func| self.generate_function(func))
            .collect::<Vec<TokenStream2>>();

        quote! {
            mod #name {
                #(#funcs)*
            }
        }
    }

    pub fn generate(self) -> TokenStream2 {
        let apis = self.target.apis.iter()
            .map(|api| self.generate_api(api))
            .collect::<Vec<TokenStream2>>();
        let funcs = self.target.funcs.iter()
            .map(|func| self.generate_function(&func))
            .collect::<Vec<TokenStream2>>();

        quote! {
            mod encode {
                mod apis {
                    #(#apis)*
                }

                mod functions {
                    #(#funcs)*
                }
            }
        }
    }
}

pub(super) struct TcTracer<'a> {
    func: &'a ItemFn,
    cls: String
}

impl<'a> TcTracer<'a> {
    pub fn new(class: &Path, func: &'a ItemFn) -> Self {
        let cls = class.into_token_stream().to_string().replace("::", "_");

        Self {
            func,
            cls
        }
    }

    fn trace_param(&self, param: &FnArg, index: usize) -> TokenStream2 {
        let ident = match param {
            FnArg::Captured(arg) => {
                match &arg.pat {
                    Pat::Ident(ident) => Some(ident),
                    _ => None,
                }
            },
            _ => None
        };

        if let Some(ident) = ident {
            let name = Ident::new(
                format!("{}_{}", self.cls, index).as_str(),
                Span::call_site()
            );
            quote! { #name!(#ident);  }
        } else {
            // compile_error!(format!("Unsupported argument for tracing: {}", param.to_token_stream()).as_str());
            // compile_error!("Unsupported argument for tracing");
            unreachable!()
        }
    }

    pub fn compile(&self) -> TokenStream2 {
        let mut code = TokenStream2::new();
        self.func.decl.inputs.iter()
            .enumerate()
            .map(|(ind, arg)| self.trace_param(arg, ind))
            .for_each(|c| code.append_all(c));

        let ItemFn {
            attrs,
            vis,
            constness,
            unsafety,
            asyncness,
            abi,
            ident,
            decl,
            block,
        } = self.func;

        let FnDecl {
            generics,
            inputs,
            variadic,
            output,
            ..
        } = &*decl.as_ref();

        quote! {
            #(#attrs)* #vis #constness #unsafety #asyncness #abi fn #ident (#(#inputs),*) -> #output {
                #code
                #block
            }
        }
    }
}
