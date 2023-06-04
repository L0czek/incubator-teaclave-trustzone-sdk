use proc_macro2::{TokenStream as TokenStream2, Span};
use quote::{quote, TokenStreamExt, ToTokens};
use syn::{ItemFn, FnArg, Path, Pat, FnDecl, Token, Ident, parse::Parse};
use crate::{parser::{Target, Api, Function, Expression, keywords}, generator::ExpressionCompiler};

#[derive(Debug)]
pub struct TcgenCtorArgs {
    pub cls: Ident,
    pub path: Path
}

impl Parse for TcgenCtorArgs {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let cls = input.parse()?;
        let _ = input.parse::<Token![,]>()?;
        let path = input.parse()?;

        Ok(Self {
            cls,
            path
        })
    }
}

struct ExpressionReverser {
    code: TokenStream2,
    it: usize
}

impl ExpressionReverser {
    pub fn new() -> Self {
        Self { code: TokenStream2::new(), it: 0usize }
    }

    fn add_byte(&self, expr: TokenStream2) -> TokenStream2 {
        quote! {
            .add_byte(#expr)
        }
    }

    fn add_bytes(&self, expr: TokenStream2) -> TokenStream2 {
        quote! {
            .add_bytes(#expr)
        }
    }

    fn add_slice(&self, len: TokenStream2, val: TokenStream2) -> TokenStream2 {
        let mut code = TokenStream2::new();

        if !len.is_empty() {
            code = len;
        }
        code.append_all(self.add_bytes(val));
        code
    }

    fn use_obj(&self) -> TokenStream2 {
        quote! {
            .use_obj($label.__get_id__())
        }
    }


    pub fn reverse(&mut self, expr: &Box<Expression>) {
        self.code.append_all(quote! {
            TcAssembler::take()
        });
        let expr = self.reverse_expr(expr, quote! { $label });
        self.code.append_all(expr);
        self.code.append_all(quote! { ; });
    }

    fn reverse_expr(&self, expr: &Box<Expression>, value: TokenStream2) -> TokenStream2 {
        println!("exprs: {:?}", expr);
        match &*expr.as_ref() {
            Expression::Literal(_) => quote! {},
            Expression::U8 => self.add_byte(quote! { #value as u8 }),
            Expression::U16 => self.add_bytes(quote! { (#value as u16).to_le_bytes() }),
            Expression::U32 => self.add_bytes(quote! { (#value as u32).to_le_bytes() }),
            Expression::Usize => self.add_bytes(quote! { (#value as usize).to_le_bytes() }),
            Expression::Ref(expr) => self.reverse_expr(&expr, value),
            Expression::Vector(size) => self.add_slice(self.reverse_expr(size, quote! { #value.len() }), quote! { #value.as_slice() }),
            Expression::Slice(size) => self.add_slice(self.reverse_expr(size, quote! { #value.len() }), quote! { #value }),
            Expression::Eval(_) => unreachable!(),
            Expression::OneOf(list) => unreachable!(),
            Expression::Api(name) => self.use_obj(),
            Expression::EmptyVector => todo!(),
            Expression::VectorWithCap(cap, _) => self.reverse_expr(cap, value),
            Expression::RandomVector(size) => self.reverse_expr(size, value),
            Expression::Mut(expr) => self.reverse_expr(&expr, value),
            Expression::UsizeArray(size) => self.add_slice(self.reverse_expr(size, quote! { #value.len() }), quote! { std::mem::transmute::<&[u8]>(#value) }),
            Expression::AsSlice(expr) => self.reverse_expr(&expr, value),
            Expression::AsMutSlice(expr) => self.reverse_expr(&expr, value),
            Expression::Mod(a, _) => self.reverse_expr(&a, value),
            Expression::Str(size) => self.add_slice(self.reverse_expr(size, quote! { #value.len() }), quote! { #value.as_bytes() }),
            Expression::StaticStr(size) => self.add_slice(self.reverse_expr(size, quote! { #value.len() }), quote! { #value.as_bytes() }),
            Expression::TPMKey() => self.add_bytes(quote! { &$label as &[u8] }),
        }
    }
}

impl Into<TokenStream2> for ExpressionReverser {
    fn into(self) -> TokenStream2 {
        self.code
    }
}

impl ToTokens for ExpressionReverser {
    fn to_tokens(&self, tokens: &mut TokenStream2) {
        self.code.to_tokens(tokens);
    }
}

pub(super) struct TcGenerator<'a> {
    target: &'a Target
}

impl<'a> TcGenerator<'a> {
    pub fn new(target: &'a Target) -> Self { Self { target } }

    fn generate_argument(&self, func_name: &String, api_name: Option<&Ident>,
            expr: &Box<Expression>, index: usize) -> TokenStream2 {

        let api_name_str = if let Some(ident) = api_name {
            format!("{}", ident)
        } else {
            "".to_string()
        };

        let macro_label = Ident::new(
            format!("__encode_{}__{}_arg_{}__", api_name_str, func_name, index)
                .as_str(),
            Span::call_site()
        );

        let mut reverser = ExpressionReverser::new();
        reverser.reverse(expr);

        quote! {
            macro_rules! #macro_label {
                ($label:ident) => {
                    #reverser
                }
            }
            pub(crate) use #macro_label;
        }
    }

    fn generate_ctor_epilogue_macro(&self, func_name: &String, api_name: &Ident, wrap_ok: Option<keywords::Ok>) -> TokenStream2 {
        let api_name_str = format!("{}", api_name);
        let macro_label = Ident::new(format!("__encode_{}__{}_epilogue__", api_name_str, func_name).as_str(), Span::call_site());

        if let None = wrap_ok {
            quote! {
                macro_rules! #macro_label {
                    ($ret:ident) => {
                        match &mut $ret {
                            Ok(obj) => obj.__set_id__(),
                            Err(_) => {}
                        }
                    }
                }
                pub(crate) use #macro_label;
            }
        } else {
            quote! {
                macro_rules! #macro_label {
                    ($ret:ident) => {
                        $ret.__set_id__()
                    }
                }
                pub(crate) use #macro_label;
            }
        }
    }

    fn generate_function(&self, func: &Function, api_name: Option<&Ident>, is_not_ctor: bool) -> TokenStream2 {
        let func_name = format!("{}", func.name.clone().into_token_stream()).replace("::", "_")
            .chars().filter(|c| !c.is_whitespace()).collect::<String>();
        let args = func.params.iter()
            .enumerate()
            .map(|(ind, arg)| self.generate_argument(&func_name, api_name, arg, ind + is_not_ctor as usize))
            .collect::<Vec<TokenStream2>>();

        let epilogue = if is_not_ctor {
            quote! {}
        } else {
            self.generate_ctor_epilogue_macro(&func_name, api_name.unwrap(), func.wrap_ok)
        };

        quote! {
            #(#args)*
            #epilogue
        }
    }

    fn generate_api(&self, api: &Api) -> TokenStream2 {
        let name = &api.name;
        let ctors = api.ctors.iter()
            .map(|ctor| self.generate_function(ctor, Some(name), false))
            .collect::<Vec<TokenStream2>>();
        let funcs = api.functions.iter()
            .map(|func| self.generate_function(func, Some(name), true))
            .collect::<Vec<TokenStream2>>();


        quote! {
            #(#ctors)*
            #(#funcs)*
        }
    }

    pub fn generate(self) -> TokenStream2 {
        let apis = self.target.apis.iter()
            .map(|api| self.generate_api(api))
            .collect::<Vec<TokenStream2>>();
        let funcs = self.target.funcs.iter()
            .map(|func| self.generate_function(&func, None, false))
            .collect::<Vec<TokenStream2>>();

        quote! {
            mod tcgen_macros {
                #(#apis)*
                #(#funcs)*
            }
        }
    }
}

pub(super) struct TcTracer<'a> {
    func: &'a ItemFn,
    cls: String,
    full_path: Option<String>
}

impl<'a> TcTracer<'a> {
    pub fn new(class: &Ident, func: &'a ItemFn, full_path: Option<&'a Path>) -> Self {
        let cls = format!("{}", class);

        let full_path = if let Some(path) = full_path {
            Some(format!("{}", path.clone().into_token_stream())
                        .replace("::", "_")
                        .chars()
                        .filter(|c| !c.is_whitespace())
                        .collect::<String>())
        } else {
            None
        };

        Self {
            func,
            cls,
            full_path
        }
    }

    fn trace_param(&self, param: &FnArg, index: usize) -> TokenStream2 {
        if let FnArg::SelfRef(_) = param {
            return quote! {}
        }

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
            let func_name_ident = format!("{}", self.func.ident);
            let func_name = self.full_path.as_ref().unwrap_or(&func_name_ident);

            let name = Ident::new(
                format!("__encode_{}__{}_arg_{}__",
                    self.cls, func_name, index).as_str(),
                Span::call_site()
            );
            quote! { #name!(#ident);  }
        } else {
            // compile_error!(format!("Unsupported argument for tracing: {}", param.to_token_stream()).as_str());
            // compile_error!("Unsupported argument for tracing");
            // println!("{}", format!("Unsupported argument for tracing: {}", param.to_token_stream()).as_str());
            println!("Tc traser error");
            unreachable!()
        }
    }

    fn trace_params(&self, code: &mut TokenStream2) {
        self.func.decl.inputs.iter()
            .enumerate()
            .map(|(ind, arg)| self.trace_param(arg, ind))
            .for_each(|c| code.append_all(c));
    }

    fn construct_function(&self, prologue: TokenStream2, epilogue: TokenStream2) -> TokenStream2 {
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
            #(#attrs)* #vis #constness #unsafety #asyncness #abi fn #ident (#(#inputs),*) #output {
                #prologue
                let mut __ret__ = { #block };
                #epilogue
                __ret__
            }
        }
    }


    pub fn compile_ctor(&self) -> TokenStream2 {
        let label = &self.cls;
        let ident = Ident::new(label.as_str(), Span::call_site());
        let ctor_name = Ident::new(self.full_path.as_ref().unwrap().as_str(), Span::call_site());
        let enum_name = Ident::new(format!("__ctors_{}", label).as_str(), Span::call_site());
        let mut prologue = quote! {
            TcAssembler::take()
                .select_api(Apis::#ident as u8)
                .ctor_new_obj()
                .select_ctor(encodings::#enum_name::#ctor_name as u8);
        };
        self.trace_params(&mut prologue);

        let macro_label = Ident::new(format!("__encode_{}__{}_epilogue__", label, ctor_name).as_str(), Span::call_site());
        let epilogue = quote! {
            #macro_label! (__ret__);
        };

        self.construct_function(prologue, epilogue)
    }

    pub fn compile_member(&self) -> TokenStream2 {
        let label = &self.cls;
        let ident = Ident::new(label.as_str(), Span::call_site());
        let func_name = &self.func.ident;
        let enum_name = Ident::new(format!("__members_{}", label).as_str(), Span::call_site());
        let mut prologue = quote! {
            TcAssembler::take()
                .select_api(Apis::#ident as u8)
                .use_obj(self.__get_id__())
                .select_func(encodings::#enum_name::#func_name as u8);
        };
        self.trace_params(&mut prologue);
        self.construct_function(prologue, quote! {})
    }
}
