use syn::{parse::Parse, punctuated::Punctuated, *, token::parsing::keyword};

pub mod keywords {
    use syn::custom_keyword;

    custom_keyword!(OneOf);
    custom_keyword!(U8);
    custom_keyword!(U16);
    custom_keyword!(U32);
    custom_keyword!(Usize);
    custom_keyword!(Slice);
    custom_keyword!(Vector);
    custom_keyword!(Api);
    custom_keyword!(ctors);
    custom_keyword!(functions);
    custom_keyword!(Eval);
    custom_keyword!(EmptyVector);
    custom_keyword!(VectorWithCap);
    custom_keyword!(RandomVector);
    custom_keyword!(Ok);
    custom_keyword!(trace);
    custom_keyword!(tcgen);
    custom_keyword!(UsizeArray);
    custom_keyword!(Apis);
    custom_keyword!(Functions);
    custom_keyword!(AsSlice);
    custom_keyword!(AsMutSlice);
    custom_keyword!(Mod);
    custom_keyword!(AssignSelf);
    custom_keyword!(StaticStr);
    custom_keyword!(Str);
    custom_keyword!(TPMKey);
}

#[derive(Debug)]
pub(super) struct VarBinding {
    pub name: Ident,
    pub value: Box<Expression>,
}

impl Parse for VarBinding {
    fn parse(input: parse::ParseStream) -> Result<Self> {
        let name = input.parse()?;
        input.parse::<Token![=]>()?;
        let value = input.parse()?;

        Ok(Self { name, value })
    }
}

#[derive(Debug)]
pub(super) struct EvalExpr {
    pub value: Box<Expression>,
    pub bindings: Punctuated<VarBinding, Token![,]>,
}

impl Parse for EvalExpr {
    fn parse(input: parse::ParseStream) -> Result<Self> {
        input.parse::<keywords::Eval>()?;
        let content;
        parenthesized!(content in input);
        let value = content.parse()?;
        content.parse::<Token![for]>()?;
        let bindings = Punctuated::parse_terminated(&content)?;

        Ok(Self { value, bindings })
    }
}

#[derive(Debug)]
pub(super) enum Expression {
    Literal(Expr),
    OneOf(Punctuated<Box<Expression>, Token![,]>),
    U8,
    U16,
    U32,
    Usize,
    Vector(Box<Expression>),
    Slice(Box<Expression>),
    Api(Ident),
    Eval(EvalExpr),
    Ref(Box<Expression>),
    EmptyVector,
    Mut(Box<Expression>),
    UsizeArray(Box<Expression>),
    VectorWithCap(Box<Expression>, Box<Expression>),
    RandomVector(Box<Expression>),
    AsSlice(Box<Expression>),
    AsMutSlice(Box<Expression>),
    Mod(Box<Expression>, Box<Expression>),
    StaticStr(Box<Expression>),
    Str(Box<Expression>),
    TPMKey()
}

impl Parse for Expression {
    fn parse(input: parse::ParseStream) -> Result<Self> {
        // Does the input start with # if so then parse the DSL syntax
        if let Some(_) = input.parse::<Option<Token![#]>>()? {
            let look = input.lookahead1();

            if look.peek(keywords::OneOf) {
                input.parse::<keywords::OneOf>()?;
                let content;
                parenthesized!(content in input);
                Ok(Self::OneOf(Punctuated::parse_separated_nonempty(&content)?))
            } else if look.peek(keywords::U8) {
                input.parse::<keywords::U8>()?;
                Ok(Self::U8)
            } else if look.peek(keywords::U16) {
                input.parse::<keywords::U16>()?;
                Ok(Self::U16)
            } else if look.peek(keywords::U32) {
                input.parse::<keywords::U32>()?;
                Ok(Self::U32)
            } else if look.peek(keywords::Usize) {
                input.parse::<keywords::Usize>()?;
                Ok(Self::Usize)
            } else if look.peek(keywords::Vector) {
                input.parse::<keywords::Vector>()?;
                let content;
                parenthesized!(content in input);
                Ok(Self::Vector(content.parse()?))
            } else if look.peek(keywords::Slice) {
                input.parse::<keywords::Slice>()?;
                let content;
                parenthesized!(content in input);
                Ok(Self::Slice(content.parse()?))
            } else if look.peek(keywords::Api) {
                input.parse::<keywords::Api>()?;
                let content;
                parenthesized!(content in input);
                Ok(Self::Api(content.parse()?))
            } else if look.peek(keywords::Eval) {
                Ok(Self::Eval(input.parse()?))
            } else if look.peek(keywords::EmptyVector) {
                input.parse::<keywords::EmptyVector>()?;
                Ok(Self::EmptyVector)
            } else if look.peek(keywords::UsizeArray) {
                input.parse::<keywords::UsizeArray>()?;
                let content;
                parenthesized!(content in input);
                Ok(Self::UsizeArray(content.parse()?))
            } else if look.peek(keywords::VectorWithCap) {
                input.parse::<keywords::VectorWithCap>()?;
                let content;
                parenthesized!(content in input);
                let cap = content.parse()?;
                input.parse::<Token![,]>()?;
                let val = content.parse()?;
                Ok(Self::VectorWithCap(cap, val))
            } else if look.peek(keywords::RandomVector) {
                input.parse::<keywords::RandomVector>()?;
                let content;
                parenthesized!(content in input);
                Ok(Self::RandomVector(content.parse()?))
            } else if look.peek(keywords::AsSlice) {
                input.parse::<keywords::AsSlice>()?;
                let content;
                parenthesized!(content in input);
                Ok(Self::AsSlice(content.parse()?))
            } else if look.peek(keywords::AsMutSlice) {
                input.parse::<keywords::AsMutSlice>()?;
                let content;
                parenthesized!(content in input);
                Ok(Self::AsMutSlice(content.parse()?))
            } else if look.peek(keywords::Mod) {
                input.parse::<keywords::Mod>()?;
                let content;
                parenthesized!(content in input);
                let cap = content.parse()?;
                content.parse::<Token![,]>()?;
                let val = content.parse()?;
                Ok(Self::Mod(cap, val))
            } else if look.peek(keywords::StaticStr) {
                input.parse::<keywords::StaticStr>()?;
                let content;
                parenthesized!(content in input);
                Ok(Self::StaticStr(content.parse()?))
            } else if look.peek(keywords::Str) {
                input.parse::<keywords::Str>()?;
                let content;
                parenthesized!(content in input);
                Ok(Self::Str(content.parse()?))
            } else if look.peek(keywords::TPMKey) {
                input.parse::<keywords::TPMKey>()?;
                Ok(Self::TPMKey())
            } else {
                Err(look.error())
            }
        } else {
            if input.peek(Token![ref]) {
                input.parse::<Token![ref]>()?;
                Ok(Self::Ref(input.parse()?))
            } else if input.peek(Token![mut]) {
                input.parse::<Token![mut]>()?;
                Ok(Self::Mut(input.parse()?))
            } else {
                Ok(Self::Literal(input.parse()?))
            }
        }
    }
}

#[derive(Debug)]
pub(super) struct Function {
    pub assign_self: Option<keywords::AssignSelf>,
    pub wrap_ok: Option<keywords::Ok>,
    pub name: Path,
    pub params: Punctuated<Box<Expression>, Token![,]>,
    pub retval: Expr
}

impl Parse for Function {
    fn parse(input: parse::ParseStream) -> Result<Self> {
        let assign_self = input.parse()?;
        let wrap_ok = input.parse()?;
        let name = input.parse()?;
        let params;
        parenthesized!(params in input);
        input.parse::<Token![->]>()?;

        Ok(Self {
            assign_self,
            wrap_ok,
            name,
            params: Punctuated::parse_terminated(&params)?,
            retval: input.parse()?
        })
    }
}

#[derive(Debug)]
pub(super) struct Api {
    pub name: Ident,
    pub ctors: Punctuated<Function, Token![,]>,
    pub functions: Punctuated<Function, Token![,]>,
}

impl Parse for Api {
    fn parse(input: parse::ParseStream) -> Result<Self> {
        let name = input.parse()?;

        let desc;
        braced!(desc in input);

        desc.parse::<keywords::ctors>()?;
        let ctors;
        braced!(ctors in desc);

        desc.parse::<keywords::functions>()?;
        let functions;
        braced!(functions in desc);

        Ok(Self {
            name,
            ctors: Punctuated::parse_separated_nonempty(&ctors)?,
            functions: Punctuated::parse_terminated(&functions)?,
        })
    }
}

#[derive(Debug)]
pub(super) enum ImportLine {
    Empty,
    Glob,
    Super(Box<ImportLine>),
    Single(Ident, Box<ImportLine>),
    List(Punctuated<Box<ImportLine>, Token![,]>),
}

impl Parse for ImportLine {
    fn parse(input: parse::ParseStream) -> Result<Self> {
        let look = input.lookahead1();

        if look.peek(Ident) {
            let segment = input.parse()?;
            let separator = input.parse::<Option<Token![::]>>()?;

            if separator.is_some() {
                Ok(Self::Single(segment, input.parse()?))
            } else {
                Ok(Self::Single(segment, Box::new(Self::Empty)))
            }
        } else if look.peek(Token![*]) {
            input.parse::<Token![*]>()?;
            Ok(Self::Glob)
        } else if look.peek(token::Brace) {
            let list;
            braced!(list in input);
            Ok(Self::List(Punctuated::parse_terminated(&list)?))
        } else if look.peek(Token![super]) {
            input.parse::<Token![super]>()?;
            input.parse::<Token![::]>()?;
            Ok(Self::Super(input.parse()?))
        } else {
            Err(look.error())
        }
    }
}

#[derive(Debug)]
pub(super) struct Imports {
    pub list: Punctuated<Box<ImportLine>, Token![,]>,
}

impl Parse for Imports {
    fn parse(input: parse::ParseStream) -> Result<Self> {
        input.parse::<Token![use]>()?;
        let list;
        braced!(list in input);

        Ok(Self {
            list: Punctuated::parse_terminated(&list)?,
        })
    }
}

#[derive(Debug)]
pub(super) struct Options {
    pub trace: bool,
    pub tcgen: bool
}

impl Parse for Options {
    fn parse(input: parse::ParseStream) -> Result<Self> {
        let opts;
        bracketed!(opts in input);

        let mut trace: bool = false;
        let mut tcgen: bool = false;

        while !opts.is_empty() {
            let look = opts.lookahead1();

            if look.peek(keywords::trace) {
                opts.parse::<keywords::trace>()?;
                trace = true;
            } else if look.peek(keywords::tcgen) {
                opts.parse::<keywords::tcgen>()?;
                tcgen = true;
            } else {
                return Err(look.error());
            }
        }

        Ok(Self { trace, tcgen })
    }
}

#[derive(Debug)]
pub(super) struct Target {
    pub name: Ident,
    pub opts: Options,
    pub imports: Option<Imports>,
    pub apis: Punctuated<Api, Token![,]>,
    pub funcs: Punctuated<Function, Token![,]>,
}

impl Parse for Target {
    fn parse(input: parse::ParseStream) -> Result<Self> {
        let name = input.parse()?;
        let opts = input.parse()?;

        let desc;
        braced!(desc in input);

        let imports = if desc.peek(Token![use]) {
            Some(desc.parse()?)
        } else {
            None
        };

        desc.parse::<keywords::Apis>()?;
        let apis;
        braced!(apis in desc);

        desc.parse::<keywords::Functions>()?;
        let functions;
        braced!(functions in desc);

        Ok(Self {
            name,
            opts,
            imports,
            apis: Punctuated::parse_terminated(&apis)?,
            funcs: Punctuated::parse_terminated(&functions)?,
        })
    }
}
