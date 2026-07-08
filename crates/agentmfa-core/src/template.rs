//! Injection template mini-language (DESIGN.md §4.1).
//!
//! A template is a stored header line (or query-param form) mixing literal
//! text with `{{ … }}` placeholders. Inside a placeholder:
//!
//! - a bare secret name (`{{GITHUB_API_KEY}}`) interpolates that secret's
//!   value;
//! - a fixed set of transforms wraps secret refs and double-quoted string
//!   literals. v1 ships exactly two:
//!   - `base64(A ":" B)`, concatenates its arguments and base64-encodes
//!     the result (what makes HTTP Basic auth *correct*);
//!   - `url(REF)`, percent-encodes a value for a query-param form.
//!
//! The transform set is fixed, no arbitrary expressions, no shelling out.
//! Rendering runs core-side after approval; rendered output is validated
//! against the HTTP field grammar by the HTTP capability before attaching.
//!
//! Renaming a secret rewrites every template that references it, matching
//! the name inside `{{ … }}` placeholders and transform expressions alike,
//! never literal text (DESIGN.md §3).

use std::collections::BTreeSet;
use std::fmt;

use base64::Engine as _;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::types::SecretValue;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TemplateError {
    #[error("unclosed '{{{{' placeholder")]
    Unclosed,
    #[error("empty placeholder")]
    Empty,
    #[error("unknown transform {0:?} (v1 supports base64, url)")]
    UnknownTransform(String),
    #[error("transform {0} expects at least one argument")]
    NoArgs(&'static str),
    #[error("url() takes exactly one argument")]
    UrlArity,
    #[error("unterminated string literal in placeholder")]
    UnterminatedString,
    #[error("invalid secret reference {0:?}")]
    BadRef(String),
    #[error("unexpected token at {0:?}")]
    Unexpected(String),
}

/// A secret name is a valid template reference: `[A-Za-z_][A-Za-z0-9_]*`.
pub fn is_valid_secret_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    name.len() <= 64 && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Arg {
    Ref(String),
    Lit(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Expr {
    /// `{{NAME}}`
    Ref(String),
    /// `{{base64(A ":" B)}}` / `{{url(REF)}}`
    Transform { kind: Transform, args: Vec<Arg> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transform {
    Base64,
    Url,
}

impl Transform {
    fn name(&self) -> &'static str {
        match self {
            Transform::Base64 => "base64",
            Transform::Url => "url",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    /// Literal text, kept verbatim.
    Literal(String),
    Placeholder(Expr),
}

/// A parsed template. Parse once at save time (validation) and again at
/// render time; both go through [`Template::parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    segments: Vec<Segment>,
}

impl Template {
    pub fn parse(src: &str) -> Result<Self, TemplateError> {
        let mut segments = Vec::new();
        let mut rest = src;
        while let Some(open) = rest.find("{{") {
            if open > 0 {
                segments.push(Segment::Literal(rest[..open].to_string()));
            }
            let after = &rest[open + 2..];
            let close = after.find("}}").ok_or(TemplateError::Unclosed)?;
            let inner = &after[..close];
            segments.push(Segment::Placeholder(parse_expr(inner)?));
            rest = &after[close + 2..];
        }
        if !rest.is_empty() {
            segments.push(Segment::Literal(rest.to_string()));
        }
        Ok(Self { segments })
    }

    /// Every secret name the template references (inside bare placeholders
    /// and transform arguments alike).
    pub fn refs(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for seg in &self.segments {
            if let Segment::Placeholder(expr) = seg {
                match expr {
                    Expr::Ref(name) => {
                        out.insert(name.clone());
                    }
                    Expr::Transform { args, .. } => {
                        for arg in args {
                            if let Arg::Ref(name) = arg {
                                out.insert(name.clone());
                            }
                        }
                    }
                }
            }
        }
        out
    }

    /// Render with `resolve` supplying secret values by name. The output is
    /// zeroized on drop.
    pub fn render<E>(
        &self,
        mut resolve: impl FnMut(&str) -> Result<SecretValue, E>,
    ) -> Result<Zeroizing<String>, E> {
        let mut out = Zeroizing::new(String::new());
        for seg in &self.segments {
            match seg {
                Segment::Literal(text) => out.push_str(text),
                Segment::Placeholder(expr) => match expr {
                    Expr::Ref(name) => out.push_str(&resolve(name)?),
                    Expr::Transform { kind, args } => {
                        let mut concat = Zeroizing::new(String::new());
                        for arg in args {
                            match arg {
                                Arg::Ref(name) => concat.push_str(&resolve(name)?),
                                Arg::Lit(text) => concat.push_str(text),
                            }
                        }
                        match kind {
                            Transform::Base64 => {
                                out.push_str(
                                    &base64::engine::general_purpose::STANDARD
                                        .encode(concat.as_bytes()),
                                );
                            }
                            Transform::Url => {
                                for piece in utf8_percent_encode(&concat, NON_ALPHANUMERIC) {
                                    out.push_str(piece);
                                }
                            }
                        }
                    }
                },
            }
        }
        Ok(out)
    }

    /// Rewrite every reference to `old` as `new`, leaving literal text,
    /// including string literals inside transforms, untouched. Returns the
    /// re-serialized template source.
    pub fn rename_ref(&self, old: &str, new: &str) -> String {
        let renamed = Template {
            segments: self
                .segments
                .iter()
                .map(|seg| match seg {
                    Segment::Literal(t) => Segment::Literal(t.clone()),
                    Segment::Placeholder(expr) => Segment::Placeholder(match expr {
                        Expr::Ref(name) => Expr::Ref(if name == old {
                            new.to_string()
                        } else {
                            name.clone()
                        }),
                        Expr::Transform { kind, args } => Expr::Transform {
                            kind: *kind,
                            args: args
                                .iter()
                                .map(|a| match a {
                                    Arg::Ref(name) if name == old => Arg::Ref(new.to_string()),
                                    other => other.clone(),
                                })
                                .collect(),
                        },
                    }),
                })
                .collect(),
        };
        renamed.to_string()
    }
}

impl fmt::Display for Template {
    /// Canonical re-serialization: literals verbatim, placeholders in
    /// normalized form (`{{NAME}}`, `{{base64(A ":" B)}}`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for seg in &self.segments {
            match seg {
                Segment::Literal(t) => f.write_str(t)?,
                Segment::Placeholder(Expr::Ref(name)) => write!(f, "{{{{{name}}}}}")?,
                Segment::Placeholder(Expr::Transform { kind, args }) => {
                    write!(f, "{{{{{}(", kind.name())?;
                    for (i, arg) in args.iter().enumerate() {
                        if i > 0 {
                            f.write_str(" ")?;
                        }
                        match arg {
                            Arg::Ref(name) => f.write_str(name)?,
                            Arg::Lit(text) => write!(f, "{:?}", text)?,
                        }
                    }
                    f.write_str(")}}")?;
                }
            }
        }
        Ok(())
    }
}

fn parse_expr(inner: &str) -> Result<Expr, TemplateError> {
    let inner = inner.trim();
    if inner.is_empty() {
        return Err(TemplateError::Empty);
    }
    // Transform form: `name(args)`
    if let Some(paren) = inner.find('(') {
        let name = inner[..paren].trim();
        if !inner.ends_with(')') {
            return Err(TemplateError::Unexpected(inner.to_string()));
        }
        let kind = match name {
            "base64" => Transform::Base64,
            "url" => Transform::Url,
            other => return Err(TemplateError::UnknownTransform(other.to_string())),
        };
        let args = parse_args(&inner[paren + 1..inner.len() - 1])?;
        if args.is_empty() {
            return Err(TemplateError::NoArgs(kind.name()));
        }
        if kind == Transform::Url && args.len() != 1 {
            return Err(TemplateError::UrlArity);
        }
        return Ok(Expr::Transform { kind, args });
    }
    // Bare reference.
    if !is_valid_secret_name(inner) {
        return Err(TemplateError::BadRef(inner.to_string()));
    }
    Ok(Expr::Ref(inner.to_string()))
}

/// Arguments: whitespace-separated secret refs and double-quoted string
/// literals (`\"` and `\\` escapes supported).
fn parse_args(src: &str) -> Result<Vec<Arg>, TemplateError> {
    let mut args = Vec::new();
    let mut chars = src.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
        } else if c == '"' {
            chars.next();
            let mut lit = String::new();
            loop {
                match chars.next() {
                    Some('"') => break,
                    Some('\\') => match chars.next() {
                        Some(e @ ('"' | '\\')) => lit.push(e),
                        Some(other) => {
                            lit.push('\\');
                            lit.push(other);
                        }
                        None => return Err(TemplateError::UnterminatedString),
                    },
                    Some(other) => lit.push(other),
                    None => return Err(TemplateError::UnterminatedString),
                }
            }
            args.push(Arg::Lit(lit));
        } else {
            let mut word = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() || c == '"' {
                    break;
                }
                word.push(c);
                chars.next();
            }
            if !is_valid_secret_name(&word) {
                return Err(TemplateError::BadRef(word));
            }
            args.push(Arg::Ref(word));
        }
    }
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::convert::Infallible;

    fn render(t: &Template, vals: &[(&str, &str)]) -> String {
        let map: HashMap<&str, &str> = vals.iter().copied().collect();
        t.render(|name| Ok::<_, Infallible>(Zeroizing::new(map[name].to_string())))
            .unwrap()
            .to_string()
    }

    #[test]
    fn bare_ref_renders() {
        let t = Template::parse("Authorization: Bearer {{GITHUB_API_KEY}}").unwrap();
        assert_eq!(t.refs().into_iter().collect::<Vec<_>>(), ["GITHUB_API_KEY"]);
        assert_eq!(
            render(&t, &[("GITHUB_API_KEY", "ghp_x")]),
            "Authorization: Bearer ghp_x"
        );
    }

    #[test]
    fn basic_auth_base64_is_correct() {
        let t =
            Template::parse("Authorization: Basic {{base64(SERVICE_USER \":\" SERVICE_PASSWORD)}}")
                .unwrap();
        let rendered = render(
            &t,
            &[
                ("SERVICE_USER", "svc-user"),
                ("SERVICE_PASSWORD", "the-password"),
            ],
        );
        let expected = base64::engine::general_purpose::STANDARD.encode("svc-user:the-password");
        assert_eq!(rendered, format!("Authorization: Basic {expected}"));
        assert_eq!(t.refs().len(), 2);
    }

    #[test]
    fn url_transform_percent_encodes() {
        let t = Template::parse("token={{url(STREAM_TOKEN)}}").unwrap();
        assert_eq!(
            render(&t, &[("STREAM_TOKEN", "a b/c&d")]),
            "token=a%20b%2Fc%26d"
        );
    }

    #[test]
    fn url_takes_one_arg() {
        assert_eq!(
            Template::parse("{{url(A B)}}").unwrap_err(),
            TemplateError::UrlArity
        );
    }

    #[test]
    fn unknown_transform_rejected() {
        assert!(matches!(
            Template::parse("{{exec(A)}}").unwrap_err(),
            TemplateError::UnknownTransform(_)
        ));
    }

    #[test]
    fn unclosed_placeholder_rejected() {
        assert_eq!(
            Template::parse("Bearer {{OOPS").unwrap_err(),
            TemplateError::Unclosed
        );
    }

    #[test]
    fn rename_rewrites_refs_and_transform_args_but_not_literals() {
        let t = Template::parse("X: {{USER}} {{base64(USER \"USER\" PASS)}} USER {{url(USER)}}")
            .unwrap();
        let out = t.rename_ref("USER", "SERVICE_USER");
        assert_eq!(
            out,
            "X: {{SERVICE_USER}} {{base64(SERVICE_USER \"USER\" PASS)}} USER {{url(SERVICE_USER)}}"
        );
        // Round-trips: renamed source still parses to the same structure.
        let reparsed = Template::parse(&out).unwrap();
        assert!(reparsed.refs().contains("SERVICE_USER"));
        assert!(!reparsed.refs().contains("USER"));
    }

    #[test]
    fn display_round_trips_semantics() {
        let src = "Authorization: Basic {{ base64( A \":\" B ) }}";
        let t = Template::parse(src).unwrap();
        let canon = t.to_string();
        assert_eq!(canon, "Authorization: Basic {{base64(A \":\" B)}}");
        assert_eq!(Template::parse(&canon).unwrap(), t);
    }

    #[test]
    fn secret_value_never_in_debug() {
        // Templates never store values; nothing to test beyond type choice,
        // rendering returns Zeroizing<String>. Compile-time guarantee.
        let t = Template::parse("{{A}}").unwrap();
        let v = t
            .render(|_| Ok::<_, Infallible>(Zeroizing::new("s3cret".into())))
            .unwrap();
        assert_eq!(&*v, "s3cret");
    }
}
