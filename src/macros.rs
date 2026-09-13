//! Macros: `.macro`, `.rept`, `.irp` and `.irpc`.
//!
//! Expansion is **textual**, and deliberately so. A token-level substitution
//! cannot express what macro bodies routinely rely on: `.L\@_loop:` has to
//! paste the invocation counter into the middle of an identifier, and there is
//! no token that means "join these". Substituting into the source text and
//! re-lexing gives that for free, and it is what GNU as does, so bodies
//! written for it behave the same way here.
//!
//! The cost is that the expansion is a new entry in the source map. That turns
//! out to be a feature: a diagnostic inside a macro points at the expanded
//! text, with the file name saying which macro it came from.

use crate::intern::Name;
use crate::source::Span;

#[derive(Clone, Debug)]
pub struct MacroParam {
    pub name: String,
    /// Text substituted when the caller omits this argument.
    pub default: Option<String>,
    /// `:req` — omitting it is an error.
    pub required: bool,
    /// `:vararg` — absorbs every remaining argument, commas included.
    pub vararg: bool,
}

#[derive(Clone, Debug)]
pub struct MacroDef {
    pub name: Name,
    pub params: Vec<MacroParam>,
    /// The body as it was written, ready to be substituted into.
    pub body: String,
    pub def_span: Span,
}

impl MacroDef {
    pub fn param(&self, name: &str) -> Option<&MacroParam> {
        self.params.iter().find(|p| p.name == name)
    }
}

/// Substitutes `\param` references in a macro body.
///
/// `bindings` maps parameter names to the text to put in their place. `\@` is
/// replaced with `counter`, `\()` with nothing (it exists purely to end a
/// parameter name that would otherwise run into the following text), and `\\`
/// with a single backslash.
///
/// A `\x` whose name is not a parameter is left exactly as written. That
/// matters: macro bodies contain string literals, and `"a\nb"` must survive
/// unless the caller really did name a parameter `n`.
pub fn substitute(body: &str, bindings: &[(String, String)], counter: u64) -> String {
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    while let Some(i) = rest.find('\\') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        let mut chars = after.chars();
        match chars.next() {
            None => {
                // A trailing backslash: nothing to escape.
                out.push('\\');
                return out;
            }
            Some('\\') => {
                out.push('\\');
                rest = &after[1..];
            }
            Some('@') => {
                out.push_str(&counter.to_string());
                rest = &after[1..];
            }
            Some('(') if after.starts_with("()") => {
                // The empty paste: it separates a parameter name from what
                // follows and contributes nothing itself.
                rest = &after[2..];
            }
            Some(c) if is_param_start(c) => {
                let end = after
                    .find(|c: char| !is_param_cont(c))
                    .unwrap_or(after.len());
                let name = &after[..end];
                match bindings.iter().find(|(p, _)| p == name) {
                    Some((_, value)) => {
                        out.push_str(value);
                        rest = &after[end..];
                    }
                    None => {
                        // Not a parameter, so not ours to touch. The name is
                        // copied out too, so the next search does not stop on
                        // this same backslash forever.
                        out.push('\\');
                        out.push_str(name);
                        rest = &after[end..];
                    }
                }
            }
            Some(_) => {
                out.push('\\');
                rest = after;
                // Emit the escaped character too, so a `\"` inside a string
                // literal is not re-examined.
                let n = rest.chars().next().map_or(0, char::len_utf8);
                out.push_str(&rest[..n]);
                rest = &rest[n..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn is_param_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_param_cont(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '$'
}

/// Parses the parameter list of a `.macro` directive from its source text.
///
/// Accepts `a`, `a=default`, `a:req` and `a:vararg`, separated by commas or
/// whitespace, which is the range GNU as takes.
pub fn parse_params(text: &str) -> Result<Vec<MacroParam>, String> {
    let mut params: Vec<MacroParam> = Vec::new();
    for piece in split_params(text) {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        let (name, rest) = split_name(piece);
        if name.is_empty() {
            return Err(format!("`{piece}` is not a valid parameter name"));
        }
        if params.iter().any(|p| p.name == name) {
            return Err(format!("duplicate parameter `{name}`"));
        }
        let mut p = MacroParam {
            name: name.to_string(),
            default: None,
            required: false,
            vararg: false,
        };
        let rest = rest.trim();
        if let Some(d) = rest.strip_prefix('=') {
            p.default = Some(d.trim().to_string());
        } else if let Some(q) = rest.strip_prefix(':') {
            match q.trim() {
                "req" => p.required = true,
                "vararg" => p.vararg = true,
                other => return Err(format!("unknown parameter qualifier `:{other}`")),
            }
        } else if !rest.is_empty() {
            return Err(format!("unexpected `{rest}` after parameter `{name}`"));
        }
        if params.last().is_some_and(|prev| prev.vararg) {
            return Err(format!("`{name}` follows a `:vararg` parameter"));
        }
        params.push(p);
    }
    Ok(params)
}

fn split_name(s: &str) -> (&str, &str) {
    let end = s.find(|c: char| !is_param_cont(c)).unwrap_or(s.len());
    s.split_at(end)
}

/// Splits a parameter list on commas and whitespace, but not inside a default
/// value's brackets or quotes.
fn split_params(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut quote = None::<char>;
    let mut start = 0usize;
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i] as char;
        match quote {
            Some(q) => {
                if c == '\\' {
                    i += 1;
                } else if c == q {
                    quote = None;
                }
            }
            None => match c {
                '"' | '\'' => quote = Some(c),
                '(' | '[' | '<' => depth += 1,
                ')' | ']' | '>' => depth -= 1,
                ',' if depth <= 0 => {
                    out.push(&text[start..i]);
                    start = i + 1;
                }
                _ => {}
            },
        }
        i += 1;
    }
    out.push(&text[start..]);
    out
}

/// Splits an argument list the same way, used for both macro calls and `.irp`.
pub fn split_args(text: &str) -> Vec<&str> {
    split_params(text)
        .into_iter()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
}

/// Splits `name rest` or `name, rest` into the leading identifier and what
/// follows. Used for both `.macro NAME params` and `.irp VAR, values`.
pub fn split_macro_header(text: &str) -> (&str, &str) {
    let text = text.trim_start();
    let (name, rest) = split_name(text);
    (name, rest.trim_start().trim_start_matches(',').trim_start())
}

/// Recognises a `name=value` argument, which lets a caller pass arguments out
/// of order. The `=` has to be at the top level: `f(a=1)` is one positional
/// argument, not a named one.
pub fn split_named_arg(arg: &str) -> Option<(&str, &str)> {
    let (name, rest) = split_name(arg.trim_start());
    if name.is_empty() {
        return None;
    }
    let rest = rest.trim_start();
    let value = rest.strip_prefix('=')?;
    // `==` is a comparison in the argument, not an assignment.
    if value.starts_with('=') {
        return None;
    }
    Some((name, value.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(a, v)| (a.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn substitutes_named_parameters() {
        let s = substitute(
            "mov \\dst, \\src",
            &b(&[("dst", "%rax"), ("src", "%rbx")]),
            0,
        );
        assert_eq!(s, "mov %rax, %rbx");
    }

    #[test]
    fn pastes_into_the_middle_of_an_identifier() {
        // The reason expansion is textual: there is no token that means
        // "join these two".
        let s = substitute(".L\\@_loop:", &[], 7);
        assert_eq!(s, ".L7_loop:");
        let s = substitute("\\name\\()_end:", &b(&[("name", "foo")]), 0);
        assert_eq!(s, "foo_end:");
    }

    #[test]
    fn leaves_unknown_escapes_alone() {
        // A macro body full of string literals must survive expansion.
        let s = substitute(r#".ascii "a\nb\tc""#, &b(&[("x", "1")]), 0);
        assert_eq!(s, r#".ascii "a\nb\tc""#);
        // The name scan is greedy, so `\nb` looks for a parameter called
        // `nb`, not `n`. That is why `\()` exists.
        let s = substitute(r#".ascii "a\nb""#, &b(&[("n", "Z")]), 0);
        assert_eq!(s, r#".ascii "a\nb""#);
        let s = substitute(r#".ascii "a\n\()b""#, &b(&[("n", "Z")]), 0);
        assert_eq!(s, r#".ascii "aZb""#);
    }

    #[test]
    fn a_parameter_name_can_still_capture_a_string_escape() {
        // GNU as has this wart and bodies are written around it, so matching
        // it is more useful than being clever: with a parameter called `n`,
        // a `\n` that ends a string really is substituted.
        let s = substitute(r#".ascii "a\n""#, &b(&[("n", "Z")]), 0);
        assert_eq!(s, r#".ascii "aZ""#);
    }

    #[test]
    fn escaped_backslash_and_trailing_backslash() {
        assert_eq!(substitute(r"a\\b", &[], 0), r"a\b");
        assert_eq!(substitute(r"a\", &[], 0), r"a\");
    }

    #[test]
    fn parses_parameter_forms() {
        let p = parse_params("a, b=2, c:req, rest:vararg").unwrap();
        assert_eq!(p.len(), 4);
        assert_eq!(p[0].name, "a");
        assert_eq!(p[1].default.as_deref(), Some("2"));
        assert!(p[2].required);
        assert!(p[3].vararg);
    }

    #[test]
    fn rejects_bad_parameter_lists() {
        assert!(parse_params("a, a").unwrap_err().contains("duplicate"));
        assert!(parse_params("a:nope").unwrap_err().contains("qualifier"));
        assert!(parse_params("v:vararg, a").unwrap_err().contains("vararg"));
    }

    #[test]
    fn splits_headers_and_named_arguments() {
        assert_eq!(split_macro_header("foo a, b"), ("foo", "a, b"));
        assert_eq!(split_macro_header("foo, a"), ("foo", "a"));
        assert_eq!(split_macro_header("  foo  "), ("foo", ""));
        assert_eq!(split_named_arg("dst=%rax"), Some(("dst", "%rax")));
        assert_eq!(split_named_arg(" n = 4 "), Some(("n", "4")));
        assert_eq!(split_named_arg("%rax"), None);
        // A comparison is not an assignment.
        assert_eq!(split_named_arg("a==b"), None);
    }

    #[test]
    fn splits_arguments_without_breaking_nesting() {
        assert_eq!(split_args("1, 2, 3"), vec!["1", "2", "3"]);
        assert_eq!(split_args("(1, 2), 3"), vec!["(1, 2)", "3"]);
        assert_eq!(split_args(r#""a,b", c"#), vec![r#""a,b""#, "c"]);
        assert_eq!(split_args("  "), Vec::<&str>::new());
    }
}
