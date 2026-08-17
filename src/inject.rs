//! Shared request-building helpers: one place to inject payloads into query
//! strings and form data, and to report findings, instead of re-implementing
//! the same loops in every scanner.

use crate::form::Form;
use std::collections::HashMap;
use url::Url;

/// Copy of `url` with the query parameter at `param_index` rewritten by
/// `transform` (which receives the parameter's current value). All other
/// parameters are untouched.
pub fn inject_query_param<F>(url: &Url, param_index: usize, transform: F) -> Url
where
    F: Fn(&str) -> String,
{
    let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
    let mut parts = Vec::with_capacity(pairs.len());
    for (i, (key, value)) in pairs.iter().enumerate() {
        if i == param_index {
            parts.push(format!("{}={}", key, transform(value)));
        } else {
            parts.push(format!("{}={}", key, value));
        }
    }
    let mut new_url = url.clone();
    new_url.set_query(Some(&parts.join("&")));
    new_url
}

/// Form-encoded data with the input at `input_index` rewritten by `transform`
/// (which receives the input's current value). All other inputs are untouched.
pub fn inject_form_field<F>(form: &Form, input_index: usize, transform: F) -> HashMap<String, String>
where
    F: Fn(&str) -> String,
{
    let mut data = HashMap::new();
    for (i, input) in form.inputs.iter().enumerate() {
        if i == input_index {
            data.insert(input.name.clone(), transform(&input.value));
        } else {
            data.insert(input.name.clone(), input.value.clone());
        }
    }
    data
}

/// Print the standard `[+] <label> Found: <payload> in <parameter>` line, run
/// the reporter callback, and return `true` so callers can write
/// `return Ok(report_found(...))` or `report_found(...); continue 'loop;`.
pub fn report_found(label: &str, payload: &str, parameter: &str, report: impl FnOnce()) -> bool {
    println!("[+] {} Found: {} in {}", label, payload, parameter);
    report();
    true
}
