extern crate proc_macro;

use self::proc_macro::TokenStream;

/// Added a `#[derive(ToFromBytesEndian)]` macro for added the trait to wrapper types.
/// Ex: `struct Wrapper(u32)`, `struct SomeName(Wrapper)`, etc.
/// Needs
#[proc_macro_derive(ToFromBytesEndian)]
pub fn to_from_bytes_endian_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
}
