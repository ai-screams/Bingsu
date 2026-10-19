//! probe
/// lt
pub fn lt<T: PartialOrd>(a: &T, b: &T) -> bool {
    a < b
}
/// m
pub fn k03_tuple_field(c: bool) -> bool {
    let t = (|x: u8| x, |x: u8| x + 1);
    let f = if c { t.0 } else { t.1 };
    let g = if c { t.1 } else { t.0 };
    lt(&f, &g)
}
/// m
pub fn k03_array_fields() -> bool {
    let t = (|x: u8| x, |x: u8| x + 1);
    let v = [t.0, t.1];
    lt(&v[0], &v[1])
}
/// p
pub struct P<A, B> { pub a: A, pub b: B }
/// m
pub fn k03_struct_field(c: bool) -> bool {
    let p = P { a: |x: u8| x, b: |x: u8| x + 1 };
    let f = if c { p.a } else { p.b };
    lt(&f, &f)
}
