//! probe
/// Compare two code addresses without a fn item, pointer type or ptr path.
pub fn lt<T: PartialOrd>(a: &T, b: &T) -> bool {
    a < b
}
/// Closure-to-fn-pointer merge (no function item named).
pub fn pick(c: bool) -> bool {
    let f = if c { |x: u8| x } else { |x: u8| x + 1 };
    let g = if c { |x: u8| x + 2 } else { |x: u8| x + 3 };
    lt(&f, &g)
}
/// Tuple-struct constructor merged with a closure.
pub struct W(pub u8);
/// Merge.
pub fn pick2(c: bool) -> bool {
    let f = if c { W } else { |x: u8| W(x) };
    let g = if c { |x: u8| W(x + 1) } else { |x: u8| W(x) };
    lt(&f, &g)
}
/// Pointer identity with no pointer type, no `ptr` path.
fn same<T: PartialEq>(a: T, b: T) -> bool {
    a == b
}
/// Raw borrow.
pub fn ident(a: &u8, b: &u8) -> bool {
    same(&raw const *a, &raw const *b)
}
/// Tuple constructors from the prelude merged with a closure.
pub fn pick3(c: bool) -> bool {
    let f = if c { Some } else { |x: u8| Some(x) };
    let g = if c { |x: u8| Some(x + 1) } else { Some };
    lt(&f, &g)
}
