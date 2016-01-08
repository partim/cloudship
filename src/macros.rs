macro_rules! scribble {
    ($scribe:expr, $($item:expr),*) => {{
        let mut scribe = $scribe;
        $($item.scribble(scribe);)*
    }}
}

