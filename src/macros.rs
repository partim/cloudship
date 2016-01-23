//------------ for util::scribe ---------------------------------------------

macro_rules! scribble {
    ($scribe:expr, $($item:expr),*) => {{
        use util::scribe::Scribble;
        let mut scribe = $scribe;
        $($item.scribble(scribe);)*
    }}
}

