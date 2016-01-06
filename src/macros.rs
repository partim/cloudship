macro_rules! scribble {
    ($scribe:expr, $($item:expr),*) => {
        $($item.scribble($scribe);)*
    }
}

