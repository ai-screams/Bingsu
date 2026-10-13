//! Color: `math` converts OKLCH, OKLab and sRGB and quantizes the results;
//! `notation` parses the color notations accepted for overrides; `palette`
//! resolves settings into the token table without rendering; `sgr` writes
//! that table out as SGR at three color depths.
pub mod math;
pub mod notation;
pub mod palette;
pub mod sgr;
