//! `bingsu setup`'s one-screen editor, without the terminal: its eight
//! rows and their values (`rows`), what the settings files already say for
//! them (`layers`), the state and what each key does (`model`), what saving
//! writes or would change (`write`) and the screen as a grid of cells
//! (`screen`). The CLI reads the keys, loads the files, draws the preview
//! (`preview::lines`) and writes the grid and the file.
pub mod layers;
pub mod model;
pub mod rows;
pub mod screen;
pub mod write;
