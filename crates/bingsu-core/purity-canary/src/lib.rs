//! Purity canary (not a workspace member). One tagged line per entry of
//! crates/bingsu-core/clippy.toml; scripts/check_core_purity.py requires a
//! clippy diagnostic naming exactly that path on exactly that line.
#![allow(dead_code, unused_must_use, unused_variables, unreachable_code, clippy::all)]
#![warn(clippy::disallowed_methods, clippy::disallowed_types, clippy::disallowed_macros)]

pub fn c0() { let _ = std::fs::read("x"); } // CANARY: std::fs::read
pub fn c1() { let _ = std::fs::read_to_string("x"); } // CANARY: std::fs::read_to_string
pub fn c2() { let _ = std::fs::write("x", b""); } // CANARY: std::fs::write
pub fn c3() { let _ = std::fs::File::open("x"); } // CANARY: std::fs::File::open
pub fn c4() { let _ = std::fs::File::create("x"); } // CANARY: std::fs::File::create
pub fn c5() { let _ = std::fs::OpenOptions::new().open("x"); } // CANARY: std::fs::OpenOptions::open
pub fn c6() { let _ = std::fs::metadata("x"); } // CANARY: std::fs::metadata
pub fn c7() { let _ = std::fs::symlink_metadata("x"); } // CANARY: std::fs::symlink_metadata
pub fn c8() { let _ = std::fs::read_dir("x"); } // CANARY: std::fs::read_dir
pub fn c9() { let _ = std::fs::read_link("x"); } // CANARY: std::fs::read_link
pub fn c10() { let _ = std::fs::canonicalize("x"); } // CANARY: std::fs::canonicalize
pub fn c11() { let _ = std::fs::copy("x", "y"); } // CANARY: std::fs::copy
pub fn c12() { let _ = std::fs::rename("x", "y"); } // CANARY: std::fs::rename
pub fn c13() { let _ = std::fs::remove_file("x"); } // CANARY: std::fs::remove_file
pub fn c14() { let _ = std::fs::remove_dir("x"); } // CANARY: std::fs::remove_dir
pub fn c15() { let _ = std::fs::remove_dir_all("x"); } // CANARY: std::fs::remove_dir_all
pub fn c16() { let _ = std::fs::create_dir("x"); } // CANARY: std::fs::create_dir
pub fn c17() { let _ = std::fs::create_dir_all("x"); } // CANARY: std::fs::create_dir_all
pub fn c18() { let _ = std::fs::hard_link("x", "y"); } // CANARY: std::fs::hard_link
pub fn c19() { let _ = |p: std::fs::Permissions| std::fs::set_permissions("x", p); } // CANARY: std::fs::set_permissions
pub fn c20() { let _ = std::os::unix::fs::symlink("x", "y"); } // CANARY: std::os::unix::fs::symlink
pub fn c21() { let _ = std::process::Command::new("x"); } // CANARY: std::process::Command::new
pub fn c22() { std::process::exit(0); } // CANARY: std::process::exit
pub fn c23() { std::process::abort(); } // CANARY: std::process::abort
pub fn c24() { let _ = std::process::id(); } // CANARY: std::process::id
pub fn c25() { let _ = std::env::var("X"); } // CANARY: std::env::var
pub fn c26() { let _ = std::env::var_os("X"); } // CANARY: std::env::var_os
pub fn c27() { let _ = std::env::vars(); } // CANARY: std::env::vars
pub fn c28() { let _ = std::env::vars_os(); } // CANARY: std::env::vars_os
pub fn c29() { let _ = std::env::args(); } // CANARY: std::env::args
pub fn c30() { let _ = std::env::args_os(); } // CANARY: std::env::args_os
pub fn c31() { let _ = std::env::current_dir(); } // CANARY: std::env::current_dir
pub fn c32() { let _ = std::env::set_current_dir("x"); } // CANARY: std::env::set_current_dir
pub fn c33() { #[allow(deprecated)] let _ = std::env::home_dir(); } // CANARY: std::env::home_dir
pub fn c34() { let _ = std::env::temp_dir(); } // CANARY: std::env::temp_dir
pub fn c35() { let _ = std::env::current_exe(); } // CANARY: std::env::current_exe
pub fn c36() { unsafe { std::env::set_var("X", "1") }; } // CANARY: std::env::set_var
pub fn c37() { unsafe { std::env::remove_var("X") }; } // CANARY: std::env::remove_var
pub fn c38() { let _ = std::net::TcpStream::connect("127.0.0.1:1"); } // CANARY: std::net::TcpStream::connect
pub fn c39() { let _ = std::net::TcpListener::bind("127.0.0.1:0"); } // CANARY: std::net::TcpListener::bind
pub fn c40() { let _ = std::net::UdpSocket::bind("127.0.0.1:0"); } // CANARY: std::net::UdpSocket::bind
pub fn c41() { let _ = std::thread::spawn(|| ()); } // CANARY: std::thread::spawn
pub fn c42() { std::thread::sleep(core::time::Duration::ZERO); } // CANARY: std::thread::sleep
pub fn c43() { let _ = std::thread::Builder::new(); } // CANARY: std::thread::Builder::new
pub fn c44() { let _ = std::time::Instant::now(); } // CANARY: std::time::Instant::now
pub fn c45() { let _ = std::time::SystemTime::now(); } // CANARY: std::time::SystemTime::now
pub fn c46() { let _ = std::io::stdout(); } // CANARY: std::io::stdout
pub fn c47() { let _ = std::io::stderr(); } // CANARY: std::io::stderr
pub fn c48() { let _ = std::io::stdin(); } // CANARY: std::io::stdin
pub fn c49() { println!("x"); } // CANARY: std::println
pub fn c50() { print!("x"); } // CANARY: std::print
pub fn c51() { eprintln!("x"); } // CANARY: std::eprintln
pub fn c52() { eprint!("x"); } // CANARY: std::eprint
pub fn c53() { dbg!(1); } // CANARY: std::dbg
pub fn c54() { let _ = std::fs::exists("x"); } // CANARY: std::fs::exists
pub fn c55() { #[allow(deprecated)] let _ = std::fs::soft_link("x", "y"); } // CANARY: std::fs::soft_link
pub fn c56() { let _ = std::time::UNIX_EPOCH.elapsed(); } // CANARY: std::time::SystemTime::elapsed
pub fn c57() { let _ = |i: &std::time::Instant| i.elapsed(); } // CANARY: std::time::Instant::elapsed
pub fn c58() { std::thread::scope(|_| ()); } // CANARY: std::thread::scope
pub fn c59<'s, 'e>(s: &'s std::thread::Scope<'s, 'e>) { s.spawn(|| ()); } // CANARY: std::thread::Scope::spawn
pub fn c60() { #[allow(deprecated)] std::thread::sleep_ms(0); } // CANARY: std::thread::sleep_ms
pub fn c61() { std::thread::park(); } // CANARY: std::thread::park
pub fn c62() { std::thread::park_timeout(core::time::Duration::ZERO); } // CANARY: std::thread::park_timeout
pub fn c63() { #[allow(deprecated)] std::thread::park_timeout_ms(0); } // CANARY: std::thread::park_timeout_ms
pub fn c64() { std::thread::yield_now(); } // CANARY: std::thread::yield_now
pub fn c65() { let _ = std::thread::available_parallelism(); } // CANARY: std::thread::available_parallelism
pub fn c66() { let _ = std::thread::current(); } // CANARY: std::thread::current
pub fn c67() { let _ = std::backtrace::Backtrace::capture(); } // CANARY: std::backtrace::Backtrace::capture
pub fn c68() { let _ = std::backtrace::Backtrace::force_capture(); } // CANARY: std::backtrace::Backtrace::force_capture
pub fn c69() { let _ = std::os::unix::fs::chown("x", None, None); } // CANARY: std::os::unix::fs::chown
pub fn c70() { let _ = |f: &std::fs::File| std::os::unix::fs::fchown(f, None, None); } // CANARY: std::os::unix::fs::fchown
pub fn c71() { let _ = std::os::unix::fs::lchown("x", None, None); } // CANARY: std::os::unix::fs::lchown
pub fn c72() { let _ = std::os::unix::fs::chroot("x"); } // CANARY: std::os::unix::fs::chroot
pub fn c73() { use std::net::ToSocketAddrs; let _ = ("x", 1).to_socket_addrs(); } // CANARY: std::net::ToSocketAddrs::to_socket_addrs
pub fn c74() { let _ = std::os::unix::net::UnixStream::connect("x"); } // CANARY: std::os::unix::net::UnixStream::connect
pub fn c75() { let _ = std::os::unix::net::UnixListener::bind("x"); } // CANARY: std::os::unix::net::UnixListener::bind
pub fn c76() { let _ = std::os::unix::net::UnixDatagram::bind("x"); } // CANARY: std::os::unix::net::UnixDatagram::bind
pub fn c77() { let _ = std::os::unix::process::parent_id(); } // CANARY: std::os::unix::process::parent_id
pub fn t0(_: Option<std::fs::File>) {} // CANARY: std::fs::File
pub fn t1(_: Option<std::fs::OpenOptions>) {} // CANARY: std::fs::OpenOptions
pub fn t2(_: Option<std::fs::DirBuilder>) {} // CANARY: std::fs::DirBuilder
pub fn t3(_: Option<std::fs::ReadDir>) {} // CANARY: std::fs::ReadDir
pub fn t4(_: Option<std::process::Command>) {} // CANARY: std::process::Command
pub fn t5(_: Option<std::process::Child>) {} // CANARY: std::process::Child
pub fn t6(_: Option<std::process::Stdio>) {} // CANARY: std::process::Stdio
pub fn t7(_: Option<std::net::TcpStream>) {} // CANARY: std::net::TcpStream
pub fn t8(_: Option<std::net::TcpListener>) {} // CANARY: std::net::TcpListener
pub fn t9(_: Option<std::net::UdpSocket>) {} // CANARY: std::net::UdpSocket
pub fn t10(_: Option<std::thread::JoinHandle<()>>) {} // CANARY: std::thread::JoinHandle
pub fn t11(_: Option<std::thread::Builder>) {} // CANARY: std::thread::Builder
pub fn t12(_: Option<std::time::Instant>) {} // CANARY: std::time::Instant
pub fn t13(_: Option<std::time::SystemTime>) {} // CANARY: std::time::SystemTime
pub fn t14(_: Option<std::io::Stdin>) {} // CANARY: std::io::Stdin
pub fn t15(_: Option<std::io::Stdout>) {} // CANARY: std::io::Stdout
pub fn t16(_: Option<std::io::Stderr>) {} // CANARY: std::io::Stderr
pub fn t17(_: Option<&std::path::Path>) {} // CANARY: std::path::Path
pub fn t18(_: Option<std::path::PathBuf>) {} // CANARY: std::path::PathBuf
pub fn t19(_: Option<&std::thread::Scope<'_, '_>>) {} // CANARY: std::thread::Scope
pub fn t20(_: Option<std::thread::ScopedJoinHandle<'_, ()>>) {} // CANARY: std::thread::ScopedJoinHandle
pub fn t21(_: Option<std::thread::Thread>) {} // CANARY: std::thread::Thread
pub fn t22(_: Option<std::os::unix::net::UnixStream>) {} // CANARY: std::os::unix::net::UnixStream
pub fn t23(_: Option<std::os::unix::net::UnixListener>) {} // CANARY: std::os::unix::net::UnixListener
pub fn t24(_: Option<std::os::unix::net::UnixDatagram>) {} // CANARY: std::os::unix::net::UnixDatagram
pub fn t25(_: Option<std::backtrace::Backtrace>) {} // CANARY: std::backtrace::Backtrace
pub fn t26(_: Option<std::fs::DirEntry>) {} // CANARY: std::fs::DirEntry
pub fn t27(_: Option<std::fs::Metadata>) {} // CANARY: std::fs::Metadata
pub fn t28(_: Option<std::process::ChildStdin>) {} // CANARY: std::process::ChildStdin
pub fn t29(_: Option<std::process::ChildStdout>) {} // CANARY: std::process::ChildStdout
pub fn t30(_: Option<std::process::ChildStderr>) {} // CANARY: std::process::ChildStderr
pub fn t31(_: Option<std::io::StdinLock<'_>>) {} // CANARY: std::io::StdinLock
pub fn t32(_: Option<std::io::StdoutLock<'_>>) {} // CANARY: std::io::StdoutLock
pub fn t33(_: Option<std::io::StderrLock<'_>>) {} // CANARY: std::io::StderrLock
