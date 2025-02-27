//! A logging framework for eBPF programs.
//!
//! This is the user space side of the [Aya] logging framework. For the eBPF
//! side, see the `aya-log-ebpf` crate.
//!
//! `aya-log` provides the [EbpfLogger] type, which reads log records created by
//! `aya-log-ebpf` and logs them using the [log] crate. Any logger that
//! implements the [Log] trait can be used with this crate.
//!
//! # Example:
//!
//! This example uses the [env_logger] crate to log messages to the terminal.
//!
//! ```no_run
//! # let mut bpf = aya::Ebpf::load(&[]).unwrap();
//! use aya_log::EbpfLogger;
//!
//! // initialize env_logger as the default logger
//! env_logger::init();
//!
//! // start reading aya-log records and log them using the default logger
//! EbpfLogger::init(&mut bpf).unwrap();
//! ```
//!
//! With the following eBPF code:
//!
//! ```ignore
//! # let ctx = ();
//! use aya_log_ebpf::{debug, error, info, trace, warn};
//!
//! error!(&ctx, "this is an error message 🚨");
//! warn!(&ctx, "this is a warning message ⚠️");
//! info!(&ctx, "this is an info message ℹ️");
//! debug!(&ctx, "this is a debug message ️🐝");
//! trace!(&ctx, "this is a trace message 🔍");
//! ```
//! Outputs:
//!
//! ```text
//! 21:58:55 [ERROR] xxx: [src/main.rs:35] this is an error message 🚨
//! 21:58:55 [WARN] xxx: [src/main.rs:36] this is a warning message ⚠️
//! 21:58:55 [INFO] xxx: [src/main.rs:37] this is an info message ℹ️
//! 21:58:55 [DEBUG] (7) xxx: [src/main.rs:38] this is a debug message ️🐝
//! 21:58:55 [TRACE] (7) xxx: [src/main.rs:39] this is a trace message 🔍
//! ```
//!
//! [Aya]: https://docs.rs/aya
//! [env_logger]: https://docs.rs/env_logger
//! [Log]: https://docs.rs/log/0.4.14/log/trait.Log.html
//! [log]: https://docs.rs/log
//!
use std::{
    fmt::{LowerHex, UpperHex},
    io, mem,
    net::{Ipv4Addr, Ipv6Addr},
    ptr, str,
    sync::Arc,
};

const MAP_NAME: &str = "AYA_LOGS";

use aya::{
    maps::{
        perf::{AsyncPerfEventArray, Events, PerfBufferError},
        Map, MapData, MapError, MapInfo,
    },
    programs::{loaded_programs, ProgramError},
    util::online_cpus,
    Ebpf, Pod,
};
use aya_log_common::{
    Argument, DisplayHint, Level, LogValueLength, RecordField, LOG_BUF_CAPACITY, LOG_FIELDS,
};
use bytes::BytesMut;
use log::{error, Log, Record};
use thiserror::Error;

#[allow(dead_code)] // TODO(https://github.com/rust-lang/rust/issues/120770): Remove when false positive is fixed.
#[derive(Copy, Clone)]
#[repr(transparent)]
struct RecordFieldWrapper(RecordField);
#[allow(dead_code)] // TODO(https://github.com/rust-lang/rust/issues/120770): Remove when false positive is fixed.
#[derive(Copy, Clone)]
#[repr(transparent)]
struct ArgumentWrapper(Argument);
#[derive(Copy, Clone)]
#[repr(transparent)]
struct DisplayHintWrapper(DisplayHint);

unsafe impl Pod for RecordFieldWrapper {}
unsafe impl Pod for ArgumentWrapper {}
unsafe impl Pod for DisplayHintWrapper {}

/// Log messages generated by `aya_log_ebpf` using the [log] crate.
///
/// For more details see the [module level documentation](crate).
pub struct EbpfLogger;

/// Log messages generated by `aya_log_ebpf` using the [log] crate.
#[deprecated(since = "0.2.1", note = "Use `aya_log::EbpfLogger` instead")]
pub type BpfLogger = EbpfLogger;

impl EbpfLogger {
    /// Starts reading log records created with `aya-log-ebpf` and logs them
    /// with the default logger. See [log::logger].
    pub fn init(bpf: &mut Ebpf) -> Result<EbpfLogger, Error> {
        EbpfLogger::init_with_logger(bpf, log::logger())
    }

    /// Starts reading log records created with `aya-log-ebpf` and logs them
    /// with the given logger.
    pub fn init_with_logger<T: Log + 'static>(
        bpf: &mut Ebpf,
        logger: T,
    ) -> Result<EbpfLogger, Error> {
        let map = bpf.take_map(MAP_NAME).ok_or(Error::MapNotFound)?;
        Self::read_logs_async(map, logger)?;
        Ok(EbpfLogger {})
    }

    /// Attaches to an existing `aya-log-ebpf` instance.
    ///
    /// Attaches to the logs produced by `program_id`. Can be used to read logs generated by a
    /// pinned program. The log records will be written to the default logger. See [log::logger].
    pub fn init_from_id(program_id: u32) -> Result<EbpfLogger, Error> {
        Self::init_from_id_with_logger(program_id, log::logger())
    }

    /// Attaches to an existing `aya-log-ebpf` instance and logs with the given logger.
    ///
    /// Attaches to the logs produced by `program_id`. Can be used to read logs generated by a
    /// pinned program. The log records will be written to the given logger.
    pub fn init_from_id_with_logger<T: Log + 'static>(
        program_id: u32,
        logger: T,
    ) -> Result<EbpfLogger, Error> {
        let program_info = loaded_programs()
            .filter_map(|info| info.ok())
            .find(|info| info.id() == program_id)
            .ok_or(Error::ProgramNotFound)?;

        let map = program_info
            .map_ids()
            .map_err(Error::ProgramError)?
            .ok_or_else(|| Error::MapNotFound)?
            .iter()
            .filter_map(|id| MapInfo::from_id(*id).ok())
            .find(|map_info| match map_info.name_as_str() {
                Some(name) => name == MAP_NAME,
                None => false,
            })
            .ok_or(Error::MapNotFound)?;
        let map = MapData::from_id(map.id()).map_err(Error::MapError)?;

        Self::read_logs_async(Map::PerfEventArray(map), logger)?;

        Ok(EbpfLogger {})
    }

    fn read_logs_async<T: Log + 'static>(map: Map, logger: T) -> Result<(), Error> {
        let mut logs: AsyncPerfEventArray<_> = map.try_into()?;

        let logger = Arc::new(logger);
        for cpu_id in online_cpus().map_err(|(_, error)| Error::InvalidOnlineCpu(error))? {
            let mut buf = logs.open(cpu_id, None)?;

            let log = logger.clone();
            tokio::spawn(async move {
                let mut buffers = vec![BytesMut::with_capacity(LOG_BUF_CAPACITY); 10];

                loop {
                    let Events { read, lost: _ } = buf.read_events(&mut buffers).await.unwrap();

                    for buf in buffers.iter().take(read) {
                        log_buf(buf.as_ref(), &*log).unwrap();
                    }
                }
            });
        }
        Ok(())
    }
}

pub trait Formatter<T> {
    fn format(v: T) -> String;
}

pub struct DefaultFormatter;
impl<T> Formatter<T> for DefaultFormatter
where
    T: ToString,
{
    fn format(v: T) -> String {
        v.to_string()
    }
}

pub struct LowerHexFormatter;
impl<T> Formatter<T> for LowerHexFormatter
where
    T: LowerHex,
{
    fn format(v: T) -> String {
        format!("{v:x}")
    }
}

pub struct LowerHexBytesFormatter;
impl Formatter<&[u8]> for LowerHexBytesFormatter {
    fn format(v: &[u8]) -> String {
        let mut s = String::new();
        for v in v {
            let () = core::fmt::write(&mut s, format_args!("{v:02x}")).unwrap();
        }
        s
    }
}

pub struct UpperHexFormatter;
impl<T> Formatter<T> for UpperHexFormatter
where
    T: UpperHex,
{
    fn format(v: T) -> String {
        format!("{v:X}")
    }
}

pub struct UpperHexBytesFormatter;
impl Formatter<&[u8]> for UpperHexBytesFormatter {
    fn format(v: &[u8]) -> String {
        let mut s = String::new();
        for v in v {
            let () = core::fmt::write(&mut s, format_args!("{v:02X}")).unwrap();
        }
        s
    }
}

pub struct Ipv4Formatter;
impl<T> Formatter<T> for Ipv4Formatter
where
    T: Into<Ipv4Addr>,
{
    fn format(v: T) -> String {
        v.into().to_string()
    }
}

pub struct Ipv6Formatter;
impl<T> Formatter<T> for Ipv6Formatter
where
    T: Into<Ipv6Addr>,
{
    fn format(v: T) -> String {
        v.into().to_string()
    }
}

pub struct LowerMacFormatter;
impl Formatter<[u8; 6]> for LowerMacFormatter {
    fn format(v: [u8; 6]) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            v[0], v[1], v[2], v[3], v[4], v[5]
        )
    }
}

pub struct UpperMacFormatter;
impl Formatter<[u8; 6]> for UpperMacFormatter {
    fn format(v: [u8; 6]) -> String {
        format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            v[0], v[1], v[2], v[3], v[4], v[5]
        )
    }
}

trait Format {
    fn format(&self, last_hint: Option<DisplayHintWrapper>) -> Result<String, ()>;
}

impl Format for &[u8] {
    fn format(&self, last_hint: Option<DisplayHintWrapper>) -> Result<String, ()> {
        match last_hint.map(|DisplayHintWrapper(dh)| dh) {
            Some(DisplayHint::LowerHex) => Ok(LowerHexBytesFormatter::format(self)),
            Some(DisplayHint::UpperHex) => Ok(UpperHexBytesFormatter::format(self)),
            _ => Err(()),
        }
    }
}

impl Format for u32 {
    fn format(&self, last_hint: Option<DisplayHintWrapper>) -> Result<String, ()> {
        match last_hint.map(|DisplayHintWrapper(dh)| dh) {
            Some(DisplayHint::Default) => Ok(DefaultFormatter::format(self)),
            Some(DisplayHint::LowerHex) => Ok(LowerHexFormatter::format(self)),
            Some(DisplayHint::UpperHex) => Ok(UpperHexFormatter::format(self)),
            Some(DisplayHint::Ip) => Ok(Ipv4Formatter::format(*self)),
            Some(DisplayHint::LowerMac) => Err(()),
            Some(DisplayHint::UpperMac) => Err(()),
            _ => Ok(DefaultFormatter::format(self)),
        }
    }
}

impl Format for Ipv4Addr {
    fn format(&self, last_hint: Option<DisplayHintWrapper>) -> Result<String, ()> {
        match last_hint.map(|DisplayHintWrapper(dh)| dh) {
            Some(DisplayHint::Default) => Ok(Ipv4Formatter::format(*self)),
            Some(DisplayHint::LowerHex) => Err(()),
            Some(DisplayHint::UpperHex) => Err(()),
            Some(DisplayHint::Ip) => Ok(Ipv4Formatter::format(*self)),
            Some(DisplayHint::LowerMac) => Err(()),
            Some(DisplayHint::UpperMac) => Err(()),
            None => Ok(Ipv4Formatter::format(*self)),
        }
    }
}

impl Format for Ipv6Addr {
    fn format(&self, last_hint: Option<DisplayHintWrapper>) -> Result<String, ()> {
        match last_hint.map(|DisplayHintWrapper(dh)| dh) {
            Some(DisplayHint::Default) => Ok(Ipv6Formatter::format(*self)),
            Some(DisplayHint::LowerHex) => Err(()),
            Some(DisplayHint::UpperHex) => Err(()),
            Some(DisplayHint::Ip) => Ok(Ipv6Formatter::format(*self)),
            Some(DisplayHint::LowerMac) => Err(()),
            Some(DisplayHint::UpperMac) => Err(()),
            None => Ok(Ipv6Formatter::format(*self)),
        }
    }
}

impl Format for [u8; 4] {
    fn format(&self, last_hint: Option<DisplayHintWrapper>) -> Result<String, ()> {
        match last_hint.map(|DisplayHintWrapper(dh)| dh) {
            Some(DisplayHint::Default) => Ok(Ipv4Formatter::format(*self)),
            Some(DisplayHint::LowerHex) => Err(()),
            Some(DisplayHint::UpperHex) => Err(()),
            Some(DisplayHint::Ip) => Ok(Ipv4Formatter::format(*self)),
            Some(DisplayHint::LowerMac) => Err(()),
            Some(DisplayHint::UpperMac) => Err(()),
            None => Ok(Ipv4Formatter::format(*self)),
        }
    }
}

impl Format for [u8; 6] {
    fn format(&self, last_hint: Option<DisplayHintWrapper>) -> Result<String, ()> {
        match last_hint.map(|DisplayHintWrapper(dh)| dh) {
            Some(DisplayHint::Default) => Err(()),
            Some(DisplayHint::LowerHex) => Err(()),
            Some(DisplayHint::UpperHex) => Err(()),
            Some(DisplayHint::Ip) => Err(()),
            Some(DisplayHint::LowerMac) => Ok(LowerMacFormatter::format(*self)),
            Some(DisplayHint::UpperMac) => Ok(UpperMacFormatter::format(*self)),
            _ => Err(()),
        }
    }
}

impl Format for [u8; 16] {
    fn format(&self, last_hint: Option<DisplayHintWrapper>) -> Result<String, ()> {
        match last_hint.map(|DisplayHintWrapper(dh)| dh) {
            Some(DisplayHint::Default) => Err(()),
            Some(DisplayHint::LowerHex) => Err(()),
            Some(DisplayHint::UpperHex) => Err(()),
            Some(DisplayHint::Ip) => Ok(Ipv6Formatter::format(*self)),
            Some(DisplayHint::LowerMac) => Err(()),
            Some(DisplayHint::UpperMac) => Err(()),
            _ => Err(()),
        }
    }
}

impl Format for [u16; 8] {
    fn format(&self, last_hint: Option<DisplayHintWrapper>) -> Result<String, ()> {
        match last_hint.map(|DisplayHintWrapper(dh)| dh) {
            Some(DisplayHint::Default) => Err(()),
            Some(DisplayHint::LowerHex) => Err(()),
            Some(DisplayHint::UpperHex) => Err(()),
            Some(DisplayHint::Ip) => Ok(Ipv6Formatter::format(*self)),
            Some(DisplayHint::LowerMac) => Err(()),
            Some(DisplayHint::UpperMac) => Err(()),
            _ => Err(()),
        }
    }
}

macro_rules! impl_format {
    ($type:ident) => {
        impl Format for $type {
            fn format(&self, last_hint: Option<DisplayHintWrapper>) -> Result<String, ()> {
                match last_hint.map(|DisplayHintWrapper(dh)| dh) {
                    Some(DisplayHint::Default) => Ok(DefaultFormatter::format(self)),
                    Some(DisplayHint::LowerHex) => Ok(LowerHexFormatter::format(self)),
                    Some(DisplayHint::UpperHex) => Ok(UpperHexFormatter::format(self)),
                    Some(DisplayHint::Ip) => Err(()),
                    Some(DisplayHint::LowerMac) => Err(()),
                    Some(DisplayHint::UpperMac) => Err(()),
                    _ => Ok(DefaultFormatter::format(self)),
                }
            }
        }
    };
}

impl_format!(i8);
impl_format!(i16);
impl_format!(i32);
impl_format!(i64);
impl_format!(isize);

impl_format!(u8);
impl_format!(u16);
impl_format!(u64);
impl_format!(usize);

macro_rules! impl_format_float {
    ($type:ident) => {
        impl Format for $type {
            fn format(&self, last_hint: Option<DisplayHintWrapper>) -> Result<String, ()> {
                match last_hint.map(|DisplayHintWrapper(dh)| dh) {
                    Some(DisplayHint::Default) => Ok(DefaultFormatter::format(self)),
                    Some(DisplayHint::LowerHex) => Err(()),
                    Some(DisplayHint::UpperHex) => Err(()),
                    Some(DisplayHint::Ip) => Err(()),
                    Some(DisplayHint::LowerMac) => Err(()),
                    Some(DisplayHint::UpperMac) => Err(()),
                    _ => Ok(DefaultFormatter::format(self)),
                }
            }
        }
    };
}

impl_format_float!(f32);
impl_format_float!(f64);

#[derive(Error, Debug)]
pub enum Error {
    #[error("log event array {} doesn't exist", MAP_NAME)]
    MapNotFound,

    #[error("error opening log event array")]
    MapError(#[from] MapError),

    #[error("error opening log buffer")]
    PerfBufferError(#[from] PerfBufferError),

    #[error("invalid /sys/devices/system/cpu/online format")]
    InvalidOnlineCpu(#[source] io::Error),

    #[error("program not found")]
    ProgramNotFound,

    #[error(transparent)]
    ProgramError(#[from] ProgramError),
}

fn log_buf(mut buf: &[u8], logger: &dyn Log) -> Result<(), ()> {
    let mut target = None;
    let mut level = None;
    let mut module = None;
    let mut file = None;
    let mut line = None;
    let mut num_args = None;

    for () in std::iter::repeat_n((), LOG_FIELDS) {
        let (RecordFieldWrapper(tag), value, rest) = try_read(buf)?;

        match tag {
            RecordField::Target => {
                target = Some(str::from_utf8(value).map_err(|std::str::Utf8Error { .. }| ())?);
            }
            RecordField::Level => {
                level = Some({
                    let level = unsafe { ptr::read_unaligned(value.as_ptr() as *const _) };
                    match level {
                        Level::Error => log::Level::Error,
                        Level::Warn => log::Level::Warn,
                        Level::Info => log::Level::Info,
                        Level::Debug => log::Level::Debug,
                        Level::Trace => log::Level::Trace,
                    }
                })
            }
            RecordField::Module => {
                module = Some(str::from_utf8(value).map_err(|std::str::Utf8Error { .. }| ())?);
            }
            RecordField::File => {
                file = Some(str::from_utf8(value).map_err(|std::str::Utf8Error { .. }| ())?);
            }
            RecordField::Line => {
                line = Some(u32::from_ne_bytes(
                    value
                        .try_into()
                        .map_err(|std::array::TryFromSliceError { .. }| ())?,
                ));
            }
            RecordField::NumArgs => {
                num_args = Some(usize::from_ne_bytes(
                    value
                        .try_into()
                        .map_err(|std::array::TryFromSliceError { .. }| ())?,
                ));
            }
        }

        buf = rest;
    }

    let mut full_log_msg = String::new();
    let mut last_hint: Option<DisplayHintWrapper> = None;
    for () in std::iter::repeat_n((), num_args.ok_or(())?) {
        let (ArgumentWrapper(tag), value, rest) = try_read(buf)?;

        match tag {
            Argument::DisplayHint => {
                last_hint = Some(unsafe { ptr::read_unaligned(value.as_ptr() as *const _) });
            }
            Argument::I8 => {
                full_log_msg.push_str(
                    &i8::from_ne_bytes(
                        value
                            .try_into()
                            .map_err(|std::array::TryFromSliceError { .. }| ())?,
                    )
                    .format(last_hint.take())?,
                );
            }
            Argument::I16 => {
                full_log_msg.push_str(
                    &i16::from_ne_bytes(
                        value
                            .try_into()
                            .map_err(|std::array::TryFromSliceError { .. }| ())?,
                    )
                    .format(last_hint.take())?,
                );
            }
            Argument::I32 => {
                full_log_msg.push_str(
                    &i32::from_ne_bytes(
                        value
                            .try_into()
                            .map_err(|std::array::TryFromSliceError { .. }| ())?,
                    )
                    .format(last_hint.take())?,
                );
            }
            Argument::I64 => {
                full_log_msg.push_str(
                    &i64::from_ne_bytes(
                        value
                            .try_into()
                            .map_err(|std::array::TryFromSliceError { .. }| ())?,
                    )
                    .format(last_hint.take())?,
                );
            }
            Argument::Isize => {
                full_log_msg.push_str(
                    &isize::from_ne_bytes(
                        value
                            .try_into()
                            .map_err(|std::array::TryFromSliceError { .. }| ())?,
                    )
                    .format(last_hint.take())?,
                );
            }
            Argument::U8 => {
                full_log_msg.push_str(
                    &u8::from_ne_bytes(
                        value
                            .try_into()
                            .map_err(|std::array::TryFromSliceError { .. }| ())?,
                    )
                    .format(last_hint.take())?,
                );
            }
            Argument::U16 => {
                full_log_msg.push_str(
                    &u16::from_ne_bytes(
                        value
                            .try_into()
                            .map_err(|std::array::TryFromSliceError { .. }| ())?,
                    )
                    .format(last_hint.take())?,
                );
            }
            Argument::U32 => {
                full_log_msg.push_str(
                    &u32::from_ne_bytes(
                        value
                            .try_into()
                            .map_err(|std::array::TryFromSliceError { .. }| ())?,
                    )
                    .format(last_hint.take())?,
                );
            }
            Argument::U64 => {
                full_log_msg.push_str(
                    &u64::from_ne_bytes(
                        value
                            .try_into()
                            .map_err(|std::array::TryFromSliceError { .. }| ())?,
                    )
                    .format(last_hint.take())?,
                );
            }
            Argument::Usize => {
                full_log_msg.push_str(
                    &usize::from_ne_bytes(
                        value
                            .try_into()
                            .map_err(|std::array::TryFromSliceError { .. }| ())?,
                    )
                    .format(last_hint.take())?,
                );
            }
            Argument::F32 => {
                full_log_msg.push_str(
                    &f32::from_ne_bytes(
                        value
                            .try_into()
                            .map_err(|std::array::TryFromSliceError { .. }| ())?,
                    )
                    .format(last_hint.take())?,
                );
            }
            Argument::F64 => {
                full_log_msg.push_str(
                    &f64::from_ne_bytes(
                        value
                            .try_into()
                            .map_err(|std::array::TryFromSliceError { .. }| ())?,
                    )
                    .format(last_hint.take())?,
                );
            }
            Argument::Ipv4Addr => {
                let value: [u8; 4] = value
                    .try_into()
                    .map_err(|std::array::TryFromSliceError { .. }| ())?;
                let value = Ipv4Addr::from(value);
                full_log_msg.push_str(&value.format(last_hint.take())?)
            }
            Argument::Ipv6Addr => {
                let value: [u8; 16] = value
                    .try_into()
                    .map_err(|std::array::TryFromSliceError { .. }| ())?;
                let value = Ipv6Addr::from(value);
                full_log_msg.push_str(&value.format(last_hint.take())?)
            }
            Argument::ArrU8Len4 => {
                let value: [u8; 4] = value
                    .try_into()
                    .map_err(|std::array::TryFromSliceError { .. }| ())?;
                full_log_msg.push_str(&value.format(last_hint.take())?);
            }
            Argument::ArrU8Len6 => {
                let value: [u8; 6] = value
                    .try_into()
                    .map_err(|std::array::TryFromSliceError { .. }| ())?;
                full_log_msg.push_str(&value.format(last_hint.take())?);
            }
            Argument::ArrU8Len16 => {
                let value: [u8; 16] = value
                    .try_into()
                    .map_err(|std::array::TryFromSliceError { .. }| ())?;
                full_log_msg.push_str(&value.format(last_hint.take())?);
            }
            Argument::ArrU16Len8 => {
                let data: [u8; 16] = value
                    .try_into()
                    .map_err(|std::array::TryFromSliceError { .. }| ())?;
                let mut value: [u16; 8] = Default::default();
                for (i, s) in data.chunks_exact(2).enumerate() {
                    value[i] = ((s[1] as u16) << 8) | s[0] as u16;
                }
                full_log_msg.push_str(&value.format(last_hint.take())?);
            }
            Argument::Bytes => {
                full_log_msg.push_str(&value.format(last_hint.take())?);
            }
            Argument::Str => match str::from_utf8(value) {
                Ok(v) => {
                    full_log_msg.push_str(v);
                }
                Err(e) => error!("received invalid utf8 string: {}", e),
            },
        }

        buf = rest;
    }

    logger.log(
        &Record::builder()
            .args(format_args!("{full_log_msg}"))
            .target(target.ok_or(())?)
            .level(level.ok_or(())?)
            .module_path(module)
            .file(file)
            .line(line)
            .build(),
    );
    logger.flush();
    Ok(())
}

fn try_read<T: Pod>(mut buf: &[u8]) -> Result<(T, &[u8], &[u8]), ()> {
    if buf.len() < mem::size_of::<T>() + mem::size_of::<LogValueLength>() {
        return Err(());
    }

    let tag = unsafe { ptr::read_unaligned(buf.as_ptr() as *const T) };
    buf = &buf[mem::size_of::<T>()..];

    let len =
        LogValueLength::from_ne_bytes(buf[..mem::size_of::<LogValueLength>()].try_into().unwrap());
    buf = &buf[mem::size_of::<LogValueLength>()..];

    let len: usize = len.into();
    if buf.len() < len {
        return Err(());
    }

    let (value, rest) = buf.split_at(len);
    Ok((tag, value, rest))
}

#[cfg(test)]
mod test {
    use std::net::IpAddr;

    use aya_log_common::{write_record_header, WriteToBuf};
    use log::{logger, Level};

    use super::*;

    fn new_log(args: usize) -> Option<(usize, Vec<u8>)> {
        let mut buf = vec![0; 8192];
        let len = write_record_header(
            &mut buf,
            "test",
            aya_log_common::Level::Info,
            "test",
            "test.rs",
            123,
            args,
        )?;
        Some((len.get(), buf))
    }

    #[test]
    fn test_str() {
        testing_logger::setup();
        let (mut len, mut input) = new_log(1).unwrap();

        len += "test".write(&mut input[len..]).unwrap().get();

        _ = len;

        let logger = logger();
        let () = log_buf(&input, logger).unwrap();
        testing_logger::validate(|captured_logs| {
            assert_eq!(captured_logs.len(), 1);
            assert_eq!(captured_logs[0].body, "test");
            assert_eq!(captured_logs[0].level, Level::Info);
        });
    }

    #[test]
    fn test_str_with_args() {
        testing_logger::setup();
        let (mut len, mut input) = new_log(2).unwrap();

        len += "hello ".write(&mut input[len..]).unwrap().get();
        len += "test".write(&mut input[len..]).unwrap().get();

        _ = len;

        let logger = logger();
        let () = log_buf(&input, logger).unwrap();
        testing_logger::validate(|captured_logs| {
            assert_eq!(captured_logs.len(), 1);
            assert_eq!(captured_logs[0].body, "hello test");
            assert_eq!(captured_logs[0].level, Level::Info);
        });
    }

    #[test]
    fn test_bytes() {
        testing_logger::setup();
        let (mut len, mut input) = new_log(2).unwrap();

        len += DisplayHint::LowerHex
            .write(&mut input[len..])
            .unwrap()
            .get();
        len += [0xde, 0xad].write(&mut input[len..]).unwrap().get();

        _ = len;

        let logger = logger();
        let () = log_buf(&input, logger).unwrap();
        testing_logger::validate(|captured_logs| {
            assert_eq!(captured_logs.len(), 1);
            assert_eq!(captured_logs[0].body, "dead");
            assert_eq!(captured_logs[0].level, Level::Info);
        });
    }

    #[test]
    fn test_bytes_with_args() {
        testing_logger::setup();
        let (mut len, mut input) = new_log(5).unwrap();

        len += DisplayHint::LowerHex
            .write(&mut input[len..])
            .unwrap()
            .get();
        len += [0xde, 0xad].write(&mut input[len..]).unwrap().get();

        len += " ".write(&mut input[len..]).unwrap().get();

        len += DisplayHint::UpperHex
            .write(&mut input[len..])
            .unwrap()
            .get();
        len += [0xbe, 0xef].write(&mut input[len..]).unwrap().get();

        _ = len;

        let logger = logger();
        let () = log_buf(&input, logger).unwrap();
        testing_logger::validate(|captured_logs| {
            assert_eq!(captured_logs.len(), 1);
            assert_eq!(captured_logs[0].body, "dead BEEF");
            assert_eq!(captured_logs[0].level, Level::Info);
        });
    }

    #[test]
    fn test_bytes_unambiguous() {
        testing_logger::setup();
        let (mut len, mut input) = new_log(5).unwrap();

        len += DisplayHint::LowerHex
            .write(&mut input[len..])
            .unwrap()
            .get();
        len += [0x01, 0x02].write(&mut input[len..]).unwrap().get();

        len += " ".write(&mut input[len..]).unwrap().get();

        len += DisplayHint::LowerHex
            .write(&mut input[len..])
            .unwrap()
            .get();
        len += [0x12].write(&mut input[len..]).unwrap().get();

        _ = len;

        let logger = logger();
        let () = log_buf(&input, logger).unwrap();
        testing_logger::validate(|captured_logs| {
            assert_eq!(captured_logs.len(), 1);
            assert_eq!(captured_logs[0].body, "0102 12");
            assert_eq!(captured_logs[0].level, Level::Info);
        });
    }

    #[test]
    fn test_display_hint_default() {
        testing_logger::setup();
        let (mut len, mut input) = new_log(3).unwrap();

        len += "default hint: ".write(&mut input[len..]).unwrap().get();
        len += DisplayHint::Default.write(&mut input[len..]).unwrap().get();
        len += 14.write(&mut input[len..]).unwrap().get();

        _ = len;

        let logger = logger();
        let () = log_buf(&input, logger).unwrap();
        testing_logger::validate(|captured_logs| {
            assert_eq!(captured_logs.len(), 1);
            assert_eq!(captured_logs[0].body, "default hint: 14");
            assert_eq!(captured_logs[0].level, Level::Info);
        });
    }

    #[test]
    fn test_display_hint_lower_hex() {
        testing_logger::setup();
        let (mut len, mut input) = new_log(3).unwrap();

        len += "lower hex: ".write(&mut input[len..]).unwrap().get();
        len += DisplayHint::LowerHex
            .write(&mut input[len..])
            .unwrap()
            .get();
        len += 200.write(&mut input[len..]).unwrap().get();

        _ = len;

        let logger = logger();
        let () = log_buf(&input, logger).unwrap();
        testing_logger::validate(|captured_logs| {
            assert_eq!(captured_logs.len(), 1);
            assert_eq!(captured_logs[0].body, "lower hex: c8");
            assert_eq!(captured_logs[0].level, Level::Info);
        });
    }

    #[test]
    fn test_display_hint_upper_hex() {
        testing_logger::setup();
        let (mut len, mut input) = new_log(3).unwrap();

        len += "upper hex: ".write(&mut input[len..]).unwrap().get();
        len += DisplayHint::UpperHex
            .write(&mut input[len..])
            .unwrap()
            .get();
        len += 200.write(&mut input[len..]).unwrap().get();

        _ = len;

        let logger = logger();
        let () = log_buf(&input, logger).unwrap();
        testing_logger::validate(|captured_logs| {
            assert_eq!(captured_logs.len(), 1);
            assert_eq!(captured_logs[0].body, "upper hex: C8");
            assert_eq!(captured_logs[0].level, Level::Info);
        });
    }

    #[test]
    fn test_display_hint_ipv4() {
        testing_logger::setup();
        let (mut len, mut input) = new_log(3).unwrap();

        len += "ipv4: ".write(&mut input[len..]).unwrap().get();
        len += DisplayHint::Ip.write(&mut input[len..]).unwrap().get();
        len += Ipv4Addr::new(10, 0, 0, 1)
            .write(&mut input[len..])
            .unwrap()
            .get();

        _ = len;

        let logger = logger();
        let () = log_buf(&input, logger).unwrap();
        testing_logger::validate(|captured_logs| {
            assert_eq!(captured_logs.len(), 1);
            assert_eq!(captured_logs[0].body, "ipv4: 10.0.0.1");
            assert_eq!(captured_logs[0].level, Level::Info);
        });
    }

    #[test]
    fn test_display_hint_ip_ipv4() {
        testing_logger::setup();
        let (mut len, mut input) = new_log(3).unwrap();

        len += "ipv4: ".write(&mut input[len..]).unwrap().get();
        len += DisplayHint::Ip.write(&mut input[len..]).unwrap().get();
        len += IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
            .write(&mut input[len..])
            .unwrap()
            .get();

        _ = len;

        let logger = logger();
        let () = log_buf(&input, logger).unwrap();
        testing_logger::validate(|captured_logs| {
            assert_eq!(captured_logs.len(), 1);
            assert_eq!(captured_logs[0].body, "ipv4: 10.0.0.1");
            assert_eq!(captured_logs[0].level, Level::Info);
        });
    }

    #[test]
    fn test_display_hint_ipv4_u32() {
        testing_logger::setup();
        let (mut len, mut input) = new_log(3).unwrap();

        len += "ipv4: ".write(&mut input[len..]).unwrap().get();
        len += DisplayHint::Ip.write(&mut input[len..]).unwrap().get();
        // 10.0.0.1 as u32
        len += 167772161u32.write(&mut input[len..]).unwrap().get();

        _ = len;

        let logger = logger();
        let () = log_buf(&input, logger).unwrap();
        testing_logger::validate(|captured_logs| {
            assert_eq!(captured_logs.len(), 1);
            assert_eq!(captured_logs[0].body, "ipv4: 10.0.0.1");
            assert_eq!(captured_logs[0].level, Level::Info);
        });
    }

    #[test]
    fn test_display_hint_ipv6() {
        testing_logger::setup();
        let (mut len, mut input) = new_log(3).unwrap();

        len += "ipv6: ".write(&mut input[len..]).unwrap().get();
        len += DisplayHint::Ip.write(&mut input[len..]).unwrap().get();
        len += Ipv6Addr::new(
            0x2001, 0x0db8, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001, 0x0001,
        )
        .write(&mut input[len..])
        .unwrap()
        .get();

        _ = len;

        let logger = logger();
        let () = log_buf(&input, logger).unwrap();
        testing_logger::validate(|captured_logs| {
            assert_eq!(captured_logs.len(), 1);
            assert_eq!(captured_logs[0].body, "ipv6: 2001:db8::1:1");
            assert_eq!(captured_logs[0].level, Level::Info);
        });
    }

    #[test]
    fn test_display_hint_ip_ipv6() {
        testing_logger::setup();
        let (mut len, mut input) = new_log(3).unwrap();

        len += "ipv6: ".write(&mut input[len..]).unwrap().get();
        len += DisplayHint::Ip.write(&mut input[len..]).unwrap().get();
        len += IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x0db8, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001, 0x0001,
        ))
        .write(&mut input[len..])
        .unwrap()
        .get();

        _ = len;

        let logger = logger();
        let () = log_buf(&input, logger).unwrap();
        testing_logger::validate(|captured_logs| {
            assert_eq!(captured_logs.len(), 1);
            assert_eq!(captured_logs[0].body, "ipv6: 2001:db8::1:1");
            assert_eq!(captured_logs[0].level, Level::Info);
        });
    }

    #[test]
    fn test_display_hint_ipv6_arr_u8_len_16() {
        testing_logger::setup();
        let (mut len, mut input) = new_log(3).unwrap();

        len += "ipv6: ".write(&mut input[len..]).unwrap().get();
        len += DisplayHint::Ip.write(&mut input[len..]).unwrap().get();
        // 2001:db8::1:1 as byte array
        let ipv6_arr: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x01,
        ];
        len += ipv6_arr.write(&mut input[len..]).unwrap().get();

        _ = len;

        let logger = logger();
        let () = log_buf(&input, logger).unwrap();
        testing_logger::validate(|captured_logs| {
            assert_eq!(captured_logs.len(), 1);
            assert_eq!(captured_logs[0].body, "ipv6: 2001:db8::1:1");
            assert_eq!(captured_logs[0].level, Level::Info);
        });
    }

    #[test]
    fn test_display_hint_ipv6_arr_u16_len_8() {
        testing_logger::setup();
        let (mut len, mut input) = new_log(3).unwrap();

        len += "ipv6: ".write(&mut input[len..]).unwrap().get();
        len += DisplayHint::Ip.write(&mut input[len..]).unwrap().get();
        // 2001:db8::1:1 as u16 array
        #[cfg(target_endian = "little")]
        let ipv6_arr: [u16; 8] = [
            0x2001, 0x0db8, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001, 0x0001,
        ];
        #[cfg(target_endian = "big")]
        let ipv6_arr: [u16; 8] = [
            0x0120, 0xb80d, 0x0000, 0x0000, 0x0000, 0x0000, 0x0100, 0x0100,
        ];
        len += ipv6_arr.write(&mut input[len..]).unwrap().get();

        _ = len;

        let logger = logger();
        let () = log_buf(&input, logger).unwrap();
        testing_logger::validate(|captured_logs| {
            assert_eq!(captured_logs.len(), 1);
            assert_eq!(captured_logs[0].body, "ipv6: 2001:db8::1:1");
            assert_eq!(captured_logs[0].level, Level::Info);
        });
    }

    #[test]
    fn test_display_hint_lower_mac() {
        testing_logger::setup();
        let (mut len, mut input) = new_log(3).unwrap();

        len += "mac: ".write(&mut input[len..]).unwrap().get();
        len += DisplayHint::LowerMac
            .write(&mut input[len..])
            .unwrap()
            .get();
        // 00:00:5e:00:53:af as byte array
        let mac_arr: [u8; 6] = [0x00, 0x00, 0x5e, 0x00, 0x53, 0xaf];
        len += mac_arr.write(&mut input[len..]).unwrap().get();

        _ = len;

        let logger = logger();
        let () = log_buf(&input, logger).unwrap();
        testing_logger::validate(|captured_logs| {
            assert_eq!(captured_logs.len(), 1);
            assert_eq!(captured_logs[0].body, "mac: 00:00:5e:00:53:af");
            assert_eq!(captured_logs[0].level, Level::Info);
        });
    }

    #[test]
    fn test_display_hint_upper_mac() {
        testing_logger::setup();
        let (mut len, mut input) = new_log(3).unwrap();

        len += "mac: ".write(&mut input[len..]).unwrap().get();
        len += DisplayHint::UpperMac
            .write(&mut input[len..])
            .unwrap()
            .get();
        // 00:00:5E:00:53:AF as byte array
        let mac_arr: [u8; 6] = [0x00, 0x00, 0x5e, 0x00, 0x53, 0xaf];
        len += mac_arr.write(&mut input[len..]).unwrap().get();

        _ = len;

        let logger = logger();
        let () = log_buf(&input, logger).unwrap();
        testing_logger::validate(|captured_logs| {
            assert_eq!(captured_logs.len(), 1);
            assert_eq!(captured_logs[0].body, "mac: 00:00:5E:00:53:AF");
            assert_eq!(captured_logs[0].level, Level::Info);
        });
    }
}
