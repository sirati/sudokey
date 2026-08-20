//! Low-level wire helpers: big-endian integers, SSH-style length-prefixed
//! strings, and the multiplexed stream frame format used for I/O.

use std::io::{self, Read, Write};

use crate::proto::{MAX_FRAME, MAX_STRING};

pub fn read_u8(r: &mut impl Read) -> io::Result<u8> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b)?;
    Ok(b[0])
}

pub fn read_u16(r: &mut impl Read) -> io::Result<u16> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b)?;
    Ok(u16::from_be_bytes(b))
}

pub fn read_u32(r: &mut impl Read) -> io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_be_bytes(b))
}

pub fn write_u8(w: &mut impl Write, v: u8) -> io::Result<()> {
    w.write_all(&[v])
}

pub fn write_u16(w: &mut impl Write, v: u16) -> io::Result<()> {
    w.write_all(&v.to_be_bytes())
}

pub fn write_u32(w: &mut impl Write, v: u32) -> io::Result<()> {
    w.write_all(&v.to_be_bytes())
}

pub fn write_i32(w: &mut impl Write, v: i32) -> io::Result<()> {
    w.write_all(&v.to_be_bytes())
}

/// Read a `u32`-length-prefixed byte string (SSH wire "string"), rejecting
/// anything longer than `max`. Callers on the pre-authentication path pass a
/// tight bound so an unauthenticated peer cannot steer our allocations.
pub fn read_string_bounded(r: &mut impl Read, max: usize) -> io::Result<Vec<u8>> {
    let len = read_u32(r)? as usize;
    if len > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("string too long: {len} bytes (max {max})"),
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Read a `u32`-length-prefixed byte string with the default `MAX_STRING` cap.
pub fn read_string(r: &mut impl Read) -> io::Result<Vec<u8>> {
    read_string_bounded(r, MAX_STRING)
}

/// Write a `u32`-length-prefixed byte string.
pub fn write_string(w: &mut impl Write, data: &[u8]) -> io::Result<()> {
    write_u32(w, data.len() as u32)?;
    w.write_all(data)
}

/// Write one multiplexed frame: `[u8 channel][u32 be len][payload]`.
pub fn write_frame(w: &mut impl Write, channel: u8, payload: &[u8]) -> io::Result<()> {
    let mut hdr = [0u8; 5];
    hdr[0] = channel;
    hdr[1..5].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    w.write_all(&hdr)?;
    w.write_all(payload)?;
    w.flush()
}

/// Read one multiplexed frame. Returns `(channel, payload)`.
pub fn read_frame(r: &mut impl Read) -> io::Result<(u8, Vec<u8>)> {
    let channel = read_u8(r)?;
    let len = read_u32(r)? as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame too long: {len} bytes"),
        ));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok((channel, payload))
}

/// Parse an SSH wire string out of an in-memory buffer, returning the string
/// and the number of bytes consumed.
pub fn parse_string(buf: &[u8]) -> Option<(&[u8], usize)> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let end = 4usize.checked_add(len)?;
    if buf.len() < end {
        return None;
    }
    Some((&buf[4..end], end))
}
