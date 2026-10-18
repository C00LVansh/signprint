//! Minimal TLS ClientHello parser: just the fields JA4 needs.
//!
//! Input is the raw bytes at the start of a TCP connection, before any TLS
//! library has touched them. A ClientHello may be split over several TLS
//! records (post-quantum key shares push Chrome's past 1.5 KB, though it
//! usually still fits one record), so records are reassembled first.

/// Hard cap on how much we'll buffer looking for a ClientHello.
pub const MAX_HELLO: usize = 16 * 1024;

const CONTENT_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub legacy_version: u16,
    pub ciphers: Vec<u16>,
    /// Extension types in the order they appeared.
    pub extensions: Vec<u16>,
    pub has_sni: bool,
    pub alpn_first: Option<Vec<u8>>,
    pub supported_versions: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Peek {
    /// Need at least this many bytes in total before trying again.
    NeedMore(usize),
    /// The first `n` bytes hold a complete ClientHello.
    Complete(usize),
    /// Not a TLS ClientHello (or too big to bother with).
    NotTls,
}

/// Looks at the bytes received so far and says whether a full ClientHello is
/// there yet. Used to drive the peek loop without consuming the stream.
pub fn peek(buf: &[u8]) -> Peek {
    let mut handshake_len: Option<usize> = None;
    let mut have = 0usize;
    let mut at = 0usize;
    loop {
        if buf.len() < at + 5 {
            return Peek::NeedMore(at + 5);
        }
        if buf[at] != CONTENT_HANDSHAKE || buf[at + 1] != 3 {
            return Peek::NotTls;
        }
        let rec_len = u16::from_be_bytes([buf[at + 3], buf[at + 4]]) as usize;
        if rec_len == 0 || at + 5 + rec_len > MAX_HELLO {
            return Peek::NotTls;
        }
        let rec_end = at + 5 + rec_len;
        if buf.len() < rec_end {
            return Peek::NeedMore(rec_end);
        }
        if handshake_len.is_none() {
            // handshake header sits at the start of the first record
            if rec_len < 4 || buf[at + 5] != HANDSHAKE_CLIENT_HELLO {
                return Peek::NotTls;
            }
            let l = &buf[at + 6..at + 9];
            handshake_len =
                Some(((l[0] as usize) << 16 | (l[1] as usize) << 8 | l[2] as usize) + 4);
        }
        have += rec_len;
        at = rec_end;
        let need = handshake_len.expect("set above");
        if need > MAX_HELLO {
            return Peek::NotTls;
        }
        if have >= need {
            return Peek::Complete(at);
        }
    }
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (h, t) = self.0.split_at(n);
        self.0 = t;
        Some(h)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Option<usize> {
        self.take(3)
            .map(|b| (b[0] as usize) << 16 | (b[1] as usize) << 8 | b[2] as usize)
    }
    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

fn u16_list(b: &[u8]) -> Option<Vec<u16>> {
    if b.len() % 2 != 0 {
        return None;
    }
    Some(
        b.chunks(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect(),
    )
}

/// Parses a ClientHello from the start of a connection. Returns `None` for
/// anything malformed; callers just treat that as "no fingerprint".
pub fn parse(buf: &[u8]) -> Option<ClientHello> {
    let Peek::Complete(end) = peek(buf) else {
        return None;
    };

    // join the record fragments back into one handshake message
    let mut msg = Vec::with_capacity(end);
    let mut at = 0;
    while at < end {
        let len = u16::from_be_bytes([buf[at + 3], buf[at + 4]]) as usize;
        msg.extend_from_slice(&buf[at + 5..at + 5 + len]);
        at += 5 + len;
    }

    let mut c = Cursor(&msg);
    if c.u8()? != HANDSHAKE_CLIENT_HELLO {
        return None;
    }
    let body_len = c.u24()?;
    let mut c = Cursor(c.take(body_len)?);

    let legacy_version = c.u16()?;
    c.take(32)?; // random
    c.vec8()?; // session id
    let ciphers = u16_list(c.vec16()?)?;
    c.vec8()?; // compression methods

    let mut hello = ClientHello {
        legacy_version,
        ciphers,
        extensions: Vec::new(),
        has_sni: false,
        alpn_first: None,
        supported_versions: Vec::new(),
        signature_algorithms: Vec::new(),
    };
    if c.0.is_empty() {
        return Some(hello); // no extensions at all (very old clients)
    }

    let mut exts = Cursor(c.vec16()?);
    while !exts.0.is_empty() {
        let ty = exts.u16()?;
        let data = exts.vec16()?;
        hello.extensions.push(ty);
        match ty {
            0x0000 => hello.has_sni = true,
            0x0010 => {
                let mut list = Cursor(Cursor(data).vec16()?);
                hello.alpn_first = list.vec8().map(<[u8]>::to_vec);
            }
            0x002b => hello.supported_versions = u16_list(Cursor(data).vec8()?)?,
            0x000d => hello.signature_algorithms = u16_list(Cursor(data).vec16()?)?,
            _ => {}
        }
    }
    Some(hello)
}

#[cfg(test)]
pub(crate) mod build {
    //! Builds ClientHello bytes for tests.

    pub struct Ext(pub u16, pub Vec<u8>);

    pub fn sni(host: &str) -> Ext {
        let mut name = vec![0u8];
        name.extend_from_slice(&(host.len() as u16).to_be_bytes());
        name.extend_from_slice(host.as_bytes());
        let mut data = (name.len() as u16).to_be_bytes().to_vec();
        data.extend(name);
        Ext(0x0000, data)
    }

    pub fn alpn(protos: &[&[u8]]) -> Ext {
        let mut list = Vec::new();
        for p in protos {
            list.push(p.len() as u8);
            list.extend_from_slice(p);
        }
        let mut data = (list.len() as u16).to_be_bytes().to_vec();
        data.extend(list);
        Ext(0x0010, data)
    }

    pub fn versions(v: &[u16]) -> Ext {
        let mut data = vec![(v.len() * 2) as u8];
        for x in v {
            data.extend_from_slice(&x.to_be_bytes());
        }
        Ext(0x002b, data)
    }

    pub fn sig_algs(v: &[u16]) -> Ext {
        let mut data = ((v.len() * 2) as u16).to_be_bytes().to_vec();
        for x in v {
            data.extend_from_slice(&x.to_be_bytes());
        }
        Ext(0x000d, data)
    }

    pub fn client_hello(ciphers: &[u16], exts: &[Ext]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x11; 32]);
        body.push(32);
        body.extend_from_slice(&[0x22; 32]);
        body.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
        for c in ciphers {
            body.extend_from_slice(&c.to_be_bytes());
        }
        body.extend_from_slice(&[1, 0]);
        let mut ext_bytes = Vec::new();
        for Ext(ty, data) in exts {
            ext_bytes.extend_from_slice(&ty.to_be_bytes());
            ext_bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
            ext_bytes.extend_from_slice(data);
        }
        body.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
        body.extend(ext_bytes);

        let mut hs = vec![1];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend(body);
        hs
    }

    /// Wraps a handshake message in TLS records of at most `max` bytes each.
    pub fn records(hs: &[u8], max: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in hs.chunks(max) {
            out.extend_from_slice(&[22, 3, 1]);
            out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            out.extend_from_slice(chunk);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::build::*;
    use super::*;

    fn sample() -> Vec<u8> {
        client_hello(
            &[0x1301, 0x1302, 0xc02b],
            &[
                sni("shop.example"),
                alpn(&[b"h2", b"http/1.1"]),
                versions(&[0x0304, 0x0303]),
                sig_algs(&[0x0403, 0x0804]),
                Ext(0x0017, vec![]),
            ],
        )
    }

    #[test]
    fn parses_fields() {
        let h = parse(&records(&sample(), 16384)).unwrap();
        assert_eq!(h.legacy_version, 0x0303);
        assert_eq!(h.ciphers, vec![0x1301, 0x1302, 0xc02b]);
        assert_eq!(h.extensions, vec![0x0000, 0x0010, 0x002b, 0x000d, 0x0017]);
        assert!(h.has_sni);
        assert_eq!(h.alpn_first.as_deref(), Some(&b"h2"[..]));
        assert_eq!(h.supported_versions, vec![0x0304, 0x0303]);
        assert_eq!(h.signature_algorithms, vec![0x0403, 0x0804]);
    }

    #[test]
    fn reassembles_fragmented_records() {
        let hs = sample();
        let one = parse(&records(&hs, 16384)).unwrap();
        let split = records(&hs, 17);
        assert_eq!(parse(&split).unwrap(), one);
    }

    #[test]
    fn peek_asks_for_more_until_complete() {
        let bytes = records(&sample(), 40);
        let mut need = 0;
        let mut steps = 0;
        loop {
            match peek(&bytes[..need.min(bytes.len())]) {
                Peek::NeedMore(n) => {
                    assert!(n > need, "must make progress");
                    need = n;
                }
                Peek::Complete(n) => {
                    assert_eq!(n, bytes.len());
                    break;
                }
                Peek::NotTls => panic!("valid hello rejected"),
            }
            steps += 1;
            assert!(steps < 100);
        }
    }

    #[test]
    fn rejects_non_tls() {
        assert_eq!(peek(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"), Peek::NotTls);
        assert_eq!(
            peek(&[22, 3, 1, 0xff, 0xff]),
            Peek::NotTls,
            "over the size cap"
        );
        assert!(parse(b"\x16\x03\x01\x00\x04\x01\x00\x00\x00").is_none());
    }
}
