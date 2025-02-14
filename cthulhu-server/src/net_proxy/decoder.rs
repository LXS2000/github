
use async_compression::tokio::bufread::{BrotliDecoder, GzipDecoder, ZlibDecoder, ZstdDecoder};
use bstr::ByteSlice;
use futures::Stream;
use hyper::{
    body::{Body as HttpBody, Bytes},
    header::{HeaderMap, HeaderValue, CONTENT_ENCODING, CONTENT_LENGTH},
    Request, Response,
};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncBufRead, AsyncRead, BufReader};
use tokio_util::io::{ReaderStream, StreamReader};

use super::{body::Body, Error};

struct IoStream<T>(T);

impl<T: HttpBody<Data = Bytes, Error = Error> + Unpin> Stream for IoStream<T> {
    type Item = Result<Bytes, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        loop {
            return match futures::ready!(Pin::new(&mut self.0).poll_frame(cx)) {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(buf) => Poll::Ready(Some(Ok(buf))),
                    Err(_) => continue,
                },
                Some(Err(Error::Io(err))) => Poll::Ready(Some(Err(err))),
                Some(Err(err)) => Poll::Ready(Some(Err(io::Error::other(err)))),
                None => Poll::Ready(None),
            };
        }
    }
}

fn decode(
    encoding: &[u8],
    reader: impl AsyncBufRead + Send + Sync + Unpin + 'static,
) -> Result<Box<dyn AsyncRead + Send + Sync + Unpin>, Error> {
    Ok(match encoding {
        b"gzip" | b"x-gzip" => Box::new(GzipDecoder::new(reader)),
        b"deflate" => Box::new(ZlibDecoder::new(reader)),
        b"br" => Box::new(BrotliDecoder::new(reader)),
        b"zstd" => Box::new(ZstdDecoder::new(reader)),
        _ => Err(Error::Decode)?,
    })
}

enum Decoder<T> {
    Body(T),
    Decoder(Box<dyn AsyncRead + Send + Sync + Unpin>),
}

impl Decoder<Body> {
    pub fn decode(self, encoding: &[u8]) -> Result<Self, Error> {
        if encoding == b"identity" {
            return Ok(self);
        }

        Ok(Self::Decoder(match self {
            Self::Body(body) => decode(encoding, StreamReader::new(IoStream(body))),
            Self::Decoder(decoder) => decode(encoding, BufReader::new(decoder)),
        }?))
    }
}

impl From<Decoder<Body>> for Body {
    fn from(decoder: Decoder<Body>) -> Body {
        match decoder {
            Decoder::Body(body) => body,
            Decoder::Decoder(decoder) => Body::from_stream(ReaderStream::new(decoder)),
        }
    }
}

fn extract_encodings(headers: &HeaderMap<HeaderValue>) -> impl Iterator<Item = &[u8]> {
    headers
        .get_all(CONTENT_ENCODING)
        .iter()
        .rev()
        .flat_map(|val| val.as_bytes().rsplit_str(b",").map(|v| v.trim()))
}

fn decode_body<'a>(
    encodings: impl IntoIterator<Item = &'a [u8]>,
    body: Body,
) -> Result<Body, Error> {
    let mut decoder = Decoder::Body(body);

    for encoding in encodings {
        decoder = decoder.decode(encoding)?;
    }

    Ok(decoder.into())
}


pub fn decode_request(mut req: Request<Body>) -> Result<Request<Body>, Error> {
    if !req.headers().contains_key(CONTENT_ENCODING) {
        return Ok(req);
    }

    if let Some(val) = req.headers_mut().remove(CONTENT_LENGTH) {
        if val == "0" {
            return Ok(req);
        }
    }

    let (mut parts, body) = req.into_parts();

    let body = {
        let encodings = extract_encodings(&parts.headers);
        decode_body(encodings, body)?
    };

    parts.headers.remove(CONTENT_ENCODING);

    Ok(Request::from_parts(parts, body))
}


pub fn decode_response(mut res: Response<Body>) -> Result<Response<Body>, Error> {
    if !res.headers().contains_key(CONTENT_ENCODING) {
        return Ok(res);
    }

    if let Some(val) = res.headers_mut().remove(CONTENT_LENGTH) {
        if val == "0" {
            return Ok(res);
        }
    }

    let (mut parts, body) = res.into_parts();

    let body = {
        let encodings = extract_encodings(&parts.headers);
        decode_body(encodings, body)?
    };

    parts.headers.remove(CONTENT_ENCODING);

    Ok(Response::from_parts(parts, body))
}

