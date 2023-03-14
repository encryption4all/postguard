use rand::RngCore;

use wasm_bindgen::prelude::*;
use wasm_streams::readable::sys::ReadableStream as RawReadableStream;
use wasm_streams::writable::sys::WritableStream as RawWritableStream;

#[wasm_bindgen(module = "/tests/helpers.js")]
extern "C" {
    pub fn new_readable_stream_from_array(chunks: Box<[JsValue]>) -> RawReadableStream;
}

#[wasm_bindgen(module = "/tests/helpers.js")]
extern "C" {
    pub fn new_recording_writable_stream() -> WritableStreamAndEvents;

    #[derive(Clone, Debug)]
    pub type WritableStreamAndEvents;

    #[wasm_bindgen(method, getter)]
    pub fn stream(this: &WritableStreamAndEvents) -> RawWritableStream;

    #[wasm_bindgen(method, getter)]
    pub fn written(this: &WritableStreamAndEvents) -> Box<[JsValue]>;
}

pub struct RecordingWritableStream {
    raw: WritableStreamAndEvents,
}

impl RecordingWritableStream {
    pub fn new() -> Self {
        Self {
            raw: new_recording_writable_stream(),
        }
    }

    pub fn stream(&self) -> RawWritableStream {
        self.raw.stream()
    }

    pub fn written(&self) -> Vec<String> {
        self.raw
            .written()
            .into_iter()
            .map(|x| x.as_string().unwrap())
            .collect::<Vec<_>>()
    }
}

pub fn rand_vec(length: usize) -> Vec<u8> {
    let mut vec = vec![0u8; length];
    rand::thread_rng().fill_bytes(&mut vec);
    vec
}
