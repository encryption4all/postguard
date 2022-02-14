/* This file contains JS helper functions to create readable/writable streams
 * for testing purposes. Source:
 * https://github.com/MattiasBuelens/wasm-streams/tree/master/tests/js.
 */

export function new_readable_byte_stream_from_array(chunks) {
    return new ReadableStream({
        start(controller) {
            for (let chunk of chunks) {
                controller.enqueue(chunk);
            }
            controller.close();
        }
    });
}

export function new_recording_writable_stream() {
    const written = [];
    const stream = new WritableStream({
        write(chunk) {
            written.push(chunk);
        },
    });
    return { stream, written };
}
