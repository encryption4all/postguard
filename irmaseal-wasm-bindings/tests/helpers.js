/* This file contains JS helper functions to create readable/writable streams
 * for testing purposes. Source:
 * https://github.com/MattiasBuelens/wasm-streams/tree/master/tests/js.
 */

export function new_readable_byte_stream_from_array(chunks) {
    return new ReadableStream({
        type: "bytes",
        start(controller) {
            this.controller = controller;
            for (let chunk of chunks) {
                controller.enqueue(chunk);
            }
            controller.close();
        },
        cancel() {
            const byobRequest = this.controller.byobRequest;
            if (byobRequest) {
                byobRequest.respond(0);
            }
        },
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
