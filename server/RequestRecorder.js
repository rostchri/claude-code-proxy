const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Logger = require('./Logger');

// RequestRecorder — optional request/response diagnostics.
//
// When the proxy runs in debug mode (log_level DEBUG or TRACE) AND a writable
// log directory is available, every incoming Messages request is written to
// its own timestamped JSON file together with the (re-assembled) upstream
// response. Purely additive: if the directory is missing or not writable,
// recording disables itself and the proxy behaves exactly as before.
//
// Sensitive request headers (authorization / x-api-key / cookie / ...) are
// redacted before writing — secrets are never persisted to disk. Request and
// response bodies are kept verbatim (that is the point of the diagnostics).
//
// File name: <ts>__<model>__<seq>.json  e.g.
//   2026-07-08T07-15-32-123Z__claude-sonnet-4-6__000042.json
// The name is lexicographically time-sortable; `__` is an unambiguous
// separator because <ts> and <model> are sanitised to never contain it.

const REDACTED = '<redacted>';
const SENSITIVE_HEADERS = new Set([
  'authorization',
  'x-api-key',
  'proxy-authorization',
  'cookie',
  'set-cookie',
]);

class RequestRecorder {
  static enabled = false;
  static dir = '/data/request-log';
  static maxFiles = 2000;
  static seq = 0;
  static writeCount = 0;

  static init(config) {
    this.dir = config && typeof config.request_log_dir === 'string' && config.request_log_dir.trim()
      ? config.request_log_dir.trim()
      : '/data/request-log';

    const cap = config ? parseInt(config.request_log_max_files, 10) : NaN;
    this.maxFiles = Number.isFinite(cap) && cap >= 0 ? cap : 2000;

    // Only record in debug mode (log_level DEBUG/TRACE).
    if (Logger.getLogLevel() < 3) {
      this.enabled = false;
      Logger.info('RequestRecorder: disabled (log_level below DEBUG)');
      return;
    }

    // Ensure the target directory exists and is writable, otherwise disable.
    try {
      fs.mkdirSync(this.dir, { recursive: true });
      fs.accessSync(this.dir, fs.constants.W_OK);
      this.enabled = true;
      Logger.info(`RequestRecorder: enabled -> ${this.dir} (max_files=${this.maxFiles || 'unlimited'})`);
      if (this.maxFiles > 0) {
        this.prune();
      }
    } catch (error) {
      this.enabled = false;
      Logger.warn(`RequestRecorder: disabled (cannot write ${this.dir}): ${error.message}`);
    }
  }

  // Start a recording for one incoming request. Returns an opaque handle that
  // must later be passed to finishResponse(), or null when recording is off.
  // The request body is deep-cloned so later in-place transformations by the
  // proxy do not mutate the captured "as received" snapshot.
  static begin({ method, path: reqPath, preset, clientIP, headers, body } = {}) {
    if (!this.enabled) {
      return null;
    }
    const now = new Date();
    const model = body && typeof body.model === 'string' ? body.model : 'unknown';
    let bodySnapshot = body ?? null;
    try {
      bodySnapshot = body != null ? structuredClone(body) : null;
    } catch (error) {
      Logger.debug(`RequestRecorder: body clone failed, storing reference: ${error.message}`);
    }
    return {
      id: this.buildId(now, model),
      startedAt: now.toISOString(),
      startMs: Date.now(),
      client: {
        ip: clientIP || null,
        method: method || null,
        path: reqPath || null,
        preset: preset || null,
      },
      request: {
        model,
        headers: this.redactHeaders(headers),
        body: bodySnapshot,
      },
      finished: false,
    };
  }

  // Wrap res.write/res.end to capture the full outgoing response body (streaming
  // or not), then record it once the response finishes. This keeps all recording
  // logic in the server layer — the upstream request handler stays untouched.
  static instrumentResponse(res, recording) {
    if (!recording) {
      return;
    }
    const MAX_BYTES = 8 * 1024 * 1024; // bound memory for very large responses
    // Accumulate raw Buffers and decode ONCE at the end. Decoding per-chunk
    // (chunk.toString('utf8')) corrupts any multi-byte UTF-8 sequence split
    // across a stream chunk boundary into U+FFFD, so the recorded response
    // would show mojibake even when the forwarded bytes were intact.
    const capturedChunks = [];
    let capturedBytes = 0;
    const append = (chunk) => {
      if (chunk == null || capturedBytes >= MAX_BYTES) {
        return;
      }
      let buf = null;
      if (Buffer.isBuffer(chunk)) {
        buf = chunk;
      } else if (typeof chunk === 'string') {
        buf = Buffer.from(chunk, 'utf8');
      }
      if (buf && buf.length) {
        capturedChunks.push(buf);
        capturedBytes += buf.length;
      }
    };

    const origWrite = res.write.bind(res);
    const origEnd = res.end.bind(res);
    res.write = (chunk, ...args) => {
      append(chunk);
      return origWrite(chunk, ...args);
    };
    res.end = (chunk, ...args) => {
      append(chunk);
      return origEnd(chunk, ...args);
    };

    const record = () => {
      const contentType = String(res.getHeader('content-type') || '');
      this.finishResponse(recording, {
        status: res.statusCode,
        streaming: contentType.includes('text/event-stream'),
        headers: res.getHeaders(),
        contentType,
        rawBody: Buffer.concat(capturedChunks).toString('utf8'),
      });
    };
    res.on('finish', record);
    res.on('close', record); // client aborted before finish → record partial
  }

  static buildId(date, model) {
    const ts = date.toISOString().replace(/:/g, '-').replace(/\./g, '-');
    const safeModel = String(model).replace(/[^A-Za-z0-9.-]+/g, '-').slice(0, 60) || 'unknown';
    this.seq = (this.seq + 1) % 1000000;
    const seq = String(this.seq).padStart(6, '0');
    return `${ts}__${safeModel}__${seq}`;
  }

  static redactHeaders(headers) {
    const out = {};
    if (!headers || typeof headers !== 'object') {
      return out;
    }
    for (const [key, value] of Object.entries(headers)) {
      out[key] = SENSITIVE_HEADERS.has(key.toLowerCase()) ? REDACTED : value;
    }
    return out;
  }

  // Complete a recording and write it to disk. Idempotent per handle.
  static finishResponse(recording, { status, streaming, headers, contentType, rawBody, error } = {}) {
    if (!recording || recording.finished) {
      return;
    }
    recording.finished = true;
    const record = {
      id: recording.id,
      recordedAt: recording.startedAt,
      completedAt: new Date().toISOString(),
      durationMs: Date.now() - recording.startMs,
      client: recording.client,
      request: recording.request,
      response: null,
    };
    if (error) {
      record.response = { status: status ?? null, error: String(error) };
    } else {
      record.response = this.buildResponse({ status, streaming, headers, contentType, rawBody });
    }
    this.write(recording.id, record);
  }

  static buildResponse({ status, streaming, headers, contentType, rawBody }) {
    const resp = {
      status: status ?? null,
      streaming: !!streaming,
      headers: this.redactHeaders(headers),
    };
    const raw = rawBody != null ? String(rawBody) : '';
    if (streaming && String(contentType || '').includes('text/event-stream')) {
      Object.assign(resp, this.reassembleSSE(raw));
    } else {
      try {
        const parsed = JSON.parse(raw);
        resp.model = parsed.model ?? null;
        resp.stopReason = parsed.stop_reason ?? null;
        resp.usage = parsed.usage ?? null;
        resp.content = parsed.content ?? null;
        if (parsed.type === 'error' || parsed.error) {
          resp.error = parsed.error ?? parsed;
        }
      } catch (e) {
        resp.rawBody = raw.slice(0, 20000);
      }
    }
    return resp;
  }

  // Re-assemble an Anthropic Messages SSE stream into a final message object
  // (content blocks + usage + stop_reason), mirroring the non-streaming shape.
  static reassembleSSE(raw) {
    const result = { model: null, stopReason: null, usage: null, content: [] };
    const blocks = new Map();
    const usage = {};
    for (const line of raw.split(/\r?\n/)) {
      if (!line.startsWith('data:')) {
        continue;
      }
      const payload = line.slice(5).trim();
      if (!payload || payload === '[DONE]') {
        continue;
      }
      let evt;
      try {
        evt = JSON.parse(payload);
      } catch (e) {
        continue;
      }
      switch (evt.type) {
        case 'message_start':
          if (evt.message) {
            result.model = evt.message.model ?? result.model;
            if (evt.message.usage) {
              Object.assign(usage, evt.message.usage);
            }
          }
          break;
        case 'content_block_start':
          if (typeof evt.index === 'number') {
            blocks.set(evt.index, this.cloneBlockStart(evt.content_block));
          }
          break;
        case 'content_block_delta':
          if (blocks.has(evt.index) && evt.delta) {
            this.applyBlockDelta(blocks.get(evt.index), evt.delta);
          }
          break;
        case 'content_block_stop':
          if (blocks.has(evt.index)) {
            this.finalizeBlock(blocks.get(evt.index));
          }
          break;
        case 'message_delta':
          if (evt.delta && evt.delta.stop_reason !== undefined) {
            result.stopReason = evt.delta.stop_reason;
          }
          if (evt.usage) {
            Object.assign(usage, evt.usage);
          }
          break;
        case 'error':
          result.error = evt.error ?? evt;
          break;
        default:
          break;
      }
    }
    result.content = [...blocks.keys()].sort((a, b) => a - b).map((k) => this.exportBlock(blocks.get(k)));
    if (Object.keys(usage).length) {
      result.usage = usage;
    }
    return result;
  }

  static cloneBlockStart(cb) {
    const block = cb || {};
    if (block.type === 'text') {
      return { type: 'text', text: block.text || '' };
    }
    if (block.type === 'thinking') {
      return { type: 'thinking', thinking: block.thinking || '', signature: block.signature || '' };
    }
    if (block.type === 'tool_use') {
      return { type: 'tool_use', id: block.id, name: block.name, input: block.input ?? {}, _partialJson: '' };
    }
    return { type: block.type || 'unknown', _raw: block };
  }

  static applyBlockDelta(block, delta) {
    if (delta.type === 'text_delta') {
      block.text = (block.text || '') + (delta.text || '');
    } else if (delta.type === 'thinking_delta') {
      block.thinking = (block.thinking || '') + (delta.thinking || '');
    } else if (delta.type === 'signature_delta') {
      block.signature = (block.signature || '') + (delta.signature || '');
    } else if (delta.type === 'input_json_delta') {
      block._partialJson = (block._partialJson || '') + (delta.partial_json || '');
    }
  }

  static finalizeBlock(block) {
    if (block.type === 'tool_use' && block._partialJson) {
      try {
        block.input = JSON.parse(block._partialJson);
      } catch (e) {
        // keep the partial JSON string as-is on parse failure
      }
    }
  }

  static exportBlock(block) {
    const out = { ...block };
    delete out._partialJson;
    delete out._raw;
    return out;
  }

  static write(id, record) {
    try {
      const finalPath = path.join(this.dir, `${id}.json`);
      const tmpPath = `${finalPath}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
      fs.writeFileSync(tmpPath, JSON.stringify(record, null, 2), { mode: 0o644 });
      fs.renameSync(tmpPath, finalPath);
      Logger.debug(`RequestRecorder: wrote ${id}.json`);
      this.writeCount += 1;
      if (this.maxFiles > 0 && this.writeCount % 100 === 0) {
        this.prune();
      }
    } catch (error) {
      Logger.warn(`RequestRecorder: write failed: ${error.message}`);
    }
  }

  static prune() {
    try {
      const files = fs.readdirSync(this.dir).filter((f) => f.endsWith('.json'));
      if (files.length <= this.maxFiles) {
        return;
      }
      files.sort();
      const remove = files.slice(0, files.length - this.maxFiles);
      for (const f of remove) {
        try {
          fs.unlinkSync(path.join(this.dir, f));
        } catch (e) {
          // ignore individual unlink failures
        }
      }
      Logger.debug(`RequestRecorder: pruned ${remove.length} old file(s)`);
    } catch (error) {
      Logger.warn(`RequestRecorder: prune failed: ${error.message}`);
    }
  }
}

module.exports = RequestRecorder;
