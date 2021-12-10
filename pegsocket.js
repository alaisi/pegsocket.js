const utf8Encoder = new TextEncoder('utf-8');
const utf8Decoder = new TextDecoder('utf-8');

const buffer = (sizeHint, wrapped = null) => {
    let buf = wrapped ? wrapped : new ArrayBuffer(sizeHint);
    let view = new DataView(buf);
    let pos = 0, len = wrapped ? wrapped.byteLength : 0;

    const alloc = (n) => {
        if (len + n > buf.byteLength) {
            const old = buf;
            for (let size = old.byteLength * 2;; size *= 2) {
                if (size > len + n) {
                    buf = new ArrayBuffer(size);
                    view = new DataView(buf);
                    new Uint8Array(buf).set(new Uint8Array(old));
                    break;
                }
            }
        }
    }
    const writeUint8 = (i) => {
        alloc(1);
        view.setUint8(len++, i);
    }
    const writeUint16 = (i) => {
        alloc(2);
        view.setUint16(len, i);
        len += 2;
    }
    const writeUint32 = (i) => {
        alloc(4);
        view.setUint32(len, i);
        len += 4;
    }
    const writeInt32 = (i) => {
        alloc(4);
        view.setInt32(len, i);
        len += 4;
    }
    const writeString = (str) => {
        const bytes = utf8Encoder.encode(str);
        alloc(bytes.byteLength + 1);
        new Uint8Array(buf).set(bytes, len);
        len += bytes.byteLength;
        view.setUint8(len++, 0);
    }
    const writeBuf = (arrayBuffer) => {
        alloc(arrayBuffer.byteLength);
        new Uint8Array(buf).set(new Uint8Array(arrayBuffer), len);
        len += arrayBuffer.byteLength;
    }
    const readUint8 = () => {
        return view.getUint8(pos++);
    }
    const readUint16 = () => {
        const i = view.getUint16(pos);
        pos += 2;
        return i;
    }
    const readUint32 = () => {
        const i = view.getUint32(pos);
        pos += 4;
        return i;
    }
    const readInt32 = () => {
        const i = view.getInt32(pos);
        pos += 4;
        return i;
    }
    const readBuf = (n) => {
        const arrayBuffer = buf.slice(pos, pos += n);
        return arrayBuffer;
    }
    const readString = () => {
        for (let i = 0;; i++) {
            if (view.getUint8(pos + i) === 0) {
                const str = utf8Decoder.decode(new Uint8Array(buf, pos, i));
                pos += i + 1;
                return str;
            }         
        }
    }
    const available = () => {
        return len - pos;
    }
    const read = (n) => {
        pos += n;
    }
    const unread = (n) => {
        pos -= n;
    }
    const trim = () => {
        return len === buf.byteLength ? buf : buf.slice(0, len);
    }
    const toPacket = () => {
        const packet = trim();
        new DataView(packet).setUint32(1, packet.byteLength - 1);
        return packet;
    }
    const compact = () => {
        const remaining = buf.slice(pos, len);
        buf = new ArrayBuffer(Math.max(sizeHint, remaining.byteLength));
        view = new DataView(buf);
        len = pos = 0;
        writeBuf(remaining);
    }
    return { 
        writeUint8, writeUint16, writeUint32, writeInt32, writeString, writeBuf, compact,
        readUint8, readUint16, readUint32, readInt32, readString, readBuf, available, read, unread,
        trim, toPacket
    };
}

const protocol = (() => {
    const defragment = (onRecvMsg) => {
        const backlog = buffer(4096);
        return (arrayBuffer) => {
            backlog.writeBuf(arrayBuffer);
            while (backlog.available() >= 5) {
                const type = String.fromCharCode(backlog.readUint8());
                const size = backlog.readUint32() - 4;
                if (backlog.available() < size) {
                    backlog.unread(5);
                    break;
                }
                const data = backlog.readBuf(size);
                onRecvMsg({ type, data: buffer(0, data) });
            }
            backlog.compact();
        }
    }
    const writeStartup = (database, user) => {
        const msg = buffer(47 + database.length + user.length);
        msg.writeUint32(0);
        msg.writeUint32(196608);
        ['client_encoding', 'UTF-8', 'database', database, 'user', user, ''].forEach(msg.writeString);
        const packet = msg.trim();
        new DataView(packet).setUint32(0, packet.byteLength);
        return packet;
    }
    const writeQuery = (sql) => {
        const msg = buffer(sql.length + 6);
        msg.writeUint8('Q'.charCodeAt(0));
        msg.writeUint32(0);
        msg.writeString(sql);
        return msg.toPacket();
    }
    const writeParse = (sql, paramCount) => {
        const msg = buffer(sql.length + 9 + 4*paramCount);
        msg.writeUint8('P'.charCodeAt(0));
        msg.writeUint32(0);
        msg.writeUint8(0);
        msg.writeString(sql);
        msg.writeUint16(paramCount);
        for (let i = 0; i < paramCount; i++) {
            msg.writeUint32(0);
        }
        return msg.toPacket();
    }
    const writeBind = (params) => {
        const msg = buffer(64);
        msg.writeUint8('B'.charCodeAt(0));
        msg.writeUint32(0);
        msg.writeUint8(0);
        msg.writeUint8(0);
        msg.writeUint16(0);
        msg.writeUint16(params.length);
        params.forEach(p => {
            if (p === null || typeof(p) === 'undefined') {
                msg.writeInt32(-1);
            } else {
                const bytes = utf8Encoder.encode(p);
                msg.writeInt32(bytes.length);
                msg.writeBuf(bytes.buffer);
            }
        })
        msg.writeUint16(0);
        return msg.toPacket();
    }
    const writeDescribe = () => {
        const msg = buffer(7);
        msg.writeUint8('D'.charCodeAt(0));
        msg.writeUint32(0);
        msg.writeUint8('S'.charCodeAt(0));
        msg.writeUint8(0);
        return msg.toPacket();
    }
    const writeExecute = () => {
        const msg = buffer(10);
        msg.writeUint8('E'.charCodeAt(0));
        msg.writeUint32(0);
        msg.writeUint8(0);
        msg.writeUint32(0);
        return msg.toPacket();
    }
    const writeClose = () => {
        const msg = buffer(7);
        msg.writeUint8('C'.charCodeAt(0));
        msg.writeUint32(0);
        msg.writeUint8('S'.charCodeAt(0));
        msg.writeUint8(0);
        return msg.toPacket();
    }
    const writeSync = () => {
        const msg = buffer(5);
        msg.writeUint8('S'.charCodeAt(0));
        msg.writeUint32(0);
        return msg.toPacket();
    }
    const readAuthentication = (msg) => {
        return { id: 'Authentication', ok: msg.readUint32() === 0 };
    }
    const readRowDescription = (msg) => {
        const desc = { id: 'RowDescription', cols: msg.readUint16(), oids: [], names: [] };
        for (let i = 0; i < desc.cols; i++) {
            const name = msg.readString();
            msg.read(6);
            const oid = msg.readUint32();
            msg.read(8);
            desc.names.push(name);
            desc.oids.push(oid);
        }
        return desc;
    }
    const readDataRow = (msg) => {
        const values = [];
        const cols = msg.readUint16();
        for (let i = 0; i < cols; i++) {
            const len = msg.readInt32();
            values.push(len == -1 ? null : msg.readBuf(len));
        }
        return { id: 'DataRow', values };
    }
    const readCommandComplete = (msg) => {
        return { id: 'CommandComplete', tag: msg.readString() };
    }
    const readErrorResponse = (msg) => {
        const error = { id: 'ErrorResponse', err: {} };
        for (let field = msg.readUint8(); field !== 0; field = msg.readUint8()) {
            const value = msg.readString();
            switch (String.fromCharCode(field)) {
                case 'V': error.err.severity = value; break;
                case 'C': error.err.code = value; break;
                case 'M': error.err.message = value; break;
                case 'D': error.err.detail = value; break;
            }
        }
        return error;
    }
    const recv = (onRecvMsgs) => {
        let msgs = [];
        return defragment((response) => {
            switch (response.type) {
                case 'E': return msgs.push(readErrorResponse(response.data));
                case 'T': return msgs.push(readRowDescription(response.data));
                case 'D': return msgs.push(readDataRow(response.data));
                case 'C': return msgs.push(readCommandComplete(response.data));
                case 'Z': // ReadyForQuery
                    onRecvMsgs(msgs);
                    return msgs = [];
                case 'R': // Authentication(Ok|...)
                    const auth = readAuthentication(response.data);
                    return auth.ok ? msgs.push(auth) : onRecvMsgs([auth]);
            }
        });
    }
    return { recv, writeStartup, writeQuery, 
        writeParse, writeBind, writeDescribe, writeExecute, writeClose, writeSync };
})();

const client = (send, close) => {
    const decodeByOid = (arrayBuffer, oid) => {
        if (!arrayBuffer) {
            return null;
        }
        switch (oid) {
            case 16:   // BOOL
                return new Uint8Array(arrayBuffer)[0] === 't'.charCodeAt(0);
            case 20:   // INT8
            case 21:   // INT2
            case 23:   // INT4
                return BigInt(utf8Decoder.decode(new Uint8Array(arrayBuffer)));
            case 700:  // FLOAT4
            case 701:  // FLOAT8
                return parseFloat(utf8Decoder.decode(new Uint8Array(arrayBuffer)));
            default:
                return utf8Decoder.decode(new Uint8Array(arrayBuffer));
        }
    }
    const toRows = (result, msg) => {
        switch (msg.id) {
            case 'ErrorResponse':
                throw Object.assign(new Error(msg.err.message), { error: msg.err }); 
            case 'RowDescription':
                result.desc = msg;
                break;
            case 'DataRow':
                (result.rows = result.rows || []).push(
                    msg.values.reduce((row, ab, i) => {
                        row[result.desc.names[i]] = decodeByOid(ab, result.desc.oids[i]);
                        return row;
                    }, {})
                );
                break;
            case 'CommandComplete':
                result.updated = ['INSERT ', 'UPDATE ', 'DELETE ']
                    .filter(s => msg.tag.startsWith(s))
                    .map(_ => msg.tag.split(' '))
                    .map(s => parseInt(s[s.length - 1]))
                    .find(i => i > 0) || 0;
        }
        return result;
    }

    return {
        close,
        async query(sql, params = null) {
            const responses = await send(params && params.length > 0 
                ? [protocol.writeParse(sql, params.length),
                    protocol.writeBind(params),
                    protocol.writeDescribe(),
                    protocol.writeExecute(),
                    protocol.writeClose(),
                    protocol.writeSync()]
                : [protocol.writeQuery(sql)]);
            const { rows, updated } = responses.reduce(toRows, {});
            return { rows: rows || [], updated: updated || 0 };
        }
    }
}

export default ({ url, database, user }) => {
    return new Promise((resolve, reject) => {
        const socket = new WebSocket(url, ['binary']);
        socket.binaryType = 'arraybuffer';
        const callbacks = [];
        const recv = protocol.recv((msgs) => callbacks.shift(1)(msgs));
        const send = (requests) => new Promise((cb) => { 
            callbacks.push(cb);
            requests.forEach(req => socket.send(req));
        });
        socket.addEventListener('message', (e) => recv(e.data));
        socket.addEventListener('error', reject, { once: true });
        socket.addEventListener('open', async () => {
            const responses = await send([protocol.writeStartup(database, user)]);
            if (responses[0].id !== 'Authentication' || !responses[0].ok) {
                socket.close();
                return reject('Failed to authenticate with method=trust');
            }
            resolve(client(send, () => socket.close()));
        }, { once: true });
    });
}