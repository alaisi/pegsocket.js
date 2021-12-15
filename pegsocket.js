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
        return buf.slice(pos, pos += n);
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
        readUint8, readUint16, readUint32, readInt32, readString, readBuf, available, read,
        trim, toPacket
    };
}

const scram = (() => {
    const hmacSha256 = async (key, data) => {
        const ipad = new Uint8Array(64);
        const opad = new Uint8Array(64);
        for (let i = 0; i < 64; i++) {
            const b = i < key.byteLength ? key[i] : 0;
            ipad[i] = b ^ 0x36;
            opad[i] = b ^ 0x5c;
        }
        const firstPass = new Uint8Array(64 + data.byteLength);
        firstPass.set(ipad, 0);
        firstPass.set(data, 64);
        const secondPass = new Uint8Array(96);
        secondPass.set(opad, 0);
        secondPass.set(new Uint8Array(await crypto.subtle.digest('SHA-256', firstPass.buffer)), 64);
        return new Uint8Array(await crypto.subtle.digest('SHA-256', secondPass.buffer));
    }
    const pbkdf2HmacSha256 = async (password, salt, iterations) => {
        const one = new ArrayBuffer(4);
        new DataView(one).setInt32(0, 1);
        const initialSalt = new Uint8Array(salt.byteLength + 4);
        initialSalt.set(salt, 0);
        initialSalt.set(new Uint8Array(one), salt.byteLength);
        const key = await hmacSha256(password, initialSalt);
        for (let i = 1, prev = key; i < iterations; i++) {
            prev = await hmacSha256(password, prev);
            for (let j = 0; j < key.byteLength; j++) {
                key[j] ^= prev[j];
            }
        }
        return key;
    }
    const parse = (response) => {
        return response.split(',')
            .map(s => [ s[0], s.substring(2) ])
            .reduce((acc, ss) => { return { [ss[0]]: ss[1], ...acc }}, {});
    }
    const hashPassword = (password, serverFirst) => {
        const challenge = parse(serverFirst);
        const salt = Uint8Array.from(atob(challenge.s), c => c.charCodeAt(0));
        return pbkdf2HmacSha256(utf8Encoder.encode(password), salt, parseInt(challenge.i));
    }
    const writeClientFirst = async () => {
        const nonce = new Uint8Array(32);
        crypto.getRandomValues(nonce);
        return 'n,,n=*,r=' + btoa(String.fromCharCode(...nonce)).replaceAll('=', '');
    }
    const writeClientFinal = async (saltedPassword, clientFirst, serverFirst) => {
        const challenge = parse(serverFirst);
        const clientFirstBare = clientFirst.substring(3);
        if (challenge.r.indexOf(parse(clientFirstBare).r) !== 0) {
            throw new Error('Invalid server nonce');
        }
        const clientKey = await hmacSha256(saltedPassword, utf8Encoder.encode('Client Key'));
        const storedKey = await crypto.subtle.digest('SHA-256', clientKey.buffer);
        const clientFinalWithoutProof = 'c=biws,r=' + challenge.r;
        const authMessage = clientFirstBare + ',' + serverFirst + ',' + clientFinalWithoutProof;
        const clientSignature = await hmacSha256(new Uint8Array(storedKey), utf8Encoder.encode(authMessage));
        for (let i = 0; i < clientKey.byteLength; i++) {
            clientKey[i] ^= clientSignature[i];
        }
        return clientFinalWithoutProof + ',p=' + btoa(String.fromCharCode(...clientKey));
    }
    const verifySignature = (s1, s2) => {
        if (s1.byteLength !== s2.byteLength) {
            return false;
        }
        let result = 0;
        for(let i = 0; i < s1.byteLength; i++) {
            result |= s1[i] ^ s2[i];
        }
        return result === 0;
    }
    const authenticateServer = async (saltedPassword, clientFirst, serverFirst, clientFinal, serverFinal) => {
        const serverKey = await hmacSha256(saltedPassword, utf8Encoder.encode('Server Key'));
        const clientFinalWithoutProof = clientFinal.substring(0, clientFinal.indexOf(',p='));
        const authMessage = clientFirst.substring(3) + ',' + serverFirst + ',' + clientFinalWithoutProof;
        const serverSignature = await hmacSha256(serverKey, utf8Encoder.encode(authMessage));
        const verifier = Uint8Array.from(atob(parse(serverFinal).v), c => c.charCodeAt(0));
        if (!verifySignature(serverSignature, verifier)) {
            throw new Error('Server signature verification failed');
        }
    }
    return { writeClientFirst, hashPassword, writeClientFinal, authenticateServer };
})();

const protocol = (() => {
    const defragment = (onRecvMsg) => {
        const backlog = buffer(4096);
        return (arrayBuffer) => {
            backlog.writeBuf(arrayBuffer);
            while (backlog.available() >= 5) {
                const type = String.fromCharCode(backlog.readUint8());
                const size = backlog.readUint32() - 4;
                if (backlog.available() < size) {
                    backlog.read(-5);
                    break;
                }
                const data = backlog.readBuf(size);
                onRecvMsg({ type, data: buffer(0, data) });
            }
            backlog.compact();
        }
    }
    const writeStartup = async (database, user) => {
        const msg = buffer(47 + database.length + user.length);
        msg.writeUint32(0);
        msg.writeUint32(196608);
        ['client_encoding', 'UTF-8', 'database', database, 'user', user, ''].forEach(msg.writeString);
        const packet = msg.trim();
        new DataView(packet).setUint32(0, packet.byteLength);
        return packet;
    }
    const writeQuery = async (sql) => {
        const msg = buffer(sql.length + 6);
        msg.writeUint8('Q'.charCodeAt(0));
        msg.writeUint32(0);
        msg.writeString(sql);
        return msg.toPacket();
    }
    const writeParse = async (sql, paramCount) => {
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
    const writeBind = async (params) => {
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
    const writeDescribe = async () => {
        const msg = buffer(7);
        msg.writeUint8('D'.charCodeAt(0));
        msg.writeUint32(0);
        msg.writeUint8('S'.charCodeAt(0));
        msg.writeUint8(0);
        return msg.toPacket();
    }
    const writeExecute = async () => {
        const msg = buffer(10);
        msg.writeUint8('E'.charCodeAt(0));
        msg.writeUint32(0);
        msg.writeUint8(0);
        msg.writeUint32(0);
        return msg.toPacket();
    }
    const writeClose = async () => {
        const msg = buffer(7);
        msg.writeUint8('C'.charCodeAt(0));
        msg.writeUint32(0);
        msg.writeUint8('S'.charCodeAt(0));
        msg.writeUint8(0);
        return msg.toPacket();
    }
    const writeSync = async () => {
        const msg = buffer(5);
        msg.writeUint8('S'.charCodeAt(0));
        msg.writeUint32(0);
        return msg.toPacket();
    }
    const writeScramClientFirst = async (clientFirst) => {
        const msg = buffer(64);
        msg.writeUint8('p'.charCodeAt(0));
        msg.writeUint32(0);
        msg.writeString('SCRAM-SHA-256');
        const bytes = utf8Encoder.encode(clientFirst);
        msg.writeUint32(bytes.byteLength);
        msg.writeBuf(bytes.buffer);
        return msg.toPacket();
    }
    const writeScramClientFinal = async (clientFinal) => {
        const msg = buffer(64);
        msg.writeUint8('p'.charCodeAt(0));
        msg.writeUint32(0);
        msg.writeBuf(utf8Encoder.encode(clientFinal).buffer);
        return msg.toPacket();
    }
    const readAuthentication = (msg) => {
        const state = msg.readUint32();
        const auth = { id: 'Authentication', complete: state === 0 || state === 12, state };
        if (state === 10) {
            auth.mechanisms = [];
            while (msg.available() > 1) {
                auth.mechanisms.push(msg.readString());
            }
        } else if (state == 11) {
            auth.serverFirst = utf8Decoder.decode(new Uint8Array(msg.readBuf(msg.available())));
        } else if (state == 12) {
            auth.serverFinal = utf8Decoder.decode(new Uint8Array(msg.readBuf(msg.available())));
        }
        return auth;
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
        let authenticated = false;
        return defragment((response) => {
            switch (response.type) {
                case 'T': return msgs.push(readRowDescription(response.data));
                case 'D': return msgs.push(readDataRow(response.data));
                case 'C': return msgs.push(readCommandComplete(response.data));
                case 'E': // ErrorResponse
                    const error = readErrorResponse(response.data);
                    return authenticated ? msgs.push(error) : onRecvMsgs([error]);
                case 'R': // Authentication*
                    const auth = readAuthentication(response.data);
                    return auth.complete ? msgs.push(auth) : onRecvMsgs([auth]);
                case 'Z': // ReadyForQuery
                    const responses = msgs;
                    msgs = [];
                    authenticated = true;
                    return onRecvMsgs(responses);
            }
        });
    }
    return { recv, writeStartup, writeQuery, 
        writeParse, writeBind, writeDescribe, writeExecute, writeClose, writeSync,
        writeScramClientFirst, writeScramClientFinal };
})();

const authenticate = (() => {
    const toAuth = (responses) => responses.find(r => {
        if (r.id === 'ErrorResponse') {
            throw Object.assign(new Error(`${r.err.severity}: ${r.err.message}`), { error: r.err }); 
        }
        return r.id === 'Authentication';
    })
    return async (database, user, password, send) => {
        const auth = toAuth(await send([await protocol.writeStartup(database, user)]));
        if (auth.complete) {
            return;
        }
        if (auth.state !== 10 || auth.mechanisms.indexOf('SCRAM-SHA-256') < 0) {
            throw new Error('Unsupported auth method');
        }
        const clientFirst = await scram.writeClientFirst();
        const serverFirst = toAuth(await send([await protocol.writeScramClientFirst(clientFirst)])).serverFirst
        const saltedPassword = await scram.hashPassword(password, serverFirst);
        const clientFinal = await scram.writeClientFinal(saltedPassword, clientFirst, serverFirst)
        const serverFinal = toAuth(await send([await protocol.writeScramClientFinal(clientFinal)])).serverFinal;
        await scram.authenticateServer(saltedPassword, clientFirst, serverFirst, clientFinal, serverFinal);
    }
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
                throw Object.assign(new Error(`${msg.err.severity}: ${msg.err.message}`), { error: msg.err }); 
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
            const requests = await Promise.all(!params || params.length < 1
                ? [protocol.writeQuery(sql)]
                : [protocol.writeParse(sql, params.length),
                    protocol.writeBind(params),
                    protocol.writeDescribe(),
                    protocol.writeExecute(),
                    protocol.writeClose(),
                    protocol.writeSync()]);
            const responses = await send(requests);
            const { rows, updated } = responses.reduce(toRows, {});
            return { rows: rows || [], updated: updated || 0 };
        }
    }
}

export default ({ url, database, user, password }) => {
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
            try {
                await authenticate(database, user, password, send);
                return resolve(client(send, () => socket.close()));
            } catch (e) {
                socket.close();
                return reject(e);
            }
        }, { once: true });
    });
}