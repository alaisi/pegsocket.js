# pegsocket.js - WebSocket driver for PostgreSQL

For making SQL queries directly from the browser to a pg database. Because why not!

## Usage:
```js
import pegsocket from './pegsocket.js'

const pg = await pegsocket({ url: 'ws://example.com:15432', database: 'web', user: 'browser' });
const result = await pg.query("select 'Hello ' || $1 || '!' msg", ['world']);
=> {rows:[  {msg: "Hello world!"} ]," updated": 0 }
```

## PostgreSQL server configuration

 * Expose pg port as WebSocket endpoint with e.g., [websockify](https://github.com/novnc/websockify).
 * Configure trust authentication for a db user in ```pg_hba.conf```.
