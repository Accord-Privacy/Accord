const http = require('http');
const net = require('net');
const fs = require('fs');
const path = require('path');
const distDir = path.join(__dirname, 'dist');
const mt = {'.html':'text/html','.js':'application/javascript','.css':'text/css','.png':'image/png','.svg':'image/svg+xml','.ico':'image/x-icon'};
const BACKEND = { host: '127.0.0.1', port: 8443 };

const server = http.createServer((req, res) => {
  const url = req.url.split('?')[0];
  if (url.startsWith('/register') || url.startsWith('/auth') || url.startsWith('/health') || url.startsWith('/nodes') || url.startsWith('/channels') || url.startsWith('/messages') || url.startsWith('/users') || url.startsWith('/dm') || url.startsWith('/invites') || url.startsWith('/files') || url.startsWith('/api/') || url.startsWith('/ws')) {
    const options = { hostname: BACKEND.host, port: BACKEND.port, path: req.url, method: req.method, headers: {...req.headers, host: BACKEND.host + ':' + BACKEND.port} };
    const proxy = http.request(options, (proxyRes) => { res.writeHead(proxyRes.statusCode, proxyRes.headers); proxyRes.pipe(res); });
    req.pipe(proxy);
    proxy.on('error', (e) => { console.error('proxy err', e.message); res.writeHead(502); res.end('Bad Gateway'); });
    return;
  }
  let f = url === '/' ? '/index.html' : url;
  const fp = path.join(distDir, f);
  if (fs.existsSync(fp)) { res.writeHead(200, {'Content-Type': mt[path.extname(f)] || 'application/octet-stream'}); fs.createReadStream(fp).pipe(res); }
  else { res.writeHead(200, {'Content-Type': 'text/html'}); fs.createReadStream(path.join(distDir, 'index.html')).pipe(res); }
});

// Raw TCP tunnel for WebSocket upgrades
server.on('upgrade', (req, clientSocket, head) => {
  console.log('WS upgrade:', req.url);
  const backendSocket = net.connect(BACKEND.port, BACKEND.host, () => {
    // Forward the original HTTP upgrade request
    let reqLine = `${req.method} ${req.url} HTTP/1.1\r\n`;
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      if (req.rawHeaders[i].toLowerCase() === 'host') {
        reqLine += `${req.rawHeaders[i]}: ${BACKEND.host}:${BACKEND.port}\r\n`;
      } else {
        reqLine += `${req.rawHeaders[i]}: ${req.rawHeaders[i+1]}\r\n`;
      }
    }
    reqLine += '\r\n';
    backendSocket.write(reqLine);
    if (head.length) backendSocket.write(head);
    // Bidirectional pipe
    backendSocket.pipe(clientSocket);
    clientSocket.pipe(backendSocket);
  });
  backendSocket.on('error', (e) => {
    console.error('WS backend error:', e.message);
    clientSocket.end();
  });
  clientSocket.on('error', (e) => {
    console.error('WS client error:', e.message);
    backendSocket.end();
  });
});

server.listen(3000, '0.0.0.0', () => console.log('Proxy+Static on :3000'));
