import net from 'node:net';
import { randomBytes } from 'node:crypto';
import readline from 'node:readline';

const command = process.argv[2];
if (!command) throw new Error('Provide a guest-only shell command.');
const interactive = command === '--interactive';
const marker = 'SB_DONE_' + randomBytes(8).toString('hex');
const socket = net.connect('\\\\.\\pipe\\swanbridge-build-20261025');
let output = '';
let greeting = false;
let sent = false;
let queue = Promise.resolve();
function sendLine(line) {
  queue = queue.then(async () => {
    for (const byte of Buffer.from(line + '\n')) {
      socket.write(Buffer.from([byte]));
      await new Promise(resolve => setTimeout(resolve, 20));
    }
  }).catch(error => socket.destroy(error));
}
if (interactive) {
  readline.createInterface({input: process.stdin, terminal: false}).on('line', line => {
    if (!sent) return console.error('Guest console is not ready.');
    sendLine(line);
  });
}
const deadline = setTimeout(() => {
  socket.destroy();
  console.error('Guest console deadline exceeded.');
  process.exitCode = 1;
}, 120000);
socket.on('connect', () => {
  setTimeout(() => { greeting = true; socket.write('\n'); }, 3000);
});
socket.on('data', data => {
  const text = data.toString('utf8');
  if (sent) process.stdout.write(text);
  output = (output + text).slice(-4000);
  if (!sent && greeting && /# $/.test(output)) {
    sent = true;
    if (interactive) {
      clearTimeout(deadline);
      console.log('Guest console ready. Commands are paced to avoid UART overruns.');
      return;
    }
    const line = command + `; printf '\\n${marker}:%s\\n' "$?"\n`;
    sendLine(line.trimEnd());
  }
  const result = output.match(new RegExp(`(?:^|[\\r\\n])${marker}:(\\d+)[\\r\\n]`));
  if (result) {
    clearTimeout(deadline);
    process.exitCode = Number(result[1]);
    socket.end();
  }
});
socket.on('error', error => {
  clearTimeout(deadline);
  console.error(error.message);
  process.exitCode = 1;
});
