import net from 'net';
const PROXY_PORT = 5021; // FUXA connects here
const PLC_PORT = 5020; // PLC Simulator listening port
const PLC_HOST = '172.20.10.6';
const proxyServer = net.createServer((fuxaSocket) => {
    console.log('[PROXY] FUXA connected.');
    const plcSocket = net.connect(PLC_PORT, PLC_HOST, () => {
        console.log('[PROXY] Connected to PLC Simulator.');
    });
    // DIRECTION 1: FUXA ---> PROXY ---> PLC (Requests)
    fuxaSocket.on('data', (data) => {
        if (data.length < 12)
            return;
        // Parse Header
        const transactionId = data.readUInt16BE(0);
        const protocolId = data.readUInt16BE(2);
        const unitId = data.readUInt8(6);
        const functionCode = data.readUInt8(7);
        const startAddress = data.readUInt16BE(8);
        // Exception Helper
        const sendException = (fc, code = 0x03) => {
            const excHeader = Buffer.alloc(9);
            excHeader.writeUInt16BE(transactionId, 0);
            excHeader.writeUInt16BE(protocolId, 2);
            excHeader.writeUInt16BE(3, 4); // 3 bytes follow (UnitId, FC+0x80, ExceptionCode)
            excHeader.writeUInt8(unitId, 6);
            excHeader.writeUInt8(fc | 0x80, 7); // Exception Flag: 0x86 or 0x90
            excHeader.writeUInt8(code, 8); // 0x03 = ILLEGAL_DATA_VALUE
            fuxaSocket.write(excHeader);
        };
        // 1. READ REQUEST (FC 0x03)
        if (functionCode === 0x03) {
            const quantity = data.readUInt16BE(10);
            console.log(`[REQ READ] Start Addr: ${startAddress} | Quantity: ${quantity}`);
        }
        // 2. WRITE SINGLE REGISTER (FC 0x06)
        else if (functionCode === 0x06) {
            const valueToWrite = data.readUInt16BE(10); // Value is at byte 10 for FC 0x06
            if (valueToWrite > 1000) {
                console.log(`[BLOCKED FC06] Value: ${valueToWrite} at Addr: ${startAddress}`);
                sendException(functionCode, 0x03);
                return; // Drop packet, don't write to PLC
            }
            console.log(`[REQ WRITE FC06] Addr: ${startAddress} | Value: ${valueToWrite}`);
        }
        // 3. WRITE MULTIPLE REGISTERS (FC 0x10)
        else if (functionCode === 0x10) {
            const valueToWrite = data.readUInt16BE(13); // Payload value starts at byte 13 for FC 0x10
            if (valueToWrite > 1000) {
                console.log(`[BLOCKED FC10] Value: ${valueToWrite} at Addr: ${startAddress}`);
                sendException(functionCode, 0x03);
                return; // Drop packet, don't write to PLC
            }
            console.log(`[REQ WRITE FC10] Addr: ${startAddress} | Value: ${valueToWrite}`);
        }
        // Forward valid raw request buffer directly to PLC
        plcSocket.write(data);
    });
    // DIRECTION 2: PLC ---> PROXY ---> FUXA (Responses)
    plcSocket.on('data', (data) => {
        fuxaSocket.write(data);
    });
    // Connection Teardown
    fuxaSocket.on('close', () => plcSocket.end());
    plcSocket.on('close', () => fuxaSocket.end());
    fuxaSocket.on('error', (err) => console.error('[FUXA ERROR]', err.message));
    plcSocket.on('error', (err) => console.error('[PLC ERROR]', err.message));
});
proxyServer.listen(PROXY_PORT, () => {
    console.log(`[PROXY ACTIVE] Listening on Port ${PROXY_PORT} ===> Forwarding to PLC Port ${PLC_PORT}`);
});
//# sourceMappingURL=index.js.map