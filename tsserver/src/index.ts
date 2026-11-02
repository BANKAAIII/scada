import net from 'net';

const PROXY_PORT = 5021; // FUXA connects here
const PLC_PORT = 5020;    // PLC Simulator listening port
const PLC_HOST = 'cd at'; // Or use 'plchardware' if running inside docker network container name resolution

const proxyServer = net.createServer((fuxaSocket) => {
    console.log('[PROXY] FUXA client connected to port 5021.');

    const plcSocket = net.connect(PLC_PORT, PLC_HOST, () => {
        console.log('[PROXY] Successfully connected to PLC Simulator on port 5020.');
    });

    // DIRECTION 1: FUXA ---> PROXY ---> PLC (Requests)
    fuxaSocket.on('data', (data: Buffer) => {
        console.log(`[PROXY RX FROM FUXA] Length: ${data.length} bytes`);
        
        if (data.length < 8) {
            console.log('[PROXY WARN] Packet too short, dropping.');
            return;
        }
        
        // Parse Header for DPI Inspection
        const transactionId = data.readUInt16BE(0);
        const protocolId = data.readUInt16BE(2);
        const unitId = data.readUInt8(6);
        const functionCode = data.readUInt8(7);
        
        // Exception Helper
        const sendException = (fc: number, code = 0x03) => {
            const excHeader = Buffer.alloc(9);
            excHeader.writeUInt16BE(transactionId, 0);
            excHeader.writeUInt16BE(protocolId, 2);
            excHeader.writeUInt16BE(3, 4);
            excHeader.writeUInt8(unitId, 6);
            excHeader.writeUInt8(fc | 0x80, 7);
            excHeader.writeUInt8(code, 8);
            fuxaSocket.write(excHeader);
        };

        // WRITE SINGLE REGISTER (FC 0x06) Security Inspection Check
        if (functionCode === 0x06 && data.length >= 12) {
            const startAddress = data.readUInt16BE(8);
            const valueToWrite = data.readUInt16BE(10);
            
            if (valueToWrite > 1000) {
                console.log(`[BLOCKED FC06] Malicious/High Value: ${valueToWrite} at Addr: ${startAddress}`);
                sendException(functionCode, 0x03);
                return; // Drop packet, do not forward to PLC
            }
            console.log(`[PASSTHROUGH FC06] Addr: ${startAddress} | Value: ${valueToWrite}`);
        }
        
        // WRITE MULTIPLE REGISTERS (FC 0x10) Security Inspection Check
        else if (functionCode === 0x10 && data.length >= 13) {
            const startAddress = data.readUInt16BE(8);
            const valueToWrite = data.readUInt16BE(13);
            
            if (valueToWrite > 1000) {
                console.log(`[BLOCKED FC10] Malicious/High Value: ${valueToWrite} at Addr: ${startAddress}`);
                sendException(functionCode, 0x03);
                return; // Drop packet, do not forward to PLC
            }
            console.log(`[PASSTHROUGH FC10] Addr: ${startAddress} | Value: ${valueToWrite}`);
        }

        // Forward raw request buffer directly to PLC simulator
        if (!plcSocket.destroyed) {
            plcSocket.write(data);
        }
    });

    // DIRECTION 2: PLC ---> PROXY ---> FUXA (Responses)
    plcSocket.on('data', (data: Buffer) => {
        if (!fuxaSocket.destroyed) {
            fuxaSocket.write(data);
        }
    });

    // Connection Teardown Handlers
    fuxaSocket.on('close', () => {
        console.log('[PROXY] FUXA client disconnected.');
        plcSocket.end();
    });
    
    plcSocket.on('close', () => {
        console.log('[PROXY] Disconnected from PLC simulator.');
        fuxaSocket.end();
    });

    fuxaSocket.on('error', (err) => console.error('[FUXA SOCKET ERROR]', err.message));
    plcSocket.on('error', (err) => console.error('[PLC SOCKET ERROR]', err.message));
});

proxyServer.listen(PROXY_PORT, () => {
    console.log(`[PROXY ACTIVE] Listening on Port ${PROXY_PORT} ===> Forwarding to PLC Port ${PLC_PORT}`);
});