import { reverse } from 'dns';
import net from 'net';

// PLC memory registers simulation
// 5 empty holding Registers.
const holdingRegisters =  Uint16Array.from([0, 0, 0, 0, 0]);

holdingRegisters[holdingRegisters.length - 1] = 0; // last register is reserved.

setInterval( ()=>{

    for (let i = 0 ; i < holdingRegisters.length-1; i++) {
        holdingRegisters[i] = Math.floor(Math.random() * 1000);
        console.log(`Register ${i} updated to ${holdingRegisters[i]}`);
    }   

   
} , 2000 );

// create a TCP server for plc .
const PORT = 5020 ; // Modbus TCP default port

const server =  net.createServer( (socket)=>{
    console.log(' tcp server created for PLC simulation.');

    socket.on( 'data' , ( data:Buffer )=>{
        console.log('Recieved a TCP datapacket from the client' , data.toString() );

        // parse the datapacket and respond accoringly.
        if( data.length < 12) return ;
        
        // parse the header.
        const transactionId = data.readUInt16BE(0);
        const protocolId = data.readUInt16BE(2);
        const length = data.readUInt16BE(4);
        const unitId = data.readUInt8(6);
        const functionCode = data.readUInt8(7);
        const dRegisterAddress = data.readUInt16BE(8);

        // now once we have headers there we will create the read and write response functions.

        // FC : 0x03 - read holding registers.
        if( functionCode === 0x03){
            const registerCount = data.readUInt16BE(10);    // number of registers to read.
            const byteCount = registerCount * 2;            // total number of bytes after the starting register address byte.
            const response = Buffer.alloc(byteCount);

            for ( let i = 0 ; i < registerCount ; i++ ){
                const regValue = holdingRegisters[dRegisterAddress + i] ?? 0;
                response.writeUInt16BE(regValue, i * 2);
            }
        
        // response header
        const responseHeader = Buffer.alloc(9);
        responseHeader.writeUInt16BE(transactionId, 0);     // transaction id
        responseHeader.writeUInt16BE(protocolId, 2);        // protocol id
        responseHeader.writeUInt16BE(byteCount + 3, 4);     // length of bytes from here.
        responseHeader.writeUInt8(unitId, 6);            // unit id for identification of plc.
        responseHeader.writeUInt8(functionCode, 7);      // function code for the response.
        responseHeader.writeUInt8(byteCount, 8);          // byte count of the response.

        // appenf the response to the header to create a full tcp datapacket.
        const fullResponse = Buffer.concat([responseHeader, response]);

        // send the response back to the client.
        socket.write(fullResponse);
    }  

    else if ( functionCode === 0x06){
        if(data.length  < 12 ) return;

        const recievedValue = data.readUInt16BE(10);
        
        if(dRegisterAddress < holdingRegisters.length){
            holdingRegisters[dRegisterAddress] = recievedValue;
            console.log(`[PLC WRITE SUCCESS] Offset ${dRegisterAddress} updated to ${recievedValue}`);

        }

        socket.write(data);

    }
    else if (functionCode === 0x10) {
            const registerCount = data.readUInt16BE(10);
            const valueToWrite = data.readUInt16BE(13); // Payload value starts at byte 13

           
            if (dRegisterAddress < holdingRegisters.length) {
                holdingRegisters[dRegisterAddress] = valueToWrite;
                console.log(`[PLC WRITE SUCCESS - FC10] Offset ${dRegisterAddress} updated to ${valueToWrite}`);
            }

            // FC 0x10 Response: Header (6 bytes) + UnitId + FC + StartAddr (2 bytes) + RegCount (2 bytes)
            const response = Buffer.alloc(12);
            response.writeUInt16BE(transactionId, 0);
            response.writeUInt16BE(protocolId, 2);
            response.writeUInt16BE(6, 4); // Remaining response length is 6 bytes
            response.writeUInt8(unitId, 6);
            response.writeUInt8(functionCode, 7);
            response.writeUInt16BE(dRegisterAddress, 8);
            response.writeUInt16BE(registerCount, 10);

            socket.write(response);
        }
 }) 

 socket.on('close', () => console.log('[PLC SIMULATOR] Client disconnected'));
 socket.on('error', (err) => console.error('[PLC ERROR]', err.message));


} )



server.listen(PORT, () => {
    console.log(`[PLC SIMULATOR] Running on TCP port ${PORT}`);
});