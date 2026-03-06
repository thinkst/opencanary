"""
MongoDB Honeypot Module for OpenCanary

This module emulates a MongoDB instance to lure attackers into authentication traps.
It implements the MongoDB wire protocol to respond realistically to connection attempts.
"""

from opencanary.modules import CanaryService
from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor
from opencanary import logger
import struct
import json
import re
from datetime import datetime

class MongoDBProtocol(Protocol):
    """
    Implements MongoDB wire protocol to handle incoming connections.
    Supports OP_QUERY, OP_MSG (MongoDB 3.6+), and logs all authentication attempts.
    """
    
    def __init__(self, factory):
        self.factory = factory
        self.buffer = b''
        self.authenticated = False
        
    def connectionMade(self):
        """Log new connection attempts"""
        self.factory.log_connection(self.transport)
        
    def dataReceived(self, data):
        """
        Process incoming MongoDB wire protocol messages.
        Handles OP_QUERY (legacy) and OP_MSG (modern) opcodes.
        """
        self.buffer += data
        
        # MongoDB message format: length (4 bytes), requestID (4), responseTo (4), opCode (4), payload
        while len(self.buffer) >= 16:
            # Parse message header
            if len(self.buffer) < 4:
                break
                
            msg_length = struct.unpack('<i', self.buffer[0:4])[0]
            
            if len(self.buffer) < msg_length:
                break  # Wait for complete message
                
            # Extract full message
            message = self.buffer[:msg_length]
            self.buffer = self.buffer[msg_length:]
            
            try:
                self.process_message(message)
            except Exception as e:
                self.factory.log_error(self.transport, str(e))
                
    def process_message(self, message):
        """Process a complete MongoDB wire protocol message"""
        if len(message) < 16:
            return
            
        msg_length, request_id, response_to, opcode = struct.unpack('<iiii', message[0:16])
        payload = message[16:]
        
        # OP_QUERY (2004) - Legacy query operation
        if opcode == 2004:
            self.handle_op_query(request_id, payload)
            
        # OP_MSG (2013) - Modern message operation (MongoDB 3.6+)
        elif opcode == 2013:
            self.handle_op_msg(request_id, payload)
            
        # OP_REPLY (1) - Should not receive this from client
        # OP_INSERT (2002), OP_UPDATE (2001), OP_DELETE (2006) - Legacy operations
        else:
            # Send generic error response
            self.send_error_response(request_id, f"Unsupported opcode: {opcode}")
    
    def handle_op_query(self, request_id, payload):
        """Handle OP_QUERY messages (legacy MongoDB protocol)"""
        if len(payload) < 8:
            return
            
        flags = struct.unpack('<i', payload[0:4])[0]
        
        # Parse collection name (null-terminated string)
        null_pos = payload.find(b'\x00', 4)
        if null_pos == -1:
            return
            
        collection_name = payload[4:null_pos].decode('utf-8', errors='ignore')
        
        # Extract BSON query document
        query_start = null_pos + 1 + 8  # +1 for null, +8 for numberToSkip and numberToReturn
        if query_start < len(payload):
            try:
                query_doc = self.parse_bson(payload[query_start:])
                self.handle_query(request_id, collection_name, query_doc)
            except:
                self.send_error_response(request_id, "Invalid BSON")
    
    def handle_op_msg(self, request_id, payload):
        """Handle OP_MSG messages (modern MongoDB protocol)"""
        if len(payload) < 5:
            return
            
        flag_bits = struct.unpack('<I', payload[0:4])[0]
        
        # Section kind 0: Single document body
        if len(payload) > 4 and payload[4] == 0:
            try:
                doc = self.parse_bson(payload[5:])
                
                # Check if this is an authentication attempt
                if 'saslStart' in doc or 'authenticate' in doc:
                    self.handle_auth_attempt(request_id, doc)
                # Check for isMaster/hello command
                elif 'ismaster' in doc or 'isMaster' in doc or 'hello' in doc:
                    self.send_ismaster_response(request_id)
                # Other commands
                else:
                    command = list(doc.keys())[0] if doc else 'unknown'
                    self.factory.log_command(self.transport, command, doc)
                    self.send_error_response(request_id, "Authentication required")
            except:
                self.send_error_response(request_id, "Invalid BSON")
    
    def handle_query(self, request_id, collection, query):
        """Handle query operations and check for authentication"""
        self.factory.log_command(self.transport, f"query:{collection}", query)
        
        # Check for authentication queries
        if '$cmd' in collection and query:
            if 'authenticate' in query or 'saslStart' in query:
                self.handle_auth_attempt(request_id, query)
                return
            elif 'ismaster' in query or 'isMaster' in query:
                self.send_ismaster_response(request_id)
                return
                
        # Require authentication for other queries
        self.send_error_response(request_id, "Authentication required")
    
    def handle_auth_attempt(self, request_id, auth_doc):
        """Log authentication attempts and send response"""
        username = auth_doc.get('user', auth_doc.get('username', 'unknown'))
        mechanism = auth_doc.get('mechanism', 'SCRAM-SHA-1')

        # If username is unknown, try to extract it from the SASL binary payload
        if username == 'unknown' and 'payload' in auth_doc:
            payload = auth_doc['payload']
            if isinstance(payload, bytes):
                payload_str = payload.decode('utf-8', errors='ignore')
                # SCRAM-SHA-1/256 client first message: n,,n=user,r=nonce
                match = re.search(r'n=(.+?),', payload_str)
                if match:
                    username = match.group(1)
        
        # Log the authentication attempt
        # Convert bytes to string for JSON logging
        printable_doc = {k: (v.hex() if isinstance(v, bytes) else v) for k, v in auth_doc.items()}
        
        self.factory.log_auth_attempt(
            self.transport,
            username,
            mechanism,
            printable_doc
        )
        
        # Send authentication failure response
        self.send_auth_failure(request_id)
    
    def send_ismaster_response(self, request_id):
        """Send isMaster/hello response with MongoDB version info"""
        response_doc = {
            'ismaster': True,
            'maxBsonObjectSize': 16777216,
            'maxMessageSizeBytes': 48000000,
            'maxWriteBatchSize': 100000,
            'localTime': datetime.utcnow().isoformat(),
            'logicalSessionTimeoutMinutes': 30,
            'connectionId': 1,
            'minWireVersion': 0,
            'maxWireVersion': 8,
            'readOnly': False,
            'ok': 1.0,
            'version': self.factory.mongo_version
        }
        
        self.send_op_msg_response(request_id, response_doc)
    
    def send_auth_failure(self, request_id):
        """Send authentication failure response"""
        response_doc = {
            'ok': 0.0,
            'errmsg': 'Authentication failed.',
            'code': 18,
            'codeName': 'AuthenticationFailed'
        }
        
        self.send_op_msg_response(request_id, response_doc)
    
    def send_error_response(self, request_id, error_msg):
        """Send generic error response"""
        response_doc = {
            'ok': 0.0,
            'errmsg': error_msg,
            'code': 13,
            'codeName': 'Unauthorized'
        }
        
        self.send_op_msg_response(request_id, response_doc)
    
    def send_op_msg_response(self, request_id, doc):
        """Send OP_MSG response (opcode 2013)"""
        bson_doc = self.encode_bson(doc)
        
        # OP_MSG format: flagBits (4 bytes) + kind (1 byte) + document
        flag_bits = struct.pack('<I', 0)  # No flags
        kind = b'\x00'  # Kind 0: Body
        payload = flag_bits + kind + bson_doc
        
        # Message header: length, requestID, responseTo, opCode
        msg_length = 16 + len(payload)
        response_to = request_id
        opcode = 2013  # OP_MSG
        
        header = struct.pack('<iiii', msg_length, 9999, response_to, opcode)
        
        self.transport.write(header + payload)
    
    def parse_bson(self, data):
        """
        Minimal BSON parser for extracting key fields.
        This is simplified and handles common cases for authentication.
        """
        if len(data) < 5:
            return {}
            
        doc_length = struct.unpack('<i', data[0:4])[0]
        if len(data) < doc_length:
            return {}
            
        result = {}
        pos = 4
        
        while pos < len(data) - 1:
            element_type = data[pos]
            if element_type == 0:  # End of document
                break
                
            pos += 1
            
            # Extract field name (null-terminated)
            null_pos = data.find(b'\x00', pos)
            if null_pos == -1:
                break
                
            field_name = data[pos:null_pos].decode('utf-8', errors='ignore')
            pos = null_pos + 1
            
            # Extract value based on type
            if element_type == 0x02:  # String
                if pos + 4 > len(data):
                    break
                str_length = struct.unpack('<i', data[pos:pos+4])[0]
                pos += 4
                if pos + str_length > len(data):
                    break
                value = data[pos:pos+str_length-1].decode('utf-8', errors='ignore')
                pos += str_length
                result[field_name] = value
            elif element_type == 0x05:  # Binary data
                if pos + 4 > len(data):
                    break
                bin_length = struct.unpack('<i', data[pos:pos+4])[0]
                subtype = data[pos+4]
                pos += 5
                if pos + bin_length > len(data):
                    break
                value = data[pos:pos+bin_length]
                pos += bin_length
                result[field_name] = value
            elif element_type == 0x10:  # Int32
                if pos + 4 > len(data):
                    break
                value = struct.unpack('<i', data[pos:pos+4])[0]
                pos += 4
                result[field_name] = value
            elif element_type == 0x08:  # Boolean
                if pos + 1 > len(data):
                    break
                value = data[pos] != 0
                pos += 1
                result[field_name] = value
            elif element_type == 0x03:  # Embedded document
                if pos + 4 > len(data):
                    break
                subdoc_length = struct.unpack('<i', data[pos:pos+4])[0]
                if pos + subdoc_length > len(data):
                    break
                # Recursively parse (simplified - just skip for now)
                pos += subdoc_length
            else:
                # Skip unknown types
                break
                
        return result
    
    def encode_bson(self, doc):
        """
        Minimal BSON encoder for responses.
        Handles strings, numbers, and booleans.
        """
        body = b''
        
        for key, value in doc.items():
            if isinstance(value, str):
                # String type (0x02)
                body += b'\x02' + key.encode('utf-8') + b'\x00'
                str_bytes = value.encode('utf-8') + b'\x00'
                body += struct.pack('<i', len(str_bytes)) + str_bytes
            elif isinstance(value, bool):
                # Boolean type (0x08)
                body += b'\x08' + key.encode('utf-8') + b'\x00'
                body += b'\x01' if value else b'\x00'
            elif isinstance(value, int):
                # Int32 type (0x10)
                body += b'\x10' + key.encode('utf-8') + b'\x00'
                body += struct.pack('<i', value)
            elif isinstance(value, float):
                # Double type (0x01)
                body += b'\x01' + key.encode('utf-8') + b'\x00'
                body += struct.pack('<d', value)
        
        body += b'\x00'  # End of document
        
        # Prepend document length
        doc_length = len(body) + 4
        return struct.pack('<i', doc_length) + body
    
    def connectionLost(self, reason):
        """Log connection closure"""
        self.factory.log_disconnect(self.transport)


class CanaryMongoDB(Factory, CanaryService):
    """
    MongoDB Honeypot Service for OpenCanary
    
    Emulates a MongoDB instance on the configured port (default 27017).
    Logs all connection attempts, commands, and authentication attempts.
    """
    
    NAME = 'mongodb'
    
    def __init__(self, config=None, logger=None):
        CanaryService.__init__(self, config=config, logger=logger)
        self.port = int(config.getVal('mongodb.port', default=27017))
        self.mongo_version = config.getVal('mongodb.version', default='4.4.6')
        self.listen_addr = config.getVal('device.listen_addr', default='')
        self.logtype = 20001  # LOG_MONGODB
    
    def buildProtocol(self, addr):
        """Factory method to build protocol instances"""
        return MongoDBProtocol(self)
    
    def log_connection(self, transport):
        """Log new connection"""
        logdata = {'action': 'mongodb.connection'}
        self.log(logdata, transport=transport)
    
    def log_auth_attempt(self, transport, username, mechanism, auth_doc):
        """Log authentication attempt"""
        logdata = {
            'action': 'mongodb.auth_attempt',
            'username': username,
            'mechanism': mechanism,
            'auth_data': str(auth_doc)
        }
        self.log(logdata, transport=transport)
    
    def log_command(self, transport, command, query):
        """Log MongoDB command"""
        logdata = {
            'action': 'mongodb.command',
            'command': command,
            'query': str(query)
        }
        self.log(logdata, transport=transport)
    
    def log_error(self, transport, error):
        """Log protocol error"""
        logdata = {
            'action': 'mongodb.error',
            'error': error
        }
        self.log(logdata, transport=transport)
    
    def log_disconnect(self, transport):
        """Log disconnection"""
        logdata = {'action': 'mongodb.disconnect'}
        self.log(logdata, transport=transport)


CanaryServiceFactory = CanaryMongoDB
