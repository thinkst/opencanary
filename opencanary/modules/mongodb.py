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

# ---------------------------------------------------------------------------
# Wire protocol opcodes
# ---------------------------------------------------------------------------
OPCODE_OP_REPLY  = 1
OPCODE_OP_INSERT = 2002
OPCODE_OP_UPDATE = 2001
OPCODE_OP_DELETE = 2006
OPCODE_OP_QUERY  = 2004
OPCODE_OP_MSG    = 2013

# ---------------------------------------------------------------------------
# Wire protocol / message framing
# ---------------------------------------------------------------------------
MSG_HEADER_SIZE          = 16   # 4 × int32 fields
MSG_HEADER_FORMAT        = '<iiii'
MSG_FLAG_BITS_FORMAT     = '<I'
MSG_FLAG_BITS_NONE       = 0
MSG_SECTION_KIND_BODY    = 0    # OP_MSG section kind 0: single document body
MSG_SECTION_KIND_BYTE    = b'\x00'
SYNTHETIC_REQUEST_ID     = 9999  # request_id used in outbound responses

# ---------------------------------------------------------------------------
# BSON element types
# ---------------------------------------------------------------------------
BSON_TYPE_DOUBLE   = 0x01
BSON_TYPE_STRING   = 0x02
BSON_TYPE_DOCUMENT = 0x03
BSON_TYPE_BINARY   = 0x05
BSON_TYPE_BOOLEAN  = 0x08
BSON_TYPE_INT32    = 0x10
BSON_TYPE_EOD      = 0x00   # End-of-document marker

BSON_BOOL_TRUE     = b'\x01'
BSON_BOOL_FALSE    = b'\x00'
BSON_MIN_DOC_SIZE  = 5       # 4-byte length + 1-byte EOD

# ---------------------------------------------------------------------------
# BSON string encoding
# ---------------------------------------------------------------------------
BSON_STRING_FORMAT = '<i'
BSON_DOC_LEN_FORMAT = '<i'
BSON_BIN_LEN_FORMAT = '<i'

# ---------------------------------------------------------------------------
# MongoDB server capability constants (advertised in isMaster response)
# ---------------------------------------------------------------------------
MONGO_MAX_BSON_OBJECT_SIZE        = 16_777_216
MONGO_MAX_MESSAGE_SIZE_BYTES      = 48_000_000
MONGO_MAX_WRITE_BATCH_SIZE        = 100_000
MONGO_LOGICAL_SESSION_TIMEOUT_MIN = 30
MONGO_CONNECTION_ID               = 1
MONGO_MIN_WIRE_VERSION            = 0
MONGO_MAX_WIRE_VERSION            = 8

# ---------------------------------------------------------------------------
# MongoDB error / result codes
# ---------------------------------------------------------------------------
MONGO_OK_TRUE  = 1.0
MONGO_OK_FALSE = 0.0

MONGO_ERR_AUTH_FAILED_CODE   = 18
MONGO_ERR_AUTH_FAILED_NAME   = 'AuthenticationFailed'
MONGO_ERR_AUTH_FAILED_MSG    = 'Authentication failed.'

MONGO_ERR_UNAUTHORIZED_CODE  = 13
MONGO_ERR_UNAUTHORIZED_NAME  = 'Unauthorized'
MONGO_ERR_AUTH_REQUIRED_MSG  = 'Authentication required'

# ---------------------------------------------------------------------------
# SASL / authentication
# ---------------------------------------------------------------------------
SASL_SCRAM_USERNAME_PATTERN = r'n=(.+?),'   # SCRAM client-first-message username field
AUTH_UNKNOWN_USER           = 'unknown'
AUTH_DEFAULT_MECHANISM      = 'SCRAM-SHA-1'

# ---------------------------------------------------------------------------
# Logging action strings
# ---------------------------------------------------------------------------
LOG_ACTION_CONNECTION   = 'mongodb.connection'
LOG_ACTION_AUTH_ATTEMPT = 'mongodb.auth_attempt'
LOG_ACTION_COMMAND      = 'mongodb.command'
LOG_ACTION_ERROR        = 'mongodb.error'
LOG_ACTION_DISCONNECT   = 'mongodb.disconnect'

LOG_TYPE_MONGODB = 20001   # OpenCanary logtype for MongoDB events

# ---------------------------------------------------------------------------
# Config keys and their defaults
# ---------------------------------------------------------------------------
CONFIG_KEY_PORT         = 'mongodb.port'
CONFIG_KEY_VERSION      = 'mongodb.version'
CONFIG_KEY_LISTEN_ADDR  = 'device.listen_addr'

CONFIG_DEFAULT_PORT         = 27017
CONFIG_DEFAULT_VERSION      = '4.4.6'
CONFIG_DEFAULT_LISTEN_ADDR  = ''

# ---------------------------------------------------------------------------
# Query collection / command names
# ---------------------------------------------------------------------------
CMD_COLLECTION_SUFFIX = '$cmd'
CMD_QUERY_PREFIX      = 'query:'


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
        while len(self.buffer) >= MSG_HEADER_SIZE:
            if len(self.buffer) < 4:
                break

            msg_length = struct.unpack('<i', self.buffer[0:4])[0]

            if len(self.buffer) < msg_length:
                break  # Wait for complete message

            message = self.buffer[:msg_length]
            self.buffer = self.buffer[msg_length:]

            try:
                self.process_message(message)
            except Exception as e:
                self.factory.log_error(self.transport, str(e))

    def process_message(self, message):
        """Process a complete MongoDB wire protocol message"""
        if len(message) < MSG_HEADER_SIZE:
            return

        msg_length, request_id, response_to, opcode = struct.unpack(
            MSG_HEADER_FORMAT, message[0:MSG_HEADER_SIZE]
        )
        payload = message[MSG_HEADER_SIZE:]

        if opcode == OPCODE_OP_QUERY:
            self.handle_op_query(request_id, payload)
        elif opcode == OPCODE_OP_MSG:
            self.handle_op_msg(request_id, payload)
        else:
            self.send_error_response(request_id, f"Unsupported opcode: {opcode}")

    def handle_op_query(self, request_id, payload):
        """Handle OP_QUERY messages (legacy MongoDB protocol)"""
        if len(payload) < 8:
            return

        flags = struct.unpack('<i', payload[0:4])[0]

        null_pos = payload.find(b'\x00', 4)
        if null_pos == -1:
            return

        collection_name = payload[4:null_pos].decode('utf-8', errors='ignore')

        query_start = null_pos + 1 + 8  # +1 for null, +8 for numberToSkip and numberToReturn
        if query_start < len(payload):
            try:
                query_doc = self.parse_bson(payload[query_start:])
                self.handle_query(request_id, collection_name, query_doc)
            except Exception:
                self.send_error_response(request_id, "Invalid BSON")

    def handle_op_msg(self, request_id, payload):
        """Handle OP_MSG messages (modern MongoDB protocol)"""
        if len(payload) < 5:
            return

        flag_bits = struct.unpack(MSG_FLAG_BITS_FORMAT, payload[0:4])[0]

        if len(payload) > 4 and payload[4] == MSG_SECTION_KIND_BODY:
            try:
                doc = self.parse_bson(payload[5:])

                if 'saslStart' in doc or 'authenticate' in doc:
                    self.handle_auth_attempt(request_id, doc)
                elif 'ismaster' in doc or 'isMaster' in doc or 'hello' in doc:
                    self.send_ismaster_response(request_id)
                else:
                    command = list(doc.keys())[0] if doc else 'unknown'
                    self.factory.log_command(self.transport, command, doc)
                    self.send_error_response(request_id, MONGO_ERR_AUTH_REQUIRED_MSG)
            except Exception:
                self.send_error_response(request_id, "Invalid BSON")

    def handle_query(self, request_id, collection, query):
        """Handle query operations and check for authentication"""
        self.factory.log_command(self.transport, f"{CMD_QUERY_PREFIX}{collection}", query)

        if CMD_COLLECTION_SUFFIX in collection and query:
            if 'authenticate' in query or 'saslStart' in query:
                self.handle_auth_attempt(request_id, query)
                return
            elif 'ismaster' in query or 'isMaster' in query:
                self.send_ismaster_response(request_id)
                return

        self.send_error_response(request_id, MONGO_ERR_AUTH_REQUIRED_MSG)

    def handle_auth_attempt(self, request_id, auth_doc):
        """Log authentication attempts and send response"""
        username  = auth_doc.get('user', auth_doc.get('username', AUTH_UNKNOWN_USER))
        mechanism = auth_doc.get('mechanism', AUTH_DEFAULT_MECHANISM)

        if username == AUTH_UNKNOWN_USER and 'payload' in auth_doc:
            payload = auth_doc['payload']
            if isinstance(payload, bytes):
                payload_str = payload.decode('utf-8', errors='ignore')
                match = re.search(SASL_SCRAM_USERNAME_PATTERN, payload_str)
                if match:
                    username = match.group(1)

        printable_doc = {
            k: (v.hex() if isinstance(v, bytes) else v)
            for k, v in auth_doc.items()
        }

        self.factory.log_auth_attempt(
            self.transport,
            username,
            mechanism,
            printable_doc,
        )

        self.send_auth_failure(request_id)

    def send_ismaster_response(self, request_id):
        """Send isMaster/hello response with MongoDB version info"""
        response_doc = {
            'ismaster':                     True,
            'maxBsonObjectSize':            MONGO_MAX_BSON_OBJECT_SIZE,
            'maxMessageSizeBytes':          MONGO_MAX_MESSAGE_SIZE_BYTES,
            'maxWriteBatchSize':            MONGO_MAX_WRITE_BATCH_SIZE,
            'localTime':                    datetime.utcnow().isoformat(),
            'logicalSessionTimeoutMinutes': MONGO_LOGICAL_SESSION_TIMEOUT_MIN,
            'connectionId':                 MONGO_CONNECTION_ID,
            'minWireVersion':               MONGO_MIN_WIRE_VERSION,
            'maxWireVersion':               MONGO_MAX_WIRE_VERSION,
            'readOnly':                     False,
            'ok':                           MONGO_OK_TRUE,
            'version':                      self.factory.mongo_version,
        }
        self.send_op_msg_response(request_id, response_doc)

    def send_auth_failure(self, request_id):
        """Send authentication failure response"""
        response_doc = {
            'ok':       MONGO_OK_FALSE,
            'errmsg':   MONGO_ERR_AUTH_FAILED_MSG,
            'code':     MONGO_ERR_AUTH_FAILED_CODE,
            'codeName': MONGO_ERR_AUTH_FAILED_NAME,
        }
        self.send_op_msg_response(request_id, response_doc)

    def send_error_response(self, request_id, error_msg):
        """Send generic error response"""
        response_doc = {
            'ok':       MONGO_OK_FALSE,
            'errmsg':   error_msg,
            'code':     MONGO_ERR_UNAUTHORIZED_CODE,
            'codeName': MONGO_ERR_UNAUTHORIZED_NAME,
        }
        self.send_op_msg_response(request_id, response_doc)

    def send_op_msg_response(self, request_id, doc):
        """Send OP_MSG response (opcode 2013)"""
        bson_doc = self.encode_bson(doc)

        flag_bits = struct.pack(MSG_FLAG_BITS_FORMAT, MSG_FLAG_BITS_NONE)
        payload   = flag_bits + MSG_SECTION_KIND_BYTE + bson_doc

        msg_length = MSG_HEADER_SIZE + len(payload)
        header = struct.pack(
            MSG_HEADER_FORMAT,
            msg_length,
            SYNTHETIC_REQUEST_ID,
            request_id,
            OPCODE_OP_MSG,
        )

        self.transport.write(header + payload)

    def parse_bson(self, data):
        """
        Minimal BSON parser for extracting key fields.
        Handles common cases for authentication.
        """
        if len(data) < BSON_MIN_DOC_SIZE:
            return {}

        doc_length = struct.unpack(BSON_DOC_LEN_FORMAT, data[0:4])[0]
        if len(data) < doc_length:
            return {}

        result = {}
        pos = 4

        while pos < len(data) - 1:
            element_type = data[pos]
            if element_type == BSON_TYPE_EOD:
                break

            pos += 1

            null_pos = data.find(b'\x00', pos)
            if null_pos == -1:
                break

            field_name = data[pos:null_pos].decode('utf-8', errors='ignore')
            pos = null_pos + 1

            if element_type == BSON_TYPE_STRING:
                if pos + 4 > len(data):
                    break
                str_length = struct.unpack(BSON_STRING_FORMAT, data[pos:pos+4])[0]
                pos += 4
                if pos + str_length > len(data):
                    break
                value = data[pos:pos+str_length-1].decode('utf-8', errors='ignore')
                pos += str_length
                result[field_name] = value

            elif element_type == BSON_TYPE_BINARY:
                if pos + 4 > len(data):
                    break
                bin_length = struct.unpack(BSON_BIN_LEN_FORMAT, data[pos:pos+4])[0]
                subtype = data[pos+4]
                pos += 5
                if pos + bin_length > len(data):
                    break
                value = data[pos:pos+bin_length]
                pos += bin_length
                result[field_name] = value

            elif element_type == BSON_TYPE_INT32:
                if pos + 4 > len(data):
                    break
                value = struct.unpack('<i', data[pos:pos+4])[0]
                pos += 4
                result[field_name] = value

            elif element_type == BSON_TYPE_BOOLEAN:
                if pos + 1 > len(data):
                    break
                value = data[pos] != BSON_TYPE_EOD
                pos += 1
                result[field_name] = value

            elif element_type == BSON_TYPE_DOCUMENT:
                if pos + 4 > len(data):
                    break
                subdoc_length = struct.unpack(BSON_DOC_LEN_FORMAT, data[pos:pos+4])[0]
                if pos + subdoc_length > len(data):
                    break
                pos += subdoc_length  # Simplified: skip sub-documents

            else:
                break  # Unknown type — stop parsing

        return result

    def encode_bson(self, doc):
        """
        Minimal BSON encoder for responses.
        Handles strings, numbers, and booleans.
        """
        body = b''

        for key, value in doc.items():
            key_bytes = key.encode('utf-8') + b'\x00'

            if isinstance(value, str):
                str_bytes = value.encode('utf-8') + b'\x00'
                body += (
                    bytes([BSON_TYPE_STRING])
                    + key_bytes
                    + struct.pack(BSON_STRING_FORMAT, len(str_bytes))
                    + str_bytes
                )
            elif isinstance(value, bool):
                body += (
                    bytes([BSON_TYPE_BOOLEAN])
                    + key_bytes
                    + (BSON_BOOL_TRUE if value else BSON_BOOL_FALSE)
                )
            elif isinstance(value, int):
                body += (
                    bytes([BSON_TYPE_INT32])
                    + key_bytes
                    + struct.pack('<i', value)
                )
            elif isinstance(value, float):
                body += (
                    bytes([BSON_TYPE_DOUBLE])
                    + key_bytes
                    + struct.pack('<d', value)
                )

        body += bytes([BSON_TYPE_EOD])

        doc_length = len(body) + 4
        return struct.pack(BSON_DOC_LEN_FORMAT, doc_length) + body

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
        self.port         = int(config.getVal(CONFIG_KEY_PORT,        default=CONFIG_DEFAULT_PORT))
        self.mongo_version = config.getVal(CONFIG_KEY_VERSION,        default=CONFIG_DEFAULT_VERSION)
        self.listen_addr   = config.getVal(CONFIG_KEY_LISTEN_ADDR,    default=CONFIG_DEFAULT_LISTEN_ADDR)
        self.logtype       = LOG_TYPE_MONGODB

    def buildProtocol(self, addr):
        """Factory method to build protocol instances"""
        return MongoDBProtocol(self)

    def log_connection(self, transport):
        """Log new connection"""
        self.log({'action': LOG_ACTION_CONNECTION}, transport=transport)

    def log_auth_attempt(self, transport, username, mechanism, auth_doc):
        """Log authentication attempt"""
        self.log(
            {
                'action':    LOG_ACTION_AUTH_ATTEMPT,
                'username':  username,
                'mechanism': mechanism,
                'auth_data': str(auth_doc),
            },
            transport=transport,
        )

    def log_command(self, transport, command, query):
        """Log MongoDB command"""
        self.log(
            {
                'action':  LOG_ACTION_COMMAND,
                'command': command,
                'query':   str(query),
            },
            transport=transport,
        )

    def log_error(self, transport, error):
        """Log protocol error"""
        self.log({'action': LOG_ACTION_ERROR, 'error': error}, transport=transport)

    def log_disconnect(self, transport):
        """Log disconnection"""
        self.log({'action': LOG_ACTION_DISCONNECT}, transport=transport)

    def getService(self):
        return internet.TCPServer(self.port, self, interface=self.listen_addr)


CanaryServiceFactory = CanaryMongoDB
