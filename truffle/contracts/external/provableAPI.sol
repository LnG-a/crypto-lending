// SPDX-License-Identifier: MIT

// <provableAPI>
// Release targetted at solc 0.4.25 to silence compiler warning/error messages, compatible down to 0.4.22

/*
Copyright (c) 2015-2016 Oraclize SRL
Copyright (c) 2016-2019 Oraclize LTD
Copyright (c) 2019 Provable Things Limited



Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:



The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.



THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

pragma solidity >= 0.5.0 < 0.9.0;// Incompatible compiler version... please select one stated within pragma solidity or use different provableAPI version

abstract contract ProvableI {
    address public cbAddress;
    function query(uint _timestamp, string memory _datasource, string memory _arg) external payable returns (bytes32 _id);
    function query_withGasLimit(uint _timestamp, string memory  _datasource, string memory  _arg, uint _gaslimit) external payable returns (bytes32 _id);
    function query2(uint _timestamp, string memory  _datasource, string memory  _arg1, string  memory _arg2) public payable returns (bytes32 _id);
    function query2_withGasLimit(uint _timestamp, string memory  _datasource, string  memory _arg1, string memory  _arg2, uint _gaslimit) external payable returns (bytes32 _id);
    function queryN(uint _timestamp, string memory  _datasource, bytes memory _argN) public payable returns (bytes32 _id);
    function queryN_withGasLimit(uint _timestamp, string memory  _datasource, bytes memory _argN, uint _gaslimit) external payable returns (bytes32 _id);
    function getPrice(string memory  _datasource) public returns (uint _dsprice);
    function getPrice(string memory  _datasource, uint gaslimit) public returns (uint _dsprice);
    function setProofType(bytes1 _proofType) external;
    function setCustomGasPrice(uint _gasPrice) external;
    function randomDS_getSessionPubKeyHash() external view returns(bytes32);
}

abstract contract OracleAddrResolverI {
    function getAddress() public returns (address _addr);
}

/*
Begin solidity-cborutils

https://github.com/smartcontractkit/solidity-cborutils

MIT License

Copyright (c) 2018 SmartContract ChainLink, Ltd.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */

library Buffer {
    /**
    * @dev Represents a mutable buffer. Buffers have a current value (buf) and
    *      a capacity. The capacity may be longer than the current value, in
    *      which case it can be extended without the need to allocate more memory.
    */
    struct buffer {
        bytes buf;
        uint capacity;
    }

    /**
    * @dev Initializes a buffer with an initial capacity.
    * @param buf The buffer to initialize.
    * @param capacity The number of bytes of space to allocate the buffer.
    * @return The buffer, for chaining.
    */
    function init(buffer memory buf, uint capacity) internal pure returns(buffer memory) {
        if (capacity % 32 != 0) {
            capacity += 32 - (capacity % 32);
        }
        // Allocate space for the buffer data
        buf.capacity = capacity;
        assembly {
            let ptr := mload(0x40)
            mstore(buf, ptr)
            mstore(ptr, 0)
            let fpm := add(32, add(ptr, capacity))
            if lt(fpm, ptr) {
                revert(0, 0)
            }
            mstore(0x40, fpm)
        }
        return buf;
    }

    /**
    * @dev Initializes a new buffer from an existing bytes object.
    *      Changes to the buffer may mutate the original value.
    * @param b The bytes object to initialize the buffer with.
    * @return A new buffer.
    */
    function fromBytes(bytes memory b) internal pure returns(buffer memory) {
        buffer memory buf;
        buf.buf = b;
        buf.capacity = b.length;
        return buf;
    }

    function resize(buffer memory buf, uint capacity) private pure {
        bytes memory oldbuf = buf.buf;
        init(buf, capacity);
        append(buf, oldbuf);
    }

    /**
    * @dev Sets buffer length to 0.
    * @param buf The buffer to truncate.
    * @return The original buffer, for chaining..
    */
    function truncate(buffer memory buf) internal pure returns (buffer memory) {
        assembly {
            let bufptr := mload(buf)
            mstore(bufptr, 0)
        }
        return buf;
    }

    /**
    * @dev Appends len bytes of a byte string to a buffer. Resizes if doing so would exceed
    *      the capacity of the buffer.
    * @param buf The buffer to append to.
    * @param data The data to append.
    * @param len The number of bytes to copy.
    * @return The original buffer, for chaining.
    */
    function append(buffer memory buf, bytes memory data, uint len) internal pure returns(buffer memory) {
        require(len <= data.length);

        uint off = buf.buf.length;
        uint newCapacity = off + len;
        if (newCapacity > buf.capacity) {
            resize(buf, newCapacity * 2);
        }

        uint dest;
        uint src;
        assembly {
            // Memory address of the buffer data
            let bufptr := mload(buf)
            // Length of existing buffer data
            let buflen := mload(bufptr)
            // Start address = buffer address + offset + sizeof(buffer length)
            dest := add(add(bufptr, 32), off)
            // Update buffer length if we're extending it
            if gt(newCapacity, buflen) {
                mstore(bufptr, newCapacity)
            }
            src := add(data, 32)
        }

        // Copy word-length chunks while possible
        for (; len >= 32; len -= 32) {
            assembly {
                mstore(dest, mload(src))
            }
            dest += 32;
            src += 32;
        }

        // Copy remaining bytes
        unchecked {
            uint mask = (256 ** (32 - len)) - 1;
            assembly {
                let srcpart := and(mload(src), not(mask))
                let destpart := and(mload(dest), mask)
                mstore(dest, or(destpart, srcpart))
            }
        }

        return buf;
    }

    /**
    * @dev Appends a byte string to a buffer. Resizes if doing so would exceed
    *      the capacity of the buffer.
    * @param buf The buffer to append to.
    * @param data The data to append.
    * @return The original buffer, for chaining.
    */
    function append(buffer memory buf, bytes memory data) internal pure returns (buffer memory) {
        return append(buf, data, data.length);
    }

    /**
    * @dev Appends a byte to the buffer. Resizes if doing so would exceed the
    *      capacity of the buffer.
    * @param buf The buffer to append to.
    * @param data The data to append.
    * @return The original buffer, for chaining.
    */
    function appendUint8(buffer memory buf, uint8 data) internal pure returns(buffer memory) {
        uint off = buf.buf.length;
        uint offPlusOne = off + 1;
        if (off >= buf.capacity) {
            resize(buf, offPlusOne * 2);
        }

        assembly {
            // Memory address of the buffer data
            let bufptr := mload(buf)
            // Address = buffer address + sizeof(buffer length) + off
            let dest := add(add(bufptr, off), 32)
            mstore8(dest, data)
            // Update buffer length if we extended it
            if gt(offPlusOne, mload(bufptr)) {
                mstore(bufptr, offPlusOne)
            }
        }

        return buf;
    }

    /**
    * @dev Appends len bytes of bytes32 to a buffer. Resizes if doing so would
    *      exceed the capacity of the buffer.
    * @param buf The buffer to append to.
    * @param data The data to append.
    * @param len The number of bytes to write (left-aligned).
    * @return The original buffer, for chaining.
    */
    function append(buffer memory buf, bytes32 data, uint len) private pure returns(buffer memory) {
        uint off = buf.buf.length;
        uint newCapacity = len + off;
        if (newCapacity > buf.capacity) {
            resize(buf, newCapacity * 2);
        }

        unchecked {
            uint mask = (256 ** len) - 1;
            // Right-align data
            data = data >> (8 * (32 - len));
            assembly {
                // Memory address of the buffer data
                let bufptr := mload(buf)
                // Address = buffer address + sizeof(buffer length) + newCapacity
                let dest := add(bufptr, newCapacity)
                mstore(dest, or(and(mload(dest), not(mask)), data))
                // Update buffer length if we extended it
                if gt(newCapacity, mload(bufptr)) {
                    mstore(bufptr, newCapacity)
                }
            }
        }
        return buf;
    }

    /**
    * @dev Appends a bytes20 to the buffer. Resizes if doing so would exceed
    *      the capacity of the buffer.
    * @param buf The buffer to append to.
    * @param data The data to append.
    * @return The original buffer, for chhaining.
    */
    function appendBytes20(buffer memory buf, bytes20 data) internal pure returns (buffer memory) {
        return append(buf, bytes32(data), 20);
    }

    /**
    * @dev Appends a bytes32 to the buffer. Resizes if doing so would exceed
    *      the capacity of the buffer.
    * @param buf The buffer to append to.
    * @param data The data to append.
    * @return The original buffer, for chaining.
    */
    function appendBytes32(buffer memory buf, bytes32 data) internal pure returns (buffer memory) {
        return append(buf, data, 32);
    }

    /**
     * @dev Appends a byte to the end of the buffer. Resizes if doing so would
     *      exceed the capacity of the buffer.
     * @param buf The buffer to append to.
     * @param data The data to append.
     * @param len The number of bytes to write (right-aligned).
     * @return The original buffer.
     */
    function appendInt(buffer memory buf, uint data, uint len) internal pure returns(buffer memory) {
        uint off = buf.buf.length;
        uint newCapacity = len + off;
        if (newCapacity > buf.capacity) {
            resize(buf, newCapacity * 2);
        }

        uint mask = (256 ** len) - 1;
        assembly {
            // Memory address of the buffer data
            let bufptr := mload(buf)
            // Address = buffer address + sizeof(buffer length) + newCapacity
            let dest := add(bufptr, newCapacity)
            mstore(dest, or(and(mload(dest), not(mask)), data))
            // Update buffer length if we extended it
            if gt(newCapacity, mload(bufptr)) {
                mstore(bufptr, newCapacity)
            }
        }
        return buf;
    }
}


library CBOR {
    using Buffer for Buffer.buffer;

    struct CBORBuffer {
        Buffer.buffer buf;
        uint256 depth;
    }

    uint8 private constant MAJOR_TYPE_INT = 0;
    uint8 private constant MAJOR_TYPE_NEGATIVE_INT = 1;
    uint8 private constant MAJOR_TYPE_BYTES = 2;
    uint8 private constant MAJOR_TYPE_STRING = 3;
    uint8 private constant MAJOR_TYPE_ARRAY = 4;
    uint8 private constant MAJOR_TYPE_MAP = 5;
    uint8 private constant MAJOR_TYPE_TAG = 6;
    uint8 private constant MAJOR_TYPE_CONTENT_FREE = 7;

    uint8 private constant TAG_TYPE_BIGNUM = 2;
    uint8 private constant TAG_TYPE_NEGATIVE_BIGNUM = 3;

    uint8 private constant CBOR_FALSE = 20;
    uint8 private constant CBOR_TRUE = 21;
    uint8 private constant CBOR_NULL = 22;
    uint8 private constant CBOR_UNDEFINED = 23;

    function create(uint256 capacity) internal pure returns(CBORBuffer memory cbor) {
        Buffer.init(cbor.buf, capacity);
        cbor.depth = 0;
        return cbor;
    }

    function data(CBORBuffer memory buf) internal pure returns(bytes memory) {
        require(buf.depth == 0, "Invalid CBOR");
        return buf.buf.buf;
    }

    function writeUInt256(CBORBuffer memory buf, uint256 value) internal pure {
        buf.buf.appendUint8(uint8((MAJOR_TYPE_TAG << 5) | TAG_TYPE_BIGNUM));
        writeBytes(buf, abi.encode(value));
    }

    function writeInt256(CBORBuffer memory buf, int256 value) internal pure {
        if (value < 0) {
            buf.buf.appendUint8(
                uint8((MAJOR_TYPE_TAG << 5) | TAG_TYPE_NEGATIVE_BIGNUM)
            );
            writeBytes(buf, abi.encode(uint256(-1 - value)));
        } else {
            writeUInt256(buf, uint256(value));
        }
    }

    function writeUInt64(CBORBuffer memory buf, uint64 value) internal pure {
        writeFixedNumeric(buf, MAJOR_TYPE_INT, value);
    }

    function writeInt64(CBORBuffer memory buf, int64 value) internal pure {
        if(value >= 0) {
            writeFixedNumeric(buf, MAJOR_TYPE_INT, uint64(value));
        } else{
            writeFixedNumeric(buf, MAJOR_TYPE_NEGATIVE_INT, uint64(-1 - value));
        }
    }

    function writeBytes(CBORBuffer memory buf, bytes memory value) internal pure {
        writeFixedNumeric(buf, MAJOR_TYPE_BYTES, uint64(value.length));
        buf.buf.append(value);
    }

    function writeString(CBORBuffer memory buf, string memory value) internal pure {
        writeFixedNumeric(buf, MAJOR_TYPE_STRING, uint64(bytes(value).length));
        buf.buf.append(bytes(value));
    }

    function writeBool(CBORBuffer memory buf, bool value) internal pure {
        writeContentFree(buf, value ? CBOR_TRUE : CBOR_FALSE);
    }

    function writeNull(CBORBuffer memory buf) internal pure {
        writeContentFree(buf, CBOR_NULL);
    }

    function writeUndefined(CBORBuffer memory buf) internal pure {
        writeContentFree(buf, CBOR_UNDEFINED);
    }

    function startArray(CBORBuffer memory buf) internal pure {
        writeIndefiniteLengthType(buf, MAJOR_TYPE_ARRAY);
        buf.depth += 1;
    }

    function startFixedArray(CBORBuffer memory buf, uint64 length) internal pure {
        writeDefiniteLengthType(buf, MAJOR_TYPE_ARRAY, length);
    }

    function startMap(CBORBuffer memory buf) internal pure {
        writeIndefiniteLengthType(buf, MAJOR_TYPE_MAP);
        buf.depth += 1;
    }

    function startFixedMap(CBORBuffer memory buf, uint64 length) internal pure {
        writeDefiniteLengthType(buf, MAJOR_TYPE_MAP, length);
    }

    function endSequence(CBORBuffer memory buf) internal pure {
        writeIndefiniteLengthType(buf, MAJOR_TYPE_CONTENT_FREE);
        buf.depth -= 1;
    }

    function writeKVString(CBORBuffer memory buf, string memory key, string memory value) internal pure {
        writeString(buf, key);
        writeString(buf, value);
    }

    function writeKVBytes(CBORBuffer memory buf, string memory key, bytes memory value) internal pure {
        writeString(buf, key);
        writeBytes(buf, value);
    }

    function writeKVUInt256(CBORBuffer memory buf, string memory key, uint256 value) internal pure {
        writeString(buf, key);
        writeUInt256(buf, value);
    }

    function writeKVInt256(CBORBuffer memory buf, string memory key, int256 value) internal pure {
        writeString(buf, key);
        writeInt256(buf, value);
    }

    function writeKVUInt64(CBORBuffer memory buf, string memory key, uint64 value) internal pure {
        writeString(buf, key);
        writeUInt64(buf, value);
    }

    function writeKVInt64(CBORBuffer memory buf, string memory key, int64 value) internal pure {
        writeString(buf, key);
        writeInt64(buf, value);
    }

    function writeKVBool(CBORBuffer memory buf, string memory key, bool value) internal pure {
        writeString(buf, key);
        writeBool(buf, value);
    }

    function writeKVNull(CBORBuffer memory buf, string memory key) internal pure {
        writeString(buf, key);
        writeNull(buf);
    }

    function writeKVUndefined(CBORBuffer memory buf, string memory key) internal pure {
        writeString(buf, key);
        writeUndefined(buf);
    }

    function writeKVMap(CBORBuffer memory buf, string memory key) internal pure {
        writeString(buf, key);
        startMap(buf);
    }

    function writeKVArray(CBORBuffer memory buf, string memory key) internal pure {
        writeString(buf, key);
        startArray(buf);
    }

    function writeFixedNumeric(
        CBORBuffer memory buf,
        uint8 major,
        uint64 value
    ) private pure {
        if (value <= 23) {
            buf.buf.appendUint8(uint8((major << 5) | value));
        } else if (value <= 0xFF) {
            buf.buf.appendUint8(uint8((major << 5) | 24));
            buf.buf.appendInt(value, 1);
        } else if (value <= 0xFFFF) {
            buf.buf.appendUint8(uint8((major << 5) | 25));
            buf.buf.appendInt(value, 2);
        } else if (value <= 0xFFFFFFFF) {
            buf.buf.appendUint8(uint8((major << 5) | 26));
            buf.buf.appendInt(value, 4);
        } else {
            buf.buf.appendUint8(uint8((major << 5) | 27));
            buf.buf.appendInt(value, 8);
        }
    }

    function writeIndefiniteLengthType(CBORBuffer memory buf, uint8 major)
        private
        pure
    {
        buf.buf.appendUint8(uint8((major << 5) | 31));
    }

    function writeDefiniteLengthType(CBORBuffer memory buf, uint8 major, uint64 length)
        private
        pure
    {
        writeFixedNumeric(buf, major, length);
    }

    function writeContentFree(CBORBuffer memory buf, uint8 value) private pure {
        buf.buf.appendUint8(uint8((MAJOR_TYPE_CONTENT_FREE << 5) | value));
    }
}
/*
End solidity-cborutils
 */

// contract usingProvable {
//     uint constant day = 60*60*24;
//     uint constant week = 60*60*24*7;
//     uint constant month = 60*60*24*30;
//     bytes1 constant proofType_NONE = 0x00;
//     bytes1 constant proofType_TLSNotary = 0x10;
//     bytes1 constant proofType_Ledger = 0x30;
//     bytes1 constant proofType_Android = 0x40;
//     bytes1 constant proofType_Native = 0xF0;
//     bytes1 constant proofStorage_IPFS = 0x01;
//     uint8 constant networkID_auto = 0;
//     uint8 constant networkID_mainnet = 1;
//     uint8 constant networkID_testnet = 2;
//     uint8 constant networkID_morden = 2;
//     uint8 constant networkID_consensys = 161;

//     OracleAddrResolverI OAR;

//     ProvableI provable;
//     modifier provableAPI {
//         if((address(OAR)==0)||(getCodeSize(address(OAR))==0))
//             provable_setNetwork(networkID_auto);

//         if(address(provable) != OAR.getAddress())
//             provable = ProvableI(OAR.getAddress());

//         _;
//     }
//     modifier coupon(string code){
//         provable = ProvableI(OAR.getAddress());
//         _;
//     }

//     function provable_setNetwork(uint8 networkID) internal returns(bool){
//       return provable_setNetwork();
//       networkID; // silence the warning and remain backwards compatible
//     }
//     function provable_setNetwork() internal returns(bool){
//         if (getCodeSize(0x1d3B2638a7cC9f2CB3D298A3DA7a90B67E5506ed)>0){ //mainnet
//             OAR = OracleAddrResolverI(0x1d3B2638a7cC9f2CB3D298A3DA7a90B67E5506ed);
//             provable_setNetworkName("eth_mainnet");
//             return true;
//         }
//         if (getCodeSize(0xc03A2615D5efaf5F49F60B7BB6583eaec212fdf1)>0){ //ropsten testnet
//             OAR = OracleAddrResolverI(0xc03A2615D5efaf5F49F60B7BB6583eaec212fdf1);
//             provable_setNetworkName("eth_ropsten3");
//             return true;
//         }
//         if (getCodeSize(0xB7A07BcF2Ba2f2703b24C0691b5278999C59AC7e)>0){ //kovan testnet
//             OAR = OracleAddrResolverI(0xB7A07BcF2Ba2f2703b24C0691b5278999C59AC7e);
//             provable_setNetworkName("eth_kovan");
//             return true;
//         }
//         if (getCodeSize(0x146500cfd35B22E4A392Fe0aDc06De1a1368Ed48)>0){ //rinkeby testnet
//             OAR = OracleAddrResolverI(0x146500cfd35B22E4A392Fe0aDc06De1a1368Ed48);
//             provable_setNetworkName("eth_rinkeby");
//             return true;
//         }
//         if (getCodeSize(0xa2998EFD205FB9D4B4963aFb70778D6354ad3A41)>0){ //goerli testnet
//             OAR = OracleAddrResolverI(0xa2998EFD205FB9D4B4963aFb70778D6354ad3A41);
//             provable_setNetworkName("eth_goerli");
//             return true;
//         }
//         if (getCodeSize(0x6f485C8BF6fc43eA212E93BBF8ce046C7f1cb475)>0){ //ethereum-bridge
//             OAR = OracleAddrResolverI(0x6f485C8BF6fc43eA212E93BBF8ce046C7f1cb475);
//             return true;
//         }
//         if (getCodeSize(0x20e12A1F859B3FeaE5Fb2A0A32C18F5a65555bBF)>0){ //ether.camp ide
//             OAR = OracleAddrResolverI(0x20e12A1F859B3FeaE5Fb2A0A32C18F5a65555bBF);
//             return true;
//         }
//         if (getCodeSize(0x51efaF4c8B3C9AfBD5aB9F4bbC82784Ab6ef8fAA)>0){ //browser-solidity
//             OAR = OracleAddrResolverI(0x51efaF4c8B3C9AfBD5aB9F4bbC82784Ab6ef8fAA);
//             return true;
//         }
//         return false;
//     }
//     /**
//      * @dev The following `__callback` functions are just placeholders ideally
//      *      meant to be defined in child contract when proofs are used.
//      *      The function bodies simply silence compiler warnings.
//      */
//     function __callback(bytes32 myid, string result) public {
//         __callback(myid, result, new bytes(0));
//     }

//     function __callback(bytes32 myid, string result, bytes proof) public {
//       return;
//       myid; result; proof;
//       provable_randomDS_args[bytes32(0)] = bytes32(0);
//     }

//     function provable_getPrice(string datasource) provableAPI internal returns (uint){
//         return provable.getPrice(datasource);
//     }

//     function provable_getPrice(string datasource, uint gaslimit) provableAPI internal returns (uint){
//         return provable.getPrice(datasource, gaslimit);
//     }

//     function provable_query(string datasource, string arg) provableAPI internal returns (bytes32 id){
//         uint price = provable.getPrice(datasource);
//         if (price > 1 ether + tx.gasprice*200000) return 0; // unexpectedly high price
//         return provable.query.value(price)(0, datasource, arg);
//     }
//     function provable_query(uint timestamp, string datasource, string arg) provableAPI internal returns (bytes32 id){
//         uint price = provable.getPrice(datasource);
//         if (price > 1 ether + tx.gasprice*200000) return 0; // unexpectedly high price
//         return provable.query.value(price)(timestamp, datasource, arg);
//     }
//     function provable_query(uint timestamp, string datasource, string arg, uint gaslimit) provableAPI internal returns (bytes32 id){
//         uint price = provable.getPrice(datasource, gaslimit);
//         if (price > 1 ether + tx.gasprice*gaslimit) return 0; // unexpectedly high price
//         return provable.query_withGasLimit.value(price)(timestamp, datasource, arg, gaslimit);
//     }
//     function provable_query(string datasource, string arg, uint gaslimit) provableAPI internal returns (bytes32 id){
//         uint price = provable.getPrice(datasource, gaslimit);
//         if (price > 1 ether + tx.gasprice*gaslimit) return 0; // unexpectedly high price
//         return provable.query_withGasLimit.value(price)(0, datasource, arg, gaslimit);
//     }
//     function provable_query(string datasource, string arg1, string arg2) provableAPI internal returns (bytes32 id){
//         uint price = provable.getPrice(datasource);
//         if (price > 1 ether + tx.gasprice*200000) return 0; // unexpectedly high price
//         return provable.query2.value(price)(0, datasource, arg1, arg2);
//     }
//     function provable_query(uint timestamp, string datasource, string arg1, string arg2) provableAPI internal returns (bytes32 id){
//         uint price = provable.getPrice(datasource);
//         if (price > 1 ether + tx.gasprice*200000) return 0; // unexpectedly high price
//         return provable.query2.value(price)(timestamp, datasource, arg1, arg2);
//     }
//     function provable_query(uint timestamp, string datasource, string arg1, string arg2, uint gaslimit) provableAPI internal returns (bytes32 id){
//         uint price = provable.getPrice(datasource, gaslimit);
//         if (price > 1 ether + tx.gasprice*gaslimit) return 0; // unexpectedly high price
//         return provable.query2_withGasLimit.value(price)(timestamp, datasource, arg1, arg2, gaslimit);
//     }
//     function provable_query(string datasource, string arg1, string arg2, uint gaslimit) provableAPI internal returns (bytes32 id){
//         uint price = provable.getPrice(datasource, gaslimit);
//         if (price > 1 ether + tx.gasprice*gaslimit) return 0; // unexpectedly high price
//         return provable.query2_withGasLimit.value(price)(0, datasource, arg1, arg2, gaslimit);
//     }
//     function provable_query(string datasource, string[] argN) provableAPI internal returns (bytes32 id){
//         uint price = provable.getPrice(datasource);
//         if (price > 1 ether + tx.gasprice*200000) return 0; // unexpectedly high price
//         bytes memory args = stra2cbor(argN);
//         return provable.queryN.value(price)(0, datasource, args);
//     }
//     function provable_query(uint timestamp, string datasource, string[] argN) provableAPI internal returns (bytes32 id){
//         uint price = provable.getPrice(datasource);
//         if (price > 1 ether + tx.gasprice*200000) return 0; // unexpectedly high price
//         bytes memory args = stra2cbor(argN);
//         return provable.queryN.value(price)(timestamp, datasource, args);
//     }
//     function provable_query(uint timestamp, string datasource, string[] argN, uint gaslimit) provableAPI internal returns (bytes32 id){
//         uint price = provable.getPrice(datasource, gaslimit);
//         if (price > 1 ether + tx.gasprice*gaslimit) return 0; // unexpectedly high price
//         bytes memory args = stra2cbor(argN);
//         return provable.queryN_withGasLimit.value(price)(timestamp, datasource, args, gaslimit);
//     }
//     function provable_query(string datasource, string[] argN, uint gaslimit) provableAPI internal returns (bytes32 id){
//         uint price = provable.getPrice(datasource, gaslimit);
//         if (price > 1 ether + tx.gasprice*gaslimit) return 0; // unexpectedly high price
//         bytes memory args = stra2cbor(argN);
//         return provable.queryN_withGasLimit.value(price)(0, datasource, args, gaslimit);
//     }
//     function provable_query(string datasource, string[1] args) provableAPI internal returns (bytes32 id) {
//         string[] memory dynargs = new string[](1);
//         dynargs[0] = args[0];
//         return provable_query(datasource, dynargs);
//     }
//     function provable_query(uint timestamp, string datasource, string[1] args) provableAPI internal returns (bytes32 id) {
//         string[] memory dynargs = new string[](1);
//         dynargs[0] = args[0];
//         return provable_query(timestamp, datasource, dynargs);
//     }
//     function provable_query(uint timestamp, string datasource, string[1] args, uint gaslimit) provableAPI internal returns (bytes32 id) {
//         string[] memory dynargs = new string[](1);
//         dynargs[0] = args[0];
//         return provable_query(timestamp, datasource, dynargs, gaslimit);
//     }
//     function provable_query(string datasource, string[1] args, uint gaslimit) provableAPI internal returns (bytes32 id) {
//         string[] memory dynargs = new string[](1);
//         dynargs[0] = args[0];
//         return provable_query(datasource, dynargs, gaslimit);
//     }

//     function provable_query(string datasource, string[2] args) provableAPI internal returns (bytes32 id) {
//         string[] memory dynargs = new string[](2);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         return provable_query(datasource, dynargs);
//     }
//     function provable_query(uint timestamp, string datasource, string[2] args) provableAPI internal returns (bytes32 id) {
//         string[] memory dynargs = new string[](2);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         return provable_query(timestamp, datasource, dynargs);
//     }
//     function provable_query(uint timestamp, string datasource, string[2] args, uint gaslimit) provableAPI internal returns (bytes32 id) {
//         string[] memory dynargs = new string[](2);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         return provable_query(timestamp, datasource, dynargs, gaslimit);
//     }
//     function provable_query(string datasource, string[2] args, uint gaslimit) provableAPI internal returns (bytes32 id) {
//         string[] memory dynargs = new string[](2);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         return provable_query(datasource, dynargs, gaslimit);
//     }
//     function provable_query(string datasource, string[3] args) provableAPI internal returns (bytes32 id) {
//         string[] memory dynargs = new string[](3);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         dynargs[2] = args[2];
//         return provable_query(datasource, dynargs);
//     }
//     function provable_query(uint timestamp, string datasource, string[3] args) provableAPI internal returns (bytes32 id) {
//         string[] memory dynargs = new string[](3);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         dynargs[2] = args[2];
//         return provable_query(timestamp, datasource, dynargs);
//     }
//     function provable_query(uint timestamp, string datasource, string[3] args, uint gaslimit) provableAPI internal returns (bytes32 id) {
//         string[] memory dynargs = new string[](3);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         dynargs[2] = args[2];
//         return provable_query(timestamp, datasource, dynargs, gaslimit);
//     }
//     function provable_query(string datasource, string[3] args, uint gaslimit) provableAPI internal returns (bytes32 id) {
//         string[] memory dynargs = new string[](3);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         dynargs[2] = args[2];
//         return provable_query(datasource, dynargs, gaslimit);
//     }

//     function provable_query(string datasource, string[4] args) provableAPI internal returns (bytes32 id) {
//         string[] memory dynargs = new string[](4);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         dynargs[2] = args[2];
//         dynargs[3] = args[3];
//         return provable_query(datasource, dynargs);
//     }
//     function provable_query(uint timestamp, string datasource, string[4] args) provableAPI internal returns (bytes32 id) {
//         string[] memory dynargs = new string[](4);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         dynargs[2] = args[2];
//         dynargs[3] = args[3];
//         return provable_query(timestamp, datasource, dynargs);
//     }
//     function provable_query(uint timestamp, string datasource, string[4] args, uint gaslimit) provableAPI internal returns (bytes32 id) {
//         string[] memory dynargs = new string[](4);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         dynargs[2] = args[2];
//         dynargs[3] = args[3];
//         return provable_query(timestamp, datasource, dynargs, gaslimit);
//     }
//     function provable_query(string datasource, string[4] args, uint gaslimit) provableAPI internal returns (bytes32 id) {
//         string[] memory dynargs = new string[](4);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         dynargs[2] = args[2];
//         dynargs[3] = args[3];
//         return provable_query(datasource, dynargs, gaslimit);
//     }
//     function provable_query(string datasource, string[5] args) provableAPI internal returns (bytes32 id) {
//         string[] memory dynargs = new string[](5);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         dynargs[2] = args[2];
//         dynargs[3] = args[3];
//         dynargs[4] = args[4];
//         return provable_query(datasource, dynargs);
//     }
//     function provable_query(uint timestamp, string datasource, string[5] args) provableAPI internal returns (bytes32 id) {
//         string[] memory dynargs = new string[](5);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         dynargs[2] = args[2];
//         dynargs[3] = args[3];
//         dynargs[4] = args[4];
//         return provable_query(timestamp, datasource, dynargs);
//     }
//     function provable_query(uint timestamp, string datasource, string[5] args, uint gaslimit) provableAPI internal returns (bytes32 id) {
//         string[] memory dynargs = new string[](5);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         dynargs[2] = args[2];
//         dynargs[3] = args[3];
//         dynargs[4] = args[4];
//         return provable_query(timestamp, datasource, dynargs, gaslimit);
//     }
//     function provable_query(string datasource, string[5] args, uint gaslimit) provableAPI internal returns (bytes32 id) {
//         string[] memory dynargs = new string[](5);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         dynargs[2] = args[2];
//         dynargs[3] = args[3];
//         dynargs[4] = args[4];
//         return provable_query(datasource, dynargs, gaslimit);
//     }
//     function provable_query(string datasource, bytes[] argN) provableAPI internal returns (bytes32 id){
//         uint price = provable.getPrice(datasource);
//         if (price > 1 ether + tx.gasprice*200000) return 0; // unexpectedly high price
//         bytes memory args = ba2cbor(argN);
//         return provable.queryN.value(price)(0, datasource, args);
//     }
//     function provable_query(uint timestamp, string datasource, bytes[] argN) provableAPI internal returns (bytes32 id){
//         uint price = provable.getPrice(datasource);
//         if (price > 1 ether + tx.gasprice*200000) return 0; // unexpectedly high price
//         bytes memory args = ba2cbor(argN);
//         return provable.queryN.value(price)(timestamp, datasource, args);
//     }
//     function provable_query(uint timestamp, string datasource, bytes[] argN, uint gaslimit) provableAPI internal returns (bytes32 id){
//         uint price = provable.getPrice(datasource, gaslimit);
//         if (price > 1 ether + tx.gasprice*gaslimit) return 0; // unexpectedly high price
//         bytes memory args = ba2cbor(argN);
//         return provable.queryN_withGasLimit.value(price)(timestamp, datasource, args, gaslimit);
//     }
//     function provable_query(string datasource, bytes[] argN, uint gaslimit) provableAPI internal returns (bytes32 id){
//         uint price = provable.getPrice(datasource, gaslimit);
//         if (price > 1 ether + tx.gasprice*gaslimit) return 0; // unexpectedly high price
//         bytes memory args = ba2cbor(argN);
//         return provable.queryN_withGasLimit.value(price)(0, datasource, args, gaslimit);
//     }
//     function provable_query(string datasource, bytes[1] args) provableAPI internal returns (bytes32 id) {
//         bytes[] memory dynargs = new bytes[](1);
//         dynargs[0] = args[0];
//         return provable_query(datasource, dynargs);
//     }
//     function provable_query(uint timestamp, string datasource, bytes[1] args) provableAPI internal returns (bytes32 id) {
//         bytes[] memory dynargs = new bytes[](1);
//         dynargs[0] = args[0];
//         return provable_query(timestamp, datasource, dynargs);
//     }
//     function provable_query(uint timestamp, string datasource, bytes[1] args, uint gaslimit) provableAPI internal returns (bytes32 id) {
//         bytes[] memory dynargs = new bytes[](1);
//         dynargs[0] = args[0];
//         return provable_query(timestamp, datasource, dynargs, gaslimit);
//     }
//     function provable_query(string datasource, bytes[1] args, uint gaslimit) provableAPI internal returns (bytes32 id) {
//         bytes[] memory dynargs = new bytes[](1);
//         dynargs[0] = args[0];
//         return provable_query(datasource, dynargs, gaslimit);
//     }

//     function provable_query(string datasource, bytes[2] args) provableAPI internal returns (bytes32 id) {
//         bytes[] memory dynargs = new bytes[](2);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         return provable_query(datasource, dynargs);
//     }
//     function provable_query(uint timestamp, string datasource, bytes[2] args) provableAPI internal returns (bytes32 id) {
//         bytes[] memory dynargs = new bytes[](2);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         return provable_query(timestamp, datasource, dynargs);
//     }
//     function provable_query(uint timestamp, string datasource, bytes[2] args, uint gaslimit) provableAPI internal returns (bytes32 id) {
//         bytes[] memory dynargs = new bytes[](2);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         return provable_query(timestamp, datasource, dynargs, gaslimit);
//     }
//     function provable_query(string datasource, bytes[2] args, uint gaslimit) provableAPI internal returns (bytes32 id) {
//         bytes[] memory dynargs = new bytes[](2);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         return provable_query(datasource, dynargs, gaslimit);
//     }
//     function provable_query(string datasource, bytes[3] args) provableAPI internal returns (bytes32 id) {
//         bytes[] memory dynargs = new bytes[](3);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         dynargs[2] = args[2];
//         return provable_query(datasource, dynargs);
//     }
//     function provable_query(uint timestamp, string datasource, bytes[3] args) provableAPI internal returns (bytes32 id) {
//         bytes[] memory dynargs = new bytes[](3);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         dynargs[2] = args[2];
//         return provable_query(timestamp, datasource, dynargs);
//     }
//     function provable_query(uint timestamp, string datasource, bytes[3] args, uint gaslimit) provableAPI internal returns (bytes32 id) {
//         bytes[] memory dynargs = new bytes[](3);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         dynargs[2] = args[2];
//         return provable_query(timestamp, datasource, dynargs, gaslimit);
//     }
//     function provable_query(string datasource, bytes[3] args, uint gaslimit) provableAPI internal returns (bytes32 id) {
//         bytes[] memory dynargs = new bytes[](3);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         dynargs[2] = args[2];
//         return provable_query(datasource, dynargs, gaslimit);
//     }

//     function provable_query(string datasource, bytes[4] args) provableAPI internal returns (bytes32 id) {
//         bytes[] memory dynargs = new bytes[](4);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         dynargs[2] = args[2];
//         dynargs[3] = args[3];
//         return provable_query(datasource, dynargs);
//     }
//     function provable_query(uint timestamp, string datasource, bytes[4] args) provableAPI internal returns (bytes32 id) {
//         bytes[] memory dynargs = new bytes[](4);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         dynargs[2] = args[2];
//         dynargs[3] = args[3];
//         return provable_query(timestamp, datasource, dynargs);
//     }
//     function provable_query(uint timestamp, string datasource, bytes[4] args, uint gaslimit) provableAPI internal returns (bytes32 id) {
//         bytes[] memory dynargs = new bytes[](4);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         dynargs[2] = args[2];
//         dynargs[3] = args[3];
//         return provable_query(timestamp, datasource, dynargs, gaslimit);
//     }
//     function provable_query(string datasource, bytes[4] args, uint gaslimit) provableAPI internal returns (bytes32 id) {
//         bytes[] memory dynargs = new bytes[](4);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         dynargs[2] = args[2];
//         dynargs[3] = args[3];
//         return provable_query(datasource, dynargs, gaslimit);
//     }
//     function provable_query(string datasource, bytes[5] args) provableAPI internal returns (bytes32 id) {
//         bytes[] memory dynargs = new bytes[](5);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         dynargs[2] = args[2];
//         dynargs[3] = args[3];
//         dynargs[4] = args[4];
//         return provable_query(datasource, dynargs);
//     }
//     function provable_query(uint timestamp, string datasource, bytes[5] args) provableAPI internal returns (bytes32 id) {
//         bytes[] memory dynargs = new bytes[](5);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         dynargs[2] = args[2];
//         dynargs[3] = args[3];
//         dynargs[4] = args[4];
//         return provable_query(timestamp, datasource, dynargs);
//     }
//     function provable_query(uint timestamp, string datasource, bytes[5] args, uint gaslimit) provableAPI internal returns (bytes32 id) {
//         bytes[] memory dynargs = new bytes[](5);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         dynargs[2] = args[2];
//         dynargs[3] = args[3];
//         dynargs[4] = args[4];
//         return provable_query(timestamp, datasource, dynargs, gaslimit);
//     }
//     function provable_query(string datasource, bytes[5] args, uint gaslimit) provableAPI internal returns (bytes32 id) {
//         bytes[] memory dynargs = new bytes[](5);
//         dynargs[0] = args[0];
//         dynargs[1] = args[1];
//         dynargs[2] = args[2];
//         dynargs[3] = args[3];
//         dynargs[4] = args[4];
//         return provable_query(datasource, dynargs, gaslimit);
//     }

//     function provable_cbAddress() provableAPI internal returns (address){
//         return provable.cbAddress();
//     }
//     function provable_setProof(bytes1 proofP) provableAPI internal {
//         return provable.setProofType(proofP);
//     }
//     function provable_setCustomGasPrice(uint gasPrice) provableAPI internal {
//         return provable.setCustomGasPrice(gasPrice);
//     }

//     function provable_randomDS_getSessionPubKeyHash() provableAPI internal returns (bytes32){
//         return provable.randomDS_getSessionPubKeyHash();
//     }

//     function getCodeSize(address _addr) view internal returns(uint _size) {
//         assembly {
//             _size := extcodesize(_addr)
//         }
//     }

//     function parseAddr(string _a) internal pure returns (address){
//         bytes memory tmp = bytes(_a);
//         uint160 iaddr = 0;
//         uint160 b1;
//         uint160 b2;
//         for (uint i=2; i<2+2*20; i+=2){
//             iaddr *= 256;
//             b1 = uint160(tmp[i]);
//             b2 = uint160(tmp[i+1]);
//             if ((b1 >= 97)&&(b1 <= 102)) b1 -= 87;
//             else if ((b1 >= 65)&&(b1 <= 70)) b1 -= 55;
//             else if ((b1 >= 48)&&(b1 <= 57)) b1 -= 48;
//             if ((b2 >= 97)&&(b2 <= 102)) b2 -= 87;
//             else if ((b2 >= 65)&&(b2 <= 70)) b2 -= 55;
//             else if ((b2 >= 48)&&(b2 <= 57)) b2 -= 48;
//             iaddr += (b1*16+b2);
//         }
//         return address(iaddr);
//     }

//     function strCompare(string _a, string _b) internal pure returns (int) {
//         bytes memory a = bytes(_a);
//         bytes memory b = bytes(_b);
//         uint minLength = a.length;
//         if (b.length < minLength) minLength = b.length;
//         for (uint i = 0; i < minLength; i ++)
//             if (a[i] < b[i])
//                 return -1;
//             else if (a[i] > b[i])
//                 return 1;
//         if (a.length < b.length)
//             return -1;
//         else if (a.length > b.length)
//             return 1;
//         else
//             return 0;
//     }

//     function indexOf(string _haystack, string _needle) internal pure returns (int) {
//         bytes memory h = bytes(_haystack);
//         bytes memory n = bytes(_needle);
//         if(h.length < 1 || n.length < 1 || (n.length > h.length))
//             return -1;
//         else if(h.length > (2**128 -1))
//             return -1;
//         else
//         {
//             uint subindex = 0;
//             for (uint i = 0; i < h.length; i ++)
//             {
//                 if (h[i] == n[0])
//                 {
//                     subindex = 1;
//                     while(subindex < n.length && (i + subindex) < h.length && h[i + subindex] == n[subindex])
//                     {
//                         subindex++;
//                     }
//                     if(subindex == n.length)
//                         return int(i);
//                 }
//             }
//             return -1;
//         }
//     }

//     function strConcat(string _a, string _b, string _c, string _d, string _e) internal pure returns (string) {
//         bytes memory _ba = bytes(_a);
//         bytes memory _bb = bytes(_b);
//         bytes memory _bc = bytes(_c);
//         bytes memory _bd = bytes(_d);
//         bytes memory _be = bytes(_e);
//         string memory abcde = new string(_ba.length + _bb.length + _bc.length + _bd.length + _be.length);
//         bytes memory babcde = bytes(abcde);
//         uint k = 0;
//         for (uint i = 0; i < _ba.length; i++) babcde[k++] = _ba[i];
//         for (i = 0; i < _bb.length; i++) babcde[k++] = _bb[i];
//         for (i = 0; i < _bc.length; i++) babcde[k++] = _bc[i];
//         for (i = 0; i < _bd.length; i++) babcde[k++] = _bd[i];
//         for (i = 0; i < _be.length; i++) babcde[k++] = _be[i];
//         return string(babcde);
//     }

//     function strConcat(string _a, string _b, string _c, string _d) internal pure returns (string) {
//         return strConcat(_a, _b, _c, _d, "");
//     }

//     function strConcat(string _a, string _b, string _c) internal pure returns (string) {
//         return strConcat(_a, _b, _c, "", "");
//     }

//     function strConcat(string _a, string _b) internal pure returns (string) {
//         return strConcat(_a, _b, "", "", "");
//     }

//     // parseInt
//     function parseInt(string _a) internal pure returns (uint) {
//         return parseInt(_a, 0);
//     }

//     // parseInt(parseFloat*10^_b)
//     function parseInt(string _a, uint _b) internal pure returns (uint) {
//         bytes memory bresult = bytes(_a);
//         uint mint = 0;
//         bool decimals = false;
//         for (uint i=0; i<bresult.length; i++){
//             if ((bresult[i] >= 48)&&(bresult[i] <= 57)){
//                 if (decimals){
//                    if (_b == 0) break;
//                     else _b--;
//                 }
//                 mint *= 10;
//                 mint += uint(bresult[i]) - 48;
//             } else if (bresult[i] == 46) decimals = true;
//         }
//         if (_b > 0) mint *= 10**_b;
//         return mint;
//     }

//     function uint2str(uint i) internal pure returns (string){
//         if (i == 0) return "0";
//         uint j = i;
//         uint len;
//         while (j != 0){
//             len++;
//             j /= 10;
//         }
//         bytes memory bstr = new bytes(len);
//         uint k = len - 1;
//         while (i != 0){
//             bstr[k--] = bytes1(48 + i % 10);
//             i /= 10;
//         }
//         return string(bstr);
//     }

//     using CBOR for Buffer.buffer;
//     function stra2cbor(string[] arr) internal pure returns (bytes) {
//         safeMemoryCleaner();
//         Buffer.buffer memory buf;
//         Buffer.init(buf, 1024);
//         buf.startArray();
//         for (uint i = 0; i < arr.length; i++) {
//             buf.encodeString(arr[i]);
//         }
//         buf.endSequence();
//         return buf.buf;
//     }

//     function ba2cbor(bytes[] arr) internal pure returns (bytes) {
//         safeMemoryCleaner();
//         Buffer.buffer memory buf;
//         Buffer.init(buf, 1024);
//         buf.startArray();
//         for (uint i = 0; i < arr.length; i++) {
//             buf.encodeBytes(arr[i]);
//         }
//         buf.endSequence();
//         return buf.buf;
//     }

//     string provable_network_name;
//     function provable_setNetworkName(string _network_name) internal {
//         provable_network_name = _network_name;
//     }

//     function provable_getNetworkName() internal view returns (string) {
//         return provable_network_name;
//     }

//     function provable_newRandomDSQuery(uint _delay, uint _nbytes, uint _customGasLimit) internal returns (bytes32){
//         require((_nbytes > 0) && (_nbytes <= 32));
//         // Convert from seconds to ledger timer ticks
//         _delay *= 10;
//         bytes memory nbytes = new bytes(1);
//         nbytes[0] = bytes1(_nbytes);
//         bytes memory unonce = new bytes(32);
//         bytes memory sessionKeyHash = new bytes(32);
//         bytes32 sessionKeyHash_bytes32 = provable_randomDS_getSessionPubKeyHash();
//         assembly {
//             mstore(unonce, 0x20)
//             // the following variables can be relaxed
//             // check relaxed random contract under ethereum-examples repo
//             // for an idea on how to override and replace comit hash vars
//             mstore(add(unonce, 0x20), xor(blockhash(sub(number, 1)), xor(coinbase, timestamp)))
//             mstore(sessionKeyHash, 0x20)
//             mstore(add(sessionKeyHash, 0x20), sessionKeyHash_bytes32)
//         }
//         bytes memory delay = new bytes(32);
//         assembly {
//             mstore(add(delay, 0x20), _delay)
//         }

//         bytes memory delay_bytes8 = new bytes(8);
//         copyBytes(delay, 24, 8, delay_bytes8, 0);

//         bytes[4] memory args = [unonce, nbytes, sessionKeyHash, delay];
//         bytes32 queryId = provable_query("random", args, _customGasLimit);

//         bytes memory delay_bytes8_left = new bytes(8);

//         assembly {
//             let x := mload(add(delay_bytes8, 0x20))
//             mstore8(add(delay_bytes8_left, 0x27), div(x, 0x100000000000000000000000000000000000000000000000000000000000000))
//             mstore8(add(delay_bytes8_left, 0x26), div(x, 0x1000000000000000000000000000000000000000000000000000000000000))
//             mstore8(add(delay_bytes8_left, 0x25), div(x, 0x10000000000000000000000000000000000000000000000000000000000))
//             mstore8(add(delay_bytes8_left, 0x24), div(x, 0x100000000000000000000000000000000000000000000000000000000))
//             mstore8(add(delay_bytes8_left, 0x23), div(x, 0x1000000000000000000000000000000000000000000000000000000))
//             mstore8(add(delay_bytes8_left, 0x22), div(x, 0x10000000000000000000000000000000000000000000000000000))
//             mstore8(add(delay_bytes8_left, 0x21), div(x, 0x100000000000000000000000000000000000000000000000000))
//             mstore8(add(delay_bytes8_left, 0x20), div(x, 0x1000000000000000000000000000000000000000000000000))

//         }

//         provable_randomDS_setCommitment(queryId, keccak256(abi.encodePacked(delay_bytes8_left, args[1], sha256(args[0]), args[2])));
//         return queryId;
//     }

//     function provable_randomDS_setCommitment(bytes32 queryId, bytes32 commitment) internal {
//         provable_randomDS_args[queryId] = commitment;
//     }

//     mapping(bytes32=>bytes32) provable_randomDS_args;
//     mapping(bytes32=>bool) provable_randomDS_sessionKeysHashVerified;

//     function verifySig(bytes32 tosignh, bytes dersig, bytes pubkey) internal returns (bool){
//         bool sigok;
//         address signer;

//         bytes32 sigr;
//         bytes32 sigs;

//         bytes memory sigr_ = new bytes(32);
//         uint offset = 4+(uint(dersig[3]) - 0x20);
//         sigr_ = copyBytes(dersig, offset, 32, sigr_, 0);
//         bytes memory sigs_ = new bytes(32);
//         offset += 32 + 2;
//         sigs_ = copyBytes(dersig, offset+(uint(dersig[offset-1]) - 0x20), 32, sigs_, 0);

//         assembly {
//             sigr := mload(add(sigr_, 32))
//             sigs := mload(add(sigs_, 32))
//         }


//         (sigok, signer) = safer_ecrecover(tosignh, 27, sigr, sigs);
//         if (address(keccak256(pubkey)) == signer) return true;
//         else {
//             (sigok, signer) = safer_ecrecover(tosignh, 28, sigr, sigs);
//             return (address(keccak256(pubkey)) == signer);
//         }
//     }

//     function provable_randomDS_proofVerify__sessionKeyValidity(bytes proof, uint sig2offset) internal returns (bool) {
//         bool sigok;

//         // Step 6: verify the attestation signature, APPKEY1 must sign the sessionKey from the correct ledger app (CODEHASH)
//         bytes memory sig2 = new bytes(uint(proof[sig2offset+1])+2);
//         copyBytes(proof, sig2offset, sig2.length, sig2, 0);

//         bytes memory appkey1_pubkey = new bytes(64);
//         copyBytes(proof, 3+1, 64, appkey1_pubkey, 0);

//         bytes memory tosign2 = new bytes(1+65+32);
//         tosign2[0] = bytes1(1); //role
//         copyBytes(proof, sig2offset-65, 65, tosign2, 1);
//         bytes memory CODEHASH = hex"fd94fa71bc0ba10d39d464d0d8f465efeef0a2764e3887fcc9df41ded20f505c";
//         copyBytes(CODEHASH, 0, 32, tosign2, 1+65);
//         sigok = verifySig(sha256(tosign2), sig2, appkey1_pubkey);

//         if (sigok == false) return false;


//         // Step 7: verify the APPKEY1 provenance (must be signed by Ledger)
//         bytes memory LEDGERKEY = hex"7fb956469c5c9b89840d55b43537e66a98dd4811ea0a27224272c2e5622911e8537a2f8e86a46baec82864e98dd01e9ccc2f8bc5dfc9cbe5a91a290498dd96e4";

//         bytes memory tosign3 = new bytes(1+65);
//         tosign3[0] = 0xFE;
//         copyBytes(proof, 3, 65, tosign3, 1);

//         bytes memory sig3 = new bytes(uint(proof[3+65+1])+2);
//         copyBytes(proof, 3+65, sig3.length, sig3, 0);

//         sigok = verifySig(sha256(tosign3), sig3, LEDGERKEY);

//         return sigok;
//     }

//     modifier provable_randomDS_proofVerify(bytes32 _queryId, string _result, bytes _proof) {
//         // Step 1: the prefix has to match 'LP\x01' (Ledger Proof version 1)
//         require((_proof[0] == "L") && (_proof[1] == "P") && (_proof[2] == 1));

//         bool proofVerified = provable_randomDS_proofVerify__main(_proof, _queryId, bytes(_result), provable_getNetworkName());
//         require(proofVerified);

//         _;
//     }

//     function provable_randomDS_proofVerify__returnCode(bytes32 _queryId, string _result, bytes _proof) internal returns (uint8){
//         // Step 1: the prefix has to match 'LP\x01' (Ledger Proof version 1)
//         if ((_proof[0] != "L")||(_proof[1] != "P")||(_proof[2] != 1)) return 1;

//         bool proofVerified = provable_randomDS_proofVerify__main(_proof, _queryId, bytes(_result), provable_getNetworkName());
//         if (proofVerified == false) return 2;

//         return 0;
//     }

//     function matchBytes32Prefix(bytes32 content, bytes prefix, uint n_random_bytes) internal pure returns (bool){
//         bool match_ = true;

//         require(prefix.length == n_random_bytes);

//         for (uint256 i=0; i< n_random_bytes; i++) {
//             if (content[i] != prefix[i]) match_ = false;
//         }

//         return match_;
//     }

//     function provable_randomDS_proofVerify__main(bytes proof, bytes32 queryId, bytes result, string context_name) internal returns (bool){

//         // Step 2: the unique keyhash has to match with the sha256 of (context name + queryId)
//         uint ledgerProofLength = 3+65+(uint(proof[3+65+1])+2)+32;
//         bytes memory keyhash = new bytes(32);
//         copyBytes(proof, ledgerProofLength, 32, keyhash, 0);
//         if (!(keccak256(keyhash) == keccak256(abi.encodePacked(sha256(abi.encodePacked(context_name, queryId)))))) return false;

//         bytes memory sig1 = new bytes(uint(proof[ledgerProofLength+(32+8+1+32)+1])+2);
//         copyBytes(proof, ledgerProofLength+(32+8+1+32), sig1.length, sig1, 0);

//         // Step 3: we assume sig1 is valid (it will be verified during step 5) and we verify if 'result' is the prefix of sha256(sig1)
//         if (!matchBytes32Prefix(sha256(sig1), result, uint(proof[ledgerProofLength+32+8]))) return false;

//         // Step 4: commitment match verification, keccak256(delay, nbytes, unonce, sessionKeyHash) == commitment in storage.
//         // This is to verify that the computed args match with the ones specified in the query.
//         bytes memory commitmentSlice1 = new bytes(8+1+32);
//         copyBytes(proof, ledgerProofLength+32, 8+1+32, commitmentSlice1, 0);

//         bytes memory sessionPubkey = new bytes(64);
//         uint sig2offset = ledgerProofLength+32+(8+1+32)+sig1.length+65;
//         copyBytes(proof, sig2offset-64, 64, sessionPubkey, 0);

//         bytes32 sessionPubkeyHash = sha256(sessionPubkey);
//         if (provable_randomDS_args[queryId] == keccak256(abi.encodePacked(commitmentSlice1, sessionPubkeyHash))){ //unonce, nbytes and sessionKeyHash match
//             delete provable_randomDS_args[queryId];
//         } else return false;


//         // Step 5: validity verification for sig1 (keyhash and args signed with the sessionKey)
//         bytes memory tosign1 = new bytes(32+8+1+32);
//         copyBytes(proof, ledgerProofLength, 32+8+1+32, tosign1, 0);
//         if (!verifySig(sha256(tosign1), sig1, sessionPubkey)) return false;

//         // verify if sessionPubkeyHash was verified already, if not.. let's do it!
//         if (provable_randomDS_sessionKeysHashVerified[sessionPubkeyHash] == false){
//             provable_randomDS_sessionKeysHashVerified[sessionPubkeyHash] = provable_randomDS_proofVerify__sessionKeyValidity(proof, sig2offset);
//         }

//         return provable_randomDS_sessionKeysHashVerified[sessionPubkeyHash];
//     }

//     // the following function has been written by Alex Beregszaszi (@axic), use it under the terms of the MIT license
//     function copyBytes(bytes from, uint fromOffset, uint length, bytes to, uint toOffset) internal pure returns (bytes) {
//         uint minLength = length + toOffset;

//         // Buffer too small
//         require(to.length >= minLength); // Should be a better way?

//         // NOTE: the offset 32 is added to skip the `size` field of both bytes variables
//         uint i = 32 + fromOffset;
//         uint j = 32 + toOffset;

//         while (i < (32 + fromOffset + length)) {
//             assembly {
//                 let tmp := mload(add(from, i))
//                 mstore(add(to, j), tmp)
//             }
//             i += 32;
//             j += 32;
//         }

//         return to;
//     }

//     // the following function has been written by Alex Beregszaszi (@axic), use it under the terms of the MIT license
//     // Duplicate Solidity's ecrecover, but catching the CALL return value
//     function safer_ecrecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal returns (bool, address) {
//         // We do our own memory management here. Solidity uses memory offset
//         // 0x40 to store the current end of memory. We write past it (as
//         // writes are memory extensions), but don't update the offset so
//         // Solidity will reuse it. The memory used here is only needed for
//         // this context.

//         // FIXME: inline assembly can't access return values
//         bool ret;
//         address addr;

//         assembly {
//             let size := mload(0x40)
//             mstore(size, hash)
//             mstore(add(size, 32), v)
//             mstore(add(size, 64), r)
//             mstore(add(size, 96), s)

//             // NOTE: we can reuse the request memory because we deal with
//             //       the return code
//             ret := call(3000, 1, 0, size, 128, size, 32)
//             addr := mload(size)
//         }

//         return (ret, addr);
//     }

//     // the following function has been written by Alex Beregszaszi (@axic), use it under the terms of the MIT license
//     function ecrecovery(bytes32 hash, bytes sig) internal returns (bool, address) {
//         bytes32 r;
//         bytes32 s;
//         uint8 v;

//         if (sig.length != 65)
//           return (false, 0);

//         // The signature format is a compact form of:
//         //   {bytes32 r}{bytes32 s}{uint8 v}
//         // Compact means, uint8 is not padded to 32 bytes.
//         assembly {
//             r := mload(add(sig, 32))
//             s := mload(add(sig, 64))

//             // Here we are loading the last 32 bytes. We exploit the fact that
//             // 'mload' will pad with zeroes if we overread.
//             // There is no 'mload8' to do this, but that would be nicer.
//             v := byte(0, mload(add(sig, 96)))

//             // Alternative solution:
//             // 'byte' is not working due to the Solidity parser, so lets
//             // use the second best option, 'and'
//             // v := and(mload(add(sig, 65)), 255)
//         }

//         // albeit non-transactional signatures are not specified by the YP, one would expect it
//         // to match the YP range of [27, 28]
//         //
//         // geth uses [0, 1] and some clients have followed. This might change, see:
//         //  https://github.com/ethereum/go-ethereum/issues/2053
//         if (v < 27)
//           v += 27;

//         if (v != 27 && v != 28)
//             return (false, 0);

//         return safer_ecrecover(hash, v, r, s);
//     }

//     function safeMemoryCleaner() internal pure {
//         assembly {
//             let fmem := mload(0x40)
//             codecopy(fmem, codesize, sub(msize, fmem))
//         }
//     }

// }
// </provableAPI>
contract usingProvable {

    using CBOR for Buffer.buffer;

    ProvableI provable;
    OracleAddrResolverI OAR;

    uint constant day = 60 * 60 * 24;
    uint constant week = 60 * 60 * 24 * 7;
    uint constant month = 60 * 60 * 24 * 30;

    bytes1 constant proofType_NONE = 0x00;
    bytes1 constant proofType_Ledger = 0x30;
    bytes1 constant proofType_Native = 0xF0;
    bytes1 constant proofStorage_IPFS = 0x01;
    bytes1 constant proofType_Android = 0x40;
    bytes1 constant proofType_TLSNotary = 0x10;

    string provable_network_name;
    uint8 constant networkID_auto = 0;
    uint8 constant networkID_morden = 2;
    uint8 constant networkID_mainnet = 1;
    uint8 constant networkID_testnet = 2;
    uint8 constant networkID_consensys = 161;

    mapping(bytes32 => bytes32) provable_randomDS_args;
    mapping(bytes32 => bool) provable_randomDS_sessionKeysHashVerified;

    modifier provableAPI {
        if ((address(OAR) == address(0)) || (getCodeSize(address(OAR)) == 0)) {
            provable_setNetwork(networkID_auto);
        }
        if (address(provable) != OAR.getAddress()) {
            provable = ProvableI(OAR.getAddress());
        }
        _;
    }

    modifier provable_randomDS_proofVerify(bytes32 _queryId, string memory _result, bytes memory _proof) {
        // RandomDS Proof Step 1: The prefix has to match 'LP\x01' (Ledger Proof version 1)
        require((_proof[0] == "L") && (_proof[1] == "P") && (uint8(_proof[2]) == uint8(1)));
        bool proofVerified = provable_randomDS_proofVerify__main(_proof, _queryId, bytes(_result), provable_getNetworkName());
        require(proofVerified);
        _;
    }

    function provable_setNetwork(uint8 _networkID) internal returns (bool _networkSet) {
      _networkID; // NOTE: Silence the warning and remain backwards compatible
      return provable_setNetwork();
    }

    function provable_setNetworkName(string memory _network_name) internal {
        provable_network_name = _network_name;
    }

    function provable_getNetworkName() internal view returns (string memory _networkName) {
        return provable_network_name;
    }

    function provable_setNetwork() internal returns (bool _networkSet) {
        if (getCodeSize(0x1d3B2638a7cC9f2CB3D298A3DA7a90B67E5506ed) > 0) { //mainnet
            OAR = OracleAddrResolverI(0x1d3B2638a7cC9f2CB3D298A3DA7a90B67E5506ed);
            provable_setNetworkName("eth_mainnet");
            return true;
        }
        if (getCodeSize(0xc03A2615D5efaf5F49F60B7BB6583eaec212fdf1) > 0) { //ropsten testnet
            OAR = OracleAddrResolverI(0xc03A2615D5efaf5F49F60B7BB6583eaec212fdf1);
            provable_setNetworkName("eth_ropsten3");
            return true;
        }
        if (getCodeSize(0xB7A07BcF2Ba2f2703b24C0691b5278999C59AC7e) > 0) { //kovan testnet
            OAR = OracleAddrResolverI(0xB7A07BcF2Ba2f2703b24C0691b5278999C59AC7e);
            provable_setNetworkName("eth_kovan");
            return true;
        }
        if (getCodeSize(0x146500cfd35B22E4A392Fe0aDc06De1a1368Ed48) > 0) { //rinkeby testnet
            OAR = OracleAddrResolverI(0x146500cfd35B22E4A392Fe0aDc06De1a1368Ed48);
            provable_setNetworkName("eth_rinkeby");
            return true;
        }
        if (getCodeSize(0xa2998EFD205FB9D4B4963aFb70778D6354ad3A41) > 0) { //goerli testnet
            OAR = OracleAddrResolverI(0xa2998EFD205FB9D4B4963aFb70778D6354ad3A41);
            provable_setNetworkName("eth_goerli");
            return true;
        }
        if (getCodeSize(0x90A0F94702c9630036FB9846B52bf31A1C991a84) > 0){ //bsc mainnet
            OAR = OracleAddrResolverI(0x90A0F94702c9630036FB9846B52bf31A1C991a84);
            provable_setNetworkName("bsc_mainnet");
            return true;
        }
        if (getCodeSize(0x816ec2AF1b56183F82f8C05759E99FEc3c3De609) > 0){ //polygon mainnet
            OAR = OracleAddrResolverI(0x816ec2AF1b56183F82f8C05759E99FEc3c3De609);
            provable_setNetworkName("polygon_mainnet");
            return true;
        }
        if (getCodeSize(0x14B31A1C66a9f3D18DFaC2d123FE8cE5847b7F85) > 0){ //sepolia mainnet
            OAR = OracleAddrResolverI(0x14B31A1C66a9f3D18DFaC2d123FE8cE5847b7F85);
            provable_setNetworkName("sepolia_mainnet");
            return true;
        }
        if (getCodeSize(0x6f485C8BF6fc43eA212E93BBF8ce046C7f1cb475) > 0) { //ethereum-bridge
            OAR = OracleAddrResolverI(0x6f485C8BF6fc43eA212E93BBF8ce046C7f1cb475);
            return true;
        }
        if (getCodeSize(0x20e12A1F859B3FeaE5Fb2A0A32C18F5a65555bBF) > 0) { //ether.camp ide
            OAR = OracleAddrResolverI(0x20e12A1F859B3FeaE5Fb2A0A32C18F5a65555bBF);
            return true;
        }
        if (getCodeSize(0x51efaF4c8B3C9AfBD5aB9F4bbC82784Ab6ef8fAA) > 0) { //browser-solidity
            OAR = OracleAddrResolverI(0x51efaF4c8B3C9AfBD5aB9F4bbC82784Ab6ef8fAA);
            return true;
        }
        return false;
    }

    function provable_getPrice(string memory _datasource) provableAPI internal returns (uint _queryPrice) {
        return provable.getPrice(_datasource);
    }

    function provable_getPrice(string memory _datasource, uint _gasLimit) provableAPI internal returns (uint _queryPrice) {
        return provable.getPrice(_datasource, _gasLimit);
    }

    function provable_query(string memory _datasource, string memory _arg) provableAPI internal returns (bytes32 _id) {
        uint price = provable.getPrice(_datasource);
        if (price > 1 ether + tx.gasprice * 200000) {
            return 0; // Unexpectedly high price
        }
        return provable.query{value: price}(0, _datasource, _arg);
    }

    function provable_query(uint _timestamp, string memory _datasource, string memory _arg) provableAPI internal returns (bytes32 _id) {
        uint price = provable.getPrice(_datasource);
        if (price > 1 ether + tx.gasprice * 200000) {
            return 0; // Unexpectedly high price
        }
        return provable.query{value: price}(_timestamp, _datasource, _arg);
    }

    function provable_query(uint _timestamp, string memory _datasource, string memory _arg, uint _gasLimit) provableAPI internal returns (bytes32 _id) {
        uint price = provable.getPrice(_datasource,_gasLimit);
        if (price > 1 ether + tx.gasprice * _gasLimit) {
            return 0; // Unexpectedly high price
        }
        return provable.query_withGasLimit{value: price}(_timestamp, _datasource, _arg, _gasLimit);
    }

    function provable_query(string memory _datasource, string memory _arg, uint _gasLimit) provableAPI internal returns (bytes32 _id) {
        uint price = provable.getPrice(_datasource, _gasLimit);
        if (price > 1 ether + tx.gasprice * _gasLimit) {
           return 0; // Unexpectedly high price
        }
        return provable.query_withGasLimit{value: price}(0, _datasource, _arg, _gasLimit);
    }

    function provable_query(string memory _datasource, string memory _arg1, string memory _arg2) provableAPI internal returns (bytes32 _id) {
        uint price = provable.getPrice(_datasource);
        if (price > 1 ether + tx.gasprice * 200000) {
            return 0; // Unexpectedly high price
        }
        return provable.query2{value: price}(0, _datasource, _arg1, _arg2);
    }

    function provable_query(uint _timestamp, string memory _datasource, string memory _arg1, string memory _arg2) provableAPI internal returns (bytes32 _id) {
        uint price = provable.getPrice(_datasource);
        if (price > 1 ether + tx.gasprice * 200000) {
            return 0; // Unexpectedly high price
        }
        return provable.query2{value: price}(_timestamp, _datasource, _arg1, _arg2);
    }

    function provable_query(uint _timestamp, string memory _datasource, string memory _arg1, string memory _arg2, uint _gasLimit) provableAPI internal returns (bytes32 _id) {
        uint price = provable.getPrice(_datasource, _gasLimit);
        if (price > 1 ether + tx.gasprice * _gasLimit) {
            return 0; // Unexpectedly high price
        }
        return provable.query2_withGasLimit{value: price}(_timestamp, _datasource, _arg1, _arg2, _gasLimit);
    }

    function provable_query(string memory _datasource, string memory _arg1, string memory _arg2, uint _gasLimit) provableAPI internal returns (bytes32 _id) {
        uint price = provable.getPrice(_datasource, _gasLimit);
        if (price > 1 ether + tx.gasprice * _gasLimit) {
            return 0; // Unexpectedly high price
        }
        return provable.query2_withGasLimit{value: price}(0, _datasource, _arg1, _arg2, _gasLimit);
    }

    function provable_query(string memory _datasource, string[] memory _argN) provableAPI internal returns (bytes32 _id) {
        uint price = provable.getPrice(_datasource);
        if (price > 1 ether + tx.gasprice * 200000) {
            return 0; // Unexpectedly high price
        }
        bytes memory args = stra2cbor(_argN);
        return provable.queryN{value: price}(0, _datasource, args);
    }

    function provable_query(uint _timestamp, string memory _datasource, string[] memory _argN) provableAPI internal returns (bytes32 _id) {
        uint price = provable.getPrice(_datasource);
        if (price > 1 ether + tx.gasprice * 200000) {
            return 0; // Unexpectedly high price
        }
        bytes memory args = stra2cbor(_argN);
        return provable.queryN{value: price}(_timestamp, _datasource, args);
    }

    function provable_query(uint _timestamp, string memory _datasource, string[] memory _argN, uint _gasLimit) provableAPI internal returns (bytes32 _id) {
        uint price = provable.getPrice(_datasource, _gasLimit);
        if (price > 1 ether + tx.gasprice * _gasLimit) {
            return 0; // Unexpectedly high price
        }
        bytes memory args = stra2cbor(_argN);
        return provable.queryN_withGasLimit{value: price}(_timestamp, _datasource, args, _gasLimit);
    }

    function provable_query(string memory _datasource, string[] memory _argN, uint _gasLimit) provableAPI internal returns (bytes32 _id) {
        uint price = provable.getPrice(_datasource, _gasLimit);
        if (price > 1 ether + tx.gasprice * _gasLimit) {
            return 0; // Unexpectedly high price
        }
        bytes memory args = stra2cbor(_argN);
        return provable.queryN_withGasLimit{value: price}(0, _datasource, args, _gasLimit);
    }

    function provable_query(string memory _datasource, string[1] memory _args) provableAPI internal returns (bytes32 _id) {
        string[] memory dynargs = new string[](1);
        dynargs[0] = _args[0];
        return provable_query(_datasource, dynargs);
    }

    function provable_query(uint _timestamp, string memory _datasource, string[1] memory _args) provableAPI internal returns (bytes32 _id) {
        string[] memory dynargs = new string[](1);
        dynargs[0] = _args[0];
        return provable_query(_timestamp, _datasource, dynargs);
    }

    function provable_query(uint _timestamp, string memory _datasource, string[1] memory _args, uint _gasLimit) provableAPI internal returns (bytes32 _id) {
        string[] memory dynargs = new string[](1);
        dynargs[0] = _args[0];
        return provable_query(_timestamp, _datasource, dynargs, _gasLimit);
    }

    function provable_query(string memory _datasource, string[1] memory _args, uint _gasLimit) provableAPI internal returns (bytes32 _id) {
        string[] memory dynargs = new string[](1);
        dynargs[0] = _args[0];
        return provable_query(_datasource, dynargs, _gasLimit);
    }

    function provable_query(string memory _datasource, string[2] memory _args) provableAPI internal returns (bytes32 _id) {
        string[] memory dynargs = new string[](2);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        return provable_query(_datasource, dynargs);
    }

    function provable_query(uint _timestamp, string memory _datasource, string[2] memory _args) provableAPI internal returns (bytes32 _id) {
        string[] memory dynargs = new string[](2);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        return provable_query(_timestamp, _datasource, dynargs);
    }

    function provable_query(uint _timestamp, string memory _datasource, string[2] memory _args, uint _gasLimit) provableAPI internal returns (bytes32 _id) {
        string[] memory dynargs = new string[](2);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        return provable_query(_timestamp, _datasource, dynargs, _gasLimit);
    }

    function provable_query(string memory _datasource, string[2] memory _args, uint _gasLimit) provableAPI internal returns (bytes32 _id) {
        string[] memory dynargs = new string[](2);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        return provable_query(_datasource, dynargs, _gasLimit);
    }

    function provable_query(string memory _datasource, string[3] memory _args) provableAPI internal returns (bytes32 _id) {
        string[] memory dynargs = new string[](3);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        dynargs[2] = _args[2];
        return provable_query(_datasource, dynargs);
    }

    function provable_query(uint _timestamp, string memory _datasource, string[3] memory _args) provableAPI internal returns (bytes32 _id) {
        string[] memory dynargs = new string[](3);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        dynargs[2] = _args[2];
        return provable_query(_timestamp, _datasource, dynargs);
    }

    function provable_query(uint _timestamp, string memory _datasource, string[3] memory _args, uint _gasLimit) provableAPI internal returns (bytes32 _id) {
        string[] memory dynargs = new string[](3);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        dynargs[2] = _args[2];
        return provable_query(_timestamp, _datasource, dynargs, _gasLimit);
    }

    function provable_query(string memory _datasource, string[3] memory _args, uint _gasLimit) provableAPI internal returns (bytes32 _id) {
        string[] memory dynargs = new string[](3);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        dynargs[2] = _args[2];
        return provable_query(_datasource, dynargs, _gasLimit);
    }

    function provable_query(string memory _datasource, string[4] memory _args) provableAPI internal returns (bytes32 _id) {
        string[] memory dynargs = new string[](4);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        dynargs[2] = _args[2];
        dynargs[3] = _args[3];
        return provable_query(_datasource, dynargs);
    }

    function provable_query(uint _timestamp, string memory _datasource, string[4] memory _args) provableAPI internal returns (bytes32 _id) {
        string[] memory dynargs = new string[](4);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        dynargs[2] = _args[2];
        dynargs[3] = _args[3];
        return provable_query(_timestamp, _datasource, dynargs);
    }

    function provable_query(uint _timestamp, string memory _datasource, string[4] memory _args, uint _gasLimit) provableAPI internal returns (bytes32 _id) {
        string[] memory dynargs = new string[](4);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        dynargs[2] = _args[2];
        dynargs[3] = _args[3];
        return provable_query(_timestamp, _datasource, dynargs, _gasLimit);
    }

    function provable_query(string memory _datasource, string[4] memory _args, uint _gasLimit) provableAPI internal returns (bytes32 _id) {
        string[] memory dynargs = new string[](4);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        dynargs[2] = _args[2];
        dynargs[3] = _args[3];
        return provable_query(_datasource, dynargs, _gasLimit);
    }

    function provable_query(string memory _datasource, string[5] memory _args) provableAPI internal returns (bytes32 _id) {
        string[] memory dynargs = new string[](5);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        dynargs[2] = _args[2];
        dynargs[3] = _args[3];
        dynargs[4] = _args[4];
        return provable_query(_datasource, dynargs);
    }

    function provable_query(uint _timestamp, string memory _datasource, string[5] memory _args) provableAPI internal returns (bytes32 _id) {
        string[] memory dynargs = new string[](5);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        dynargs[2] = _args[2];
        dynargs[3] = _args[3];
        dynargs[4] = _args[4];
        return provable_query(_timestamp, _datasource, dynargs);
    }

    function provable_query(uint _timestamp, string memory _datasource, string[5] memory _args, uint _gasLimit) provableAPI internal returns (bytes32 _id) {
        string[] memory dynargs = new string[](5);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        dynargs[2] = _args[2];
        dynargs[3] = _args[3];
        dynargs[4] = _args[4];
        return provable_query(_timestamp, _datasource, dynargs, _gasLimit);
    }

    function provable_query(string memory _datasource, string[5] memory _args, uint _gasLimit) provableAPI internal returns (bytes32 _id) {
        string[] memory dynargs = new string[](5);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        dynargs[2] = _args[2];
        dynargs[3] = _args[3];
        dynargs[4] = _args[4];
        return provable_query(_datasource, dynargs, _gasLimit);
    }

    function provable_query(string memory _datasource, bytes[] memory _argN) provableAPI internal returns (bytes32 _id) {
        uint price = provable.getPrice(_datasource);
        if (price > 1 ether + tx.gasprice * 200000) {
            return 0; // Unexpectedly high price
        }
        bytes memory args = ba2cbor(_argN);
        return provable.queryN{value: price}(0, _datasource, args);
    }

    function provable_query(uint _timestamp, string memory _datasource, bytes[] memory _argN) provableAPI internal returns (bytes32 _id) {
        uint price = provable.getPrice(_datasource);
        if (price > 1 ether + tx.gasprice * 200000) {
            return 0; // Unexpectedly high price
        }
        bytes memory args = ba2cbor(_argN);
        return provable.queryN{value: price}(_timestamp, _datasource, args);
    }

    function provable_query(uint _timestamp, string memory _datasource, bytes[] memory _argN, uint _gasLimit) provableAPI internal returns (bytes32 _id) {
        uint price = provable.getPrice(_datasource, _gasLimit);
        if (price > 1 ether + tx.gasprice * _gasLimit) {
            return 0; // Unexpectedly high price
        }
        bytes memory args = ba2cbor(_argN);
        return provable.queryN_withGasLimit{value: price}(_timestamp, _datasource, args, _gasLimit);
    }

    function provable_query(string memory _datasource, bytes[] memory _argN, uint _gasLimit) provableAPI internal returns (bytes32 _id) {
        uint price = provable.getPrice(_datasource, _gasLimit);
        if (price > 1 ether + tx.gasprice * _gasLimit) {
            return 0; // Unexpectedly high price
        }
        bytes memory args = ba2cbor(_argN);
        return provable.queryN_withGasLimit{value: price}(0, _datasource, args, _gasLimit);
    }

    function provable_query(string memory _datasource, bytes[1] memory _args) provableAPI internal returns (bytes32 _id) {
        bytes[] memory dynargs = new bytes[](1);
        dynargs[0] = _args[0];
        return provable_query(_datasource, dynargs);
    }

    function provable_query(uint _timestamp, string memory _datasource, bytes[1] memory _args) provableAPI internal returns (bytes32 _id) {
        bytes[] memory dynargs = new bytes[](1);
        dynargs[0] = _args[0];
        return provable_query(_timestamp, _datasource, dynargs);
    }

    function provable_query(uint _timestamp, string memory _datasource, bytes[1] memory _args, uint _gasLimit) provableAPI internal returns (bytes32 _id) {
        bytes[] memory dynargs = new bytes[](1);
        dynargs[0] = _args[0];
        return provable_query(_timestamp, _datasource, dynargs, _gasLimit);
    }

    function provable_query(string memory _datasource, bytes[1] memory _args, uint _gasLimit) provableAPI internal returns (bytes32 _id) {
        bytes[] memory dynargs = new bytes[](1);
        dynargs[0] = _args[0];
        return provable_query(_datasource, dynargs, _gasLimit);
    }

    function provable_query(string memory _datasource, bytes[2] memory _args) provableAPI internal returns (bytes32 _id) {
        bytes[] memory dynargs = new bytes[](2);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        return provable_query(_datasource, dynargs);
    }

    function provable_query(uint _timestamp, string memory _datasource, bytes[2] memory _args) provableAPI internal returns (bytes32 _id) {
        bytes[] memory dynargs = new bytes[](2);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        return provable_query(_timestamp, _datasource, dynargs);
    }

    function provable_query(uint _timestamp, string memory _datasource, bytes[2] memory _args, uint _gasLimit) provableAPI internal returns (bytes32 _id) {
        bytes[] memory dynargs = new bytes[](2);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        return provable_query(_timestamp, _datasource, dynargs, _gasLimit);
    }

    function provable_query(string memory _datasource, bytes[2] memory _args, uint _gasLimit) provableAPI internal returns (bytes32 _id) {
        bytes[] memory dynargs = new bytes[](2);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        return provable_query(_datasource, dynargs, _gasLimit);
    }

    function provable_query(string memory _datasource, bytes[3] memory _args) provableAPI internal returns (bytes32 _id) {
        bytes[] memory dynargs = new bytes[](3);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        dynargs[2] = _args[2];
        return provable_query(_datasource, dynargs);
    }

    function provable_query(uint _timestamp, string memory _datasource, bytes[3] memory _args) provableAPI internal returns (bytes32 _id) {
        bytes[] memory dynargs = new bytes[](3);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        dynargs[2] = _args[2];
        return provable_query(_timestamp, _datasource, dynargs);
    }

    function provable_query(uint _timestamp, string memory _datasource, bytes[3] memory _args, uint _gasLimit) provableAPI internal returns (bytes32 _id) {
        bytes[] memory dynargs = new bytes[](3);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        dynargs[2] = _args[2];
        return provable_query(_timestamp, _datasource, dynargs, _gasLimit);
    }

    function provable_query(string memory _datasource, bytes[3] memory _args, uint _gasLimit) provableAPI internal returns (bytes32 _id) {
        bytes[] memory dynargs = new bytes[](3);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        dynargs[2] = _args[2];
        return provable_query(_datasource, dynargs, _gasLimit);
    }

    function provable_query(string memory _datasource, bytes[4] memory _args) provableAPI internal returns (bytes32 _id) {
        bytes[] memory dynargs = new bytes[](4);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        dynargs[2] = _args[2];
        dynargs[3] = _args[3];
        return provable_query(_datasource, dynargs);
    }

    function provable_query(uint _timestamp, string memory _datasource, bytes[4] memory _args) provableAPI internal returns (bytes32 _id) {
        bytes[] memory dynargs = new bytes[](4);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        dynargs[2] = _args[2];
        dynargs[3] = _args[3];
        return provable_query(_timestamp, _datasource, dynargs);
    }

    function provable_query(uint _timestamp, string memory _datasource, bytes[4] memory _args, uint _gasLimit) provableAPI internal returns (bytes32 _id) {
        bytes[] memory dynargs = new bytes[](4);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        dynargs[2] = _args[2];
        dynargs[3] = _args[3];
        return provable_query(_timestamp, _datasource, dynargs, _gasLimit);
    }

    function provable_query(string memory _datasource, bytes[4] memory _args, uint _gasLimit) provableAPI internal returns (bytes32 _id) {
        bytes[] memory dynargs = new bytes[](4);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        dynargs[2] = _args[2];
        dynargs[3] = _args[3];
        return provable_query(_datasource, dynargs, _gasLimit);
    }

    function provable_query(string memory _datasource, bytes[5] memory _args) provableAPI internal returns (bytes32 _id) {
        bytes[] memory dynargs = new bytes[](5);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        dynargs[2] = _args[2];
        dynargs[3] = _args[3];
        dynargs[4] = _args[4];
        return provable_query(_datasource, dynargs);
    }

    function provable_query(uint _timestamp, string memory _datasource, bytes[5] memory _args) provableAPI internal returns (bytes32 _id) {
        bytes[] memory dynargs = new bytes[](5);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        dynargs[2] = _args[2];
        dynargs[3] = _args[3];
        dynargs[4] = _args[4];
        return provable_query(_timestamp, _datasource, dynargs);
    }

    function provable_query(uint _timestamp, string memory _datasource, bytes[5] memory _args, uint _gasLimit) provableAPI internal returns (bytes32 _id) {
        bytes[] memory dynargs = new bytes[](5);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        dynargs[2] = _args[2];
        dynargs[3] = _args[3];
        dynargs[4] = _args[4];
        return provable_query(_timestamp, _datasource, dynargs, _gasLimit);
    }

    function provable_query(string memory _datasource, bytes[5] memory _args, uint _gasLimit) provableAPI internal returns (bytes32 _id) {
        bytes[] memory dynargs = new bytes[](5);
        dynargs[0] = _args[0];
        dynargs[1] = _args[1];
        dynargs[2] = _args[2];
        dynargs[3] = _args[3];
        dynargs[4] = _args[4];
        return provable_query(_datasource, dynargs, _gasLimit);
    }

    function provable_setProof(bytes1 _proofP) provableAPI internal {
        return provable.setProofType(_proofP);
    }


    function provable_cbAddress() provableAPI internal returns (address _callbackAddress) {
        return provable.cbAddress();
    }

    function getCodeSize(address _addr) view internal returns (uint _size) {
        assembly {
            _size := extcodesize(_addr)
        }
    }

    function provable_setCustomGasPrice(uint _gasPrice) provableAPI internal {
        return provable.setCustomGasPrice(_gasPrice);
    }

    function provable_randomDS_getSessionPubKeyHash() provableAPI internal returns (bytes32 _sessionKeyHash) {
        return provable.randomDS_getSessionPubKeyHash();
    }

    function parseAddr(string memory _a) internal pure returns (address _parsedAddress) {
        bytes memory tmp = bytes(_a);
        uint160 iaddr = 0;
        uint160 b1;
        uint160 b2;
        for (uint i = 2; i < 2 + 2 * 20; i += 2) {
            iaddr *= 256;
            b1 = uint160(uint8(tmp[i]));
            b2 = uint160(uint8(tmp[i + 1]));
            if ((b1 >= 97) && (b1 <= 102)) {
                b1 -= 87;
            } else if ((b1 >= 65) && (b1 <= 70)) {
                b1 -= 55;
            } else if ((b1 >= 48) && (b1 <= 57)) {
                b1 -= 48;
            }
            if ((b2 >= 97) && (b2 <= 102)) {
                b2 -= 87;
            } else if ((b2 >= 65) && (b2 <= 70)) {
                b2 -= 55;
            } else if ((b2 >= 48) && (b2 <= 57)) {
                b2 -= 48;
            }
            iaddr += (b1 * 16 + b2);
        }
        return address(iaddr);
    }

    function strCompare(string memory _a, string memory _b) internal pure returns (int _returnCode) {
        bytes memory a = bytes(_a);
        bytes memory b = bytes(_b);
        uint minLength = a.length;
        if (b.length < minLength) {
            minLength = b.length;
        }
        for (uint i = 0; i < minLength; i ++) {
            if (a[i] < b[i]) {
                return -1;
            } else if (a[i] > b[i]) {
                return 1;
            }
        }
        if (a.length < b.length) {
            return -1;
        } else if (a.length > b.length) {
            return 1;
        } else {
            return 0;
        }
    }

    function indexOf(string memory _haystack, string memory _needle) internal pure returns (int _returnCode) {
        bytes memory h = bytes(_haystack);
        bytes memory n = bytes(_needle);
        if (h.length < 1 || n.length < 1 || (n.length > h.length)) {
            return -1;
        } else if (h.length > (2 ** 128 - 1)) {
            return -1;
        } else {
            uint subindex = 0;
            for (uint i = 0; i < h.length; i++) {
                if (h[i] == n[0]) {
                    subindex = 1;
                    while(subindex < n.length && (i + subindex) < h.length && h[i + subindex] == n[subindex]) {
                        subindex++;
                    }
                    if (subindex == n.length) {
                        return int(i);
                    }
                }
            }
            return -1;
        }
    }

    function strConcat(string memory _a, string memory _b) internal pure returns (string memory _concatenatedString) {
        return strConcat(_a, _b, "", "", "");
    }

    function strConcat(string memory _a, string memory _b, string memory _c) internal pure returns (string memory _concatenatedString) {
        return strConcat(_a, _b, _c, "", "");
    }

    function strConcat(string memory _a, string memory _b, string memory _c, string memory _d) internal pure returns (string memory _concatenatedString) {
        return strConcat(_a, _b, _c, _d, "");
    }

    function strConcat(string memory _a, string memory _b, string memory _c, string memory _d, string memory _e) internal pure returns (string memory _concatenatedString) {
        bytes memory _ba = bytes(_a);
        bytes memory _bb = bytes(_b);
        bytes memory _bc = bytes(_c);
        bytes memory _bd = bytes(_d);
        bytes memory _be = bytes(_e);
        string memory abcde = new string(_ba.length + _bb.length + _bc.length + _bd.length + _be.length);
        bytes memory babcde = bytes(abcde);
        uint k = 0;
        uint i = 0;
        for (i = 0; i < _ba.length; i++) {
            babcde[k++] = _ba[i];
        }
        for (i = 0; i < _bb.length; i++) {
            babcde[k++] = _bb[i];
        }
        for (i = 0; i < _bc.length; i++) {
            babcde[k++] = _bc[i];
        }
        for (i = 0; i < _bd.length; i++) {
            babcde[k++] = _bd[i];
        }
        for (i = 0; i < _be.length; i++) {
            babcde[k++] = _be[i];
        }
        return string(babcde);
    }

    function safeParseInt(string memory _a) internal pure returns (uint _parsedInt) {
        return safeParseInt(_a, 0);
    }

    function safeParseInt(string memory _a, uint _b) internal pure returns (uint _parsedInt) {
        bytes memory bresult = bytes(_a);
        uint mint = 0;
        bool decimals = false;
        for (uint i = 0; i < bresult.length; i++) {
            if ((uint(uint8(bresult[i])) >= 48) && (uint(uint8(bresult[i])) <= 57)) {
                if (decimals) {
                   if (_b == 0) break;
                    else _b--;
                }
                mint *= 10;
                mint += uint(uint8(bresult[i])) - 48;
            } else if (uint(uint8(bresult[i])) == 46) {
                require(!decimals, 'More than one decimal encountered in string!');
                decimals = true;
            } else {
                revert("Non-numeral character encountered in string!");
            }
        }
        if (_b > 0) {
            mint *= 10 ** _b;
        }
        return mint;
    }

    function parseInt(string memory _a) internal pure returns (uint _parsedInt) {
        return parseInt(_a, 0);
    }

    function parseInt(string memory _a, uint _b) internal pure returns (uint _parsedInt) {
        bytes memory bresult = bytes(_a);
        uint mint = 0;
        bool decimals = false;
        for (uint i = 0; i < bresult.length; i++) {
            if ((uint(uint8(bresult[i])) >= 48) && (uint(uint8(bresult[i])) <= 57)) {
                if (decimals) {
                   if (_b == 0) {
                       break;
                   } else {
                       _b--;
                   }
                }
                mint *= 10;
                mint += uint(uint8(bresult[i])) - 48;
            } else if (uint(uint8(bresult[i])) == 46) {
                decimals = true;
            }
        }
        if (_b > 0) {
            mint *= 10 ** _b;
        }
        return mint;
    }

    function uint2str(uint _i) internal pure returns (string memory _uintAsString) {
        if (_i == 0) {
            return "0";
        }
        uint j = _i;
        uint len;
        while (j != 0) {
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint k = len - 1;
        while (_i != 0) {
            bstr[k--] = bytes1(uint8(48 + _i % 10));
            _i /= 10;
        }
        return string(bstr);
    }

    function stra2cbor(string[] memory _arr) internal pure returns (bytes memory _cborEncoding) {
        safeMemoryCleaner();
        Buffer.buffer memory buf;
        Buffer.init(buf, 1024);
        buf.startArray();
        for (uint i = 0; i < _arr.length; i++) {
            buf.encodeString(_arr[i]);
        }
        buf.endSequence();
        return buf.buf;
    }

    function ba2cbor(bytes[] memory _arr) internal pure returns (bytes memory _cborEncoding) {
        safeMemoryCleaner();
        Buffer.buffer memory buf;
        Buffer.init(buf, 1024);
        buf.startArray();
        for (uint i = 0; i < _arr.length; i++) {
            buf.encodeBytes(_arr[i]);
        }
        buf.endSequence();
        return buf.buf;
    }

    function provable_newRandomDSQuery(uint _delay, uint _nbytes, uint _customGasLimit) internal returns (bytes32 _queryId) {
        require((_nbytes > 0) && (_nbytes <= 32));
        _delay *= 10; // Convert from seconds to ledger timer ticks
        bytes memory nbytes = new bytes(1);
        nbytes[0] = bytes1(uint8(_nbytes));
        bytes memory unonce = new bytes(32);
        bytes memory sessionKeyHash = new bytes(32);
        bytes32 sessionKeyHash_bytes32 = provable_randomDS_getSessionPubKeyHash();
        assembly {
            mstore(unonce, 0x20)
            /*
             The following variables can be relaxed.
             Check the relaxed random contract at https://github.com/oraclize/ethereum-examples
             for an idea on how to override and replace commit hash variables.
            */
            mstore(add(unonce, 0x20), xor(blockhash(sub(number(), 1)), xor(coinbase(), timestamp())))
            mstore(sessionKeyHash, 0x20)
            mstore(add(sessionKeyHash, 0x20), sessionKeyHash_bytes32)
        }
        bytes memory delay = new bytes(32);
        assembly {
            mstore(add(delay, 0x20), _delay)
        }
        bytes memory delay_bytes8 = new bytes(8);
        copyBytes(delay, 24, 8, delay_bytes8, 0);
        bytes[4] memory args = [unonce, nbytes, sessionKeyHash, delay];
        bytes32 queryId = provable_query("random", args, _customGasLimit);
        bytes memory delay_bytes8_left = new bytes(8);
        assembly {
            let x := mload(add(delay_bytes8, 0x20))
            mstore8(add(delay_bytes8_left, 0x27), div(x, 0x100000000000000000000000000000000000000000000000000000000000000))
            mstore8(add(delay_bytes8_left, 0x26), div(x, 0x1000000000000000000000000000000000000000000000000000000000000))
            mstore8(add(delay_bytes8_left, 0x25), div(x, 0x10000000000000000000000000000000000000000000000000000000000))
            mstore8(add(delay_bytes8_left, 0x24), div(x, 0x100000000000000000000000000000000000000000000000000000000))
            mstore8(add(delay_bytes8_left, 0x23), div(x, 0x1000000000000000000000000000000000000000000000000000000))
            mstore8(add(delay_bytes8_left, 0x22), div(x, 0x10000000000000000000000000000000000000000000000000000))
            mstore8(add(delay_bytes8_left, 0x21), div(x, 0x100000000000000000000000000000000000000000000000000))
            mstore8(add(delay_bytes8_left, 0x20), div(x, 0x1000000000000000000000000000000000000000000000000))
        }
        provable_randomDS_setCommitment(queryId, keccak256(abi.encodePacked(delay_bytes8_left, args[1], sha256(args[0]), args[2])));
        return queryId;
    }

    function provable_randomDS_setCommitment(bytes32 _queryId, bytes32 _commitment) internal {
        provable_randomDS_args[_queryId] = _commitment;
    }

    function verifySig(bytes32 _tosignh, bytes memory _dersig, bytes memory _pubkey) internal returns (bool _sigVerified) {
        bool sigok;
        address signer;
        bytes32 sigr;
        bytes32 sigs;
        bytes memory sigr_ = new bytes(32);
        uint offset = 4 + (uint(uint8(_dersig[3])) - 0x20);
        sigr_ = copyBytes(_dersig, offset, 32, sigr_, 0);
        bytes memory sigs_ = new bytes(32);
        offset += 32 + 2;
        sigs_ = copyBytes(_dersig, offset + (uint(uint8(_dersig[offset - 1])) - 0x20), 32, sigs_, 0);
        assembly {
            sigr := mload(add(sigr_, 32))
            sigs := mload(add(sigs_, 32))
        }
        (sigok, signer) = safer_ecrecover(_tosignh, 27, sigr, sigs);
        if (address(uint160(uint256(keccak256(_pubkey)))) == signer) {
            return true;
        } else {
            (sigok, signer) = safer_ecrecover(_tosignh, 28, sigr, sigs);
            return (address(uint160(uint256(keccak256(_pubkey)))) == signer);
        }
    }

    function provable_randomDS_proofVerify__sessionKeyValidity(bytes memory _proof, uint _sig2offset) internal returns (bool _proofVerified) {
        bool sigok;
        // Random DS Proof Step 6: Verify the attestation signature, APPKEY1 must sign the sessionKey from the correct ledger app (CODEHASH)
        bytes memory sig2 = new bytes(uint(uint8(_proof[_sig2offset + 1])) + 2);
        copyBytes(_proof, _sig2offset, sig2.length, sig2, 0);
        bytes memory appkey1_pubkey = new bytes(64);
        copyBytes(_proof, 3 + 1, 64, appkey1_pubkey, 0);
        bytes memory tosign2 = new bytes(1 + 65 + 32);
        tosign2[0] = bytes1(uint8(1)); //role
        copyBytes(_proof, _sig2offset - 65, 65, tosign2, 1);
        bytes memory CODEHASH = hex"fd94fa71bc0ba10d39d464d0d8f465efeef0a2764e3887fcc9df41ded20f505c";
        copyBytes(CODEHASH, 0, 32, tosign2, 1 + 65);
        sigok = verifySig(sha256(tosign2), sig2, appkey1_pubkey);
        if (!sigok) {
            return false;
        }
        // Random DS Proof Step 7: Verify the APPKEY1 provenance (must be signed by Ledger)
        bytes memory LEDGERKEY = hex"7fb956469c5c9b89840d55b43537e66a98dd4811ea0a27224272c2e5622911e8537a2f8e86a46baec82864e98dd01e9ccc2f8bc5dfc9cbe5a91a290498dd96e4";
        bytes memory tosign3 = new bytes(1 + 65);
        tosign3[0] = 0xFE;
        copyBytes(_proof, 3, 65, tosign3, 1);
        bytes memory sig3 = new bytes(uint(uint8(_proof[3 + 65 + 1])) + 2);
        copyBytes(_proof, 3 + 65, sig3.length, sig3, 0);
        sigok = verifySig(sha256(tosign3), sig3, LEDGERKEY);
        return sigok;
    }

    function provable_randomDS_proofVerify__returnCode(bytes32 _queryId, string memory _result, bytes memory _proof) internal returns (uint8 _returnCode) {
        // Random DS Proof Step 1: The prefix has to match 'LP\x01' (Ledger Proof version 1)
        if ((_proof[0] != "L") || (_proof[1] != "P") || (uint8(_proof[2]) != uint8(1))) {
            return 1;
        }
        bool proofVerified = provable_randomDS_proofVerify__main(_proof, _queryId, bytes(_result), provable_getNetworkName());
        if (!proofVerified) {
            return 2;
        }
        return 0;
    }

    function matchBytes32Prefix(bytes32 _content, bytes memory _prefix, uint _nRandomBytes) internal pure returns (bool _matchesPrefix) {
        bool match_ = true;
        require(_prefix.length == _nRandomBytes);
        for (uint256 i = 0; i< _nRandomBytes; i++) {
            if (_content[i] != _prefix[i]) {
                match_ = false;
            }
        }
        return match_;
    }

    function provable_randomDS_proofVerify__main(bytes memory _proof, bytes32 _queryId, bytes memory _result, string memory _contextName) internal returns (bool _proofVerified) {
        // Random DS Proof Step 2: The unique keyhash has to match with the sha256 of (context name + _queryId)
        uint ledgerProofLength = 3 + 65 + (uint(uint8(_proof[3 + 65 + 1])) + 2) + 32;
        bytes memory keyhash = new bytes(32);
        copyBytes(_proof, ledgerProofLength, 32, keyhash, 0);
        if (!(keccak256(keyhash) == keccak256(abi.encodePacked(sha256(abi.encodePacked(_contextName, _queryId)))))) {
            return false;
        }
        bytes memory sig1 = new bytes(uint(uint8(_proof[ledgerProofLength + (32 + 8 + 1 + 32) + 1])) + 2);
        copyBytes(_proof, ledgerProofLength + (32 + 8 + 1 + 32), sig1.length, sig1, 0);
        // Random DS Proof Step 3: We assume sig1 is valid (it will be verified during step 5) and we verify if '_result' is the _prefix of sha256(sig1)
        if (!matchBytes32Prefix(sha256(sig1), _result, uint(uint8(_proof[ledgerProofLength + 32 + 8])))) {
            return false;
        }
        // Random DS Proof Step 4: Commitment match verification, keccak256(delay, nbytes, unonce, sessionKeyHash) == commitment in storage.
        // This is to verify that the computed args match with the ones specified in the query.
        bytes memory commitmentSlice1 = new bytes(8 + 1 + 32);
        copyBytes(_proof, ledgerProofLength + 32, 8 + 1 + 32, commitmentSlice1, 0);
        bytes memory sessionPubkey = new bytes(64);
        uint sig2offset = ledgerProofLength + 32 + (8 + 1 + 32) + sig1.length + 65;
        copyBytes(_proof, sig2offset - 64, 64, sessionPubkey, 0);
        bytes32 sessionPubkeyHash = sha256(sessionPubkey);
        if (provable_randomDS_args[_queryId] == keccak256(abi.encodePacked(commitmentSlice1, sessionPubkeyHash))) { //unonce, nbytes and sessionKeyHash match
            delete provable_randomDS_args[_queryId];
        } else return false;
        // Random DS Proof Step 5: Validity verification for sig1 (keyhash and args signed with the sessionKey)
        bytes memory tosign1 = new bytes(32 + 8 + 1 + 32);
        copyBytes(_proof, ledgerProofLength, 32 + 8 + 1 + 32, tosign1, 0);
        if (!verifySig(sha256(tosign1), sig1, sessionPubkey)) {
            return false;
        }
        // Verify if sessionPubkeyHash was verified already, if not.. let's do it!
        if (!provable_randomDS_sessionKeysHashVerified[sessionPubkeyHash]) {
            provable_randomDS_sessionKeysHashVerified[sessionPubkeyHash] = provable_randomDS_proofVerify__sessionKeyValidity(_proof, sig2offset);
        }
        return provable_randomDS_sessionKeysHashVerified[sessionPubkeyHash];
    }
    /*
     The following function has been written by Alex Beregszaszi (@axic), use it under the terms of the MIT license
    */
    function copyBytes(bytes memory _from, uint _fromOffset, uint _length, bytes memory _to, uint _toOffset) internal pure returns (bytes memory _copiedBytes) {
        uint minLength = _length + _toOffset;
        require(_to.length >= minLength); // Buffer too small. Should be a better way?
        uint i = 32 + _fromOffset; // NOTE: the offset 32 is added to skip the `size` field of both bytes variables
        uint j = 32 + _toOffset;
        while (i < (32 + _fromOffset + _length)) {
            assembly {
                let tmp := mload(add(_from, i))
                mstore(add(_to, j), tmp)
            }
            i += 32;
            j += 32;
        }
        return _to;
    }
    /*
     The following function has been written by Alex Beregszaszi (@axic), use it under the terms of the MIT license
     Duplicate Solidity's ecrecover, but catching the CALL return value
    */
    function safer_ecrecover(bytes32 _hash, uint8 _v, bytes32 _r, bytes32 _s) internal returns (bool _success, address _recoveredAddress) {
        /*
         We do our own memory management here. Solidity uses memory offset
         0x40 to store the current end of memory. We write past it (as
         writes are memory extensions), but don't update the offset so
         Solidity will reuse it. The memory used here is only needed for
         this context.
         FIXME: inline assembly can't access return values
        */
        bool ret;
        address addr;
        assembly {
            let size := mload(0x40)
            mstore(size, _hash)
            mstore(add(size, 32), _v)
            mstore(add(size, 64), _r)
            mstore(add(size, 96), _s)
            ret := call(3000, 1, 0, size, 128, size, 32) // NOTE: we can reuse the request memory because we deal with the return code.
            addr := mload(size)
        }
        return (ret, addr);
    }
    /*
     The following function has been written by Alex Beregszaszi (@axic), use it under the terms of the MIT license
    */
    function ecrecovery(bytes32 _hash, bytes memory _sig) internal returns (bool _success, address _recoveredAddress) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        if (_sig.length != 65) {
            return (false, address(0));
        }
        /*
         The signature format is a compact form of:
           {bytes32 r}{bytes32 s}{uint8 v}
         Compact means, uint8 is not padded to 32 bytes.
        */
        assembly {
            r := mload(add(_sig, 32))
            s := mload(add(_sig, 64))
            /*
             Here we are loading the last 32 bytes. We exploit the fact that
             'mload' will pad with zeroes if we overread.
             There is no 'mload8' to do this, but that would be nicer.
            */
            v := byte(0, mload(add(_sig, 96)))
            /*
              Alternative solution:
              'byte' is not working due to the Solidity parser, so lets
              use the second best option, 'and'
              v := and(mload(add(_sig, 65)), 255)
            */
        }
        /*
         albeit non-transactional signatures are not specified by the YP, one would expect it
         to match the YP range of [27, 28]
         geth uses [0, 1] and some clients have followed. This might change, see:
         https://github.com/ethereum/go-ethereum/issues/2053
        */
        if (v < 27) {
            v += 27;
        }
        if (v != 27 && v != 28) {
            return (false, address(0));
        }
        return safer_ecrecover(_hash, v, r, s);
    }

    function safeMemoryCleaner() internal pure {
        assembly {
            let fmem := mload(0x40)
            codecopy(fmem, codesize(), sub(msize(), fmem))
        }
    }
}