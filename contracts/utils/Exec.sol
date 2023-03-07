// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.5 <0.9.0;

// solhint-disable no-inline-assembly

/**
 * Utility functions helpful when making different kinds of contract calls in Solidity.
 */
library Exec {

    function call(
        address to,
        uint256 value,
        bytes memory data,
        uint256 txGas
    ) internal returns (bool success) {
        assembly {
            // 提供txGas，value，执行to地址的，calldata为mem[32: 32+data.size]
            success := call(txGas, to, value, add(data, 0x20), mload(data), 0, 0)
        }
    }

    function staticcall(
        address to,
        bytes memory data,
        uint256 txGas
    ) internal view returns (bool success) {
        assembly {
            success := staticcall(txGas, to, add(data, 0x20), mload(data), 0, 0)
        }
    }

    function delegateCall(
        address to,
        bytes memory data,
        uint256 txGas
    ) internal returns (bool success) {
        assembly {
            success := delegatecall(txGas, to, add(data, 0x20), mload(data), 0, 0)
        }
    }

    // get returned data from last call or calldelegate
    // 返回数据
    function getReturnData(uint256 maxLen) internal pure returns (bytes memory returnData) {
        assembly {
            // 获取返回数据大小
            let len := returndatasize()
            // 如果len > maxLen; len = maxLen
            if gt(len, maxLen) {
                len := maxLen
            }
            // 空闲内存指针
            let ptr := mload(0x40)
            // 存储分配的内存大小
            mstore(0x40, add(ptr, add(len, 0x20)))
            // 内存存储一字节数据，数据为len
            mstore(ptr, len)
            // 从0开始，复制len长度的字节到内存位置1
            returndatacopy(add(ptr, 0x20), 0, len)
            // 返回数据指针
            returnData := ptr
        }
    }

    // revert with explicit byte array (probably reverted info from call)
    function revertWithData(bytes memory returnData) internal pure {
        assembly {
            revert(add(returnData, 32), mload(returnData))
        }
    }

    function callAndRevert(address to, bytes memory data, uint256 maxLen) internal {
        bool success = call(to,0,data,gasleft());
        if (!success) {
            revertWithData(getReturnData(maxLen));
        }
    }
}
