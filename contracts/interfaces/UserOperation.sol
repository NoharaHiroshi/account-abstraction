// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

/* solhint-disable no-inline-assembly */

    /**
     * User Operation struct
     * @param sender 此请求的发件人帐户。
     * @param nonce 发送者用来验证它不是重播的唯一值。
     * @param initCode 如果设置，账户合约将由此构造函数创建
     * @param callData 要在此帐户上执行的方法调用。
     * @param callGasLimit 传递给 callData 方法调用的气体限制。
     * @param verificationGasLimit 用于 validateUserOp 和 validatePaymasterUserOp的gas上限。
     * @param preVerificationGas gas 不是通过 handleOps 方法计算的，而是添加到支付的 gas 中。涵盖批量开销。
     * @param maxFeePerGas 与 EIP-1559 gas 参数相同。
     * @param maxPriorityFeePerGas 与 EIP-1559 gas 参数相同。
     * @param paymasterAndData 如果设置，此字段包含出纳员地址和出纳员特定数据。出纳员将代替发件人支付交易费用。
     * @param signature 对整个请求、EntryPoint 地址和链 ID 的发件人验证签名。
     */
    struct UserOperation {

        address sender;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        uint256 callGasLimit;
        uint256 verificationGasLimit;
        uint256 preVerificationGas;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
        bytes paymasterAndData;
        bytes signature;
    }

/**
 * Utility functions helpful when working with UserOperation structs.
 */
library UserOperationLib {

    function getSender(UserOperation calldata userOp) internal pure returns (address) {
        address data;
        //read sender from userOp, which is first userOp member (saves 800 gas...)
        assembly {data := calldataload(userOp)}
        return address(uint160(data));
    }

    //relayer/block builder might submit the TX with higher priorityFee, but the user should not
    // pay above what he signed for.
    function gasPrice(UserOperation calldata userOp) internal view returns (uint256) {
    unchecked {
        uint256 maxFeePerGas = userOp.maxFeePerGas;
        uint256 maxPriorityFeePerGas = userOp.maxPriorityFeePerGas;
        if (maxFeePerGas == maxPriorityFeePerGas) {
            //legacy mode (for networks that don't support basefee opcode)
            return maxFeePerGas;
        }
        return min(maxFeePerGas, maxPriorityFeePerGas + block.basefee);
    }
    }

    function pack(UserOperation calldata userOp) internal pure returns (bytes memory ret) {
        //lighter signature scheme. must match UserOp.ts#packUserOp
        bytes calldata sig = userOp.signature;
        // copy directly the userOp from calldata up to (but not including) the signature.
        // this encoding depends on the ABI encoding of calldata, but is much lighter to copy
        // than referencing each field separately.
        assembly {
            let ofs := userOp
            let len := sub(sub(sig.offset, ofs), 32)
            ret := mload(0x40)
            mstore(0x40, add(ret, add(len, 32)))
            mstore(ret, len)
            calldatacopy(add(ret, 32), ofs, len)
        }
    }

    function hash(UserOperation calldata userOp) internal pure returns (bytes32) {
        return keccak256(pack(userOp));
    }

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}
