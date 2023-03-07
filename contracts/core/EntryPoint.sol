/**
 ** Account-Abstraction (EIP-4337) singleton EntryPoint implementation.
 ** Only one instance required on each chain.
 **/
// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */

import "../interfaces/IAccount.sol";
import "../interfaces/IPaymaster.sol";
import "../interfaces/IEntryPoint.sol";

import "../utils/Exec.sol";
import "./StakeManager.sol";
import "./SenderCreator.sol";
import "./Helpers.sol";

contract EntryPoint is IEntryPoint, StakeManager {

    // op库
    using UserOperationLib for UserOperation;

    SenderCreator private immutable senderCreator = new SenderCreator();

    // internal value used during simulation: need to query aggregator.
    // 模拟过程中使用的内部值：需要查询聚合器。
    address private constant SIMULATE_FIND_AGGREGATOR = address(1);

    // marker for inner call revert on out of gas
    // 内部调用标记在气体耗尽时恢复
    bytes32 private constant INNER_OUT_OF_GAS = hex'deaddead';

    // revert原因最大长度
    uint256 private constant REVERT_REASON_MAX_LEN = 2048;

    /**
     * for simulation purposes, validateUserOp (and validatePaymasterUserOp) must return this value
     * in case of signature failure, instead of revert.
     */
    // 出于模拟目的，如果签名失败，validateUserOp（和 validatePaymasterUserOp）必须返回此值，而不是revert。
    uint256 public constant SIG_VALIDATION_FAILED = 1;

    /**
     * compensate the caller's beneficiary address with the collected fees of all UserOperations.
     * @param beneficiary the address to receive the fees
     * @param amount amount to transfer.
     */
    // 用所有 UserOperations 收取的费用补偿调用者的受益人地址。
    function _compensate(address payable beneficiary, uint256 amount) internal {
        require(beneficiary != address(0), "AA90 invalid beneficiary");
        // 将amount转给beneficiary
        (bool success,) = beneficiary.call{value : amount}("");
        require(success, "AA91 failed send to beneficiary");
    }

    /**
     * execute a user op
     * @param opIndex index into the opInfo array
     * @param userOp the userOp to execute
     * @param opInfo the opInfo filled by validatePrepayment for this userOp.
     * @return collected the total amount this userOp paid.
     */
    // 执行用户op
    // opIndex opInfo 数组的索引
    // userOp 要执行的 userOp
    // opInfo 由此 userOp 的 validatePrepayment 填充的 opInfo。
    // collected 此 userOp 支付的总金额。
    function _executeUserOp(uint256 opIndex, UserOperation calldata userOp, UserOpInfo memory opInfo) private returns (uint256 collected) {
        // 执行前gas
        uint256 preGas = gasleft();
        // 获取上下文
        bytes memory context = getMemoryBytesFromOffset(opInfo.contextOffset);

        // 外部调用内部处理op，参数为用户的callData，op信息，上下文
        try this.innerHandleOp(userOp.callData, opInfo, context) returns (uint256 _actualGasCost) {
            // 返回实际消耗
            collected = _actualGasCost;
        } catch {
            // 定义内部失败code
            bytes32 innerRevertCode;
            assembly {
                // 从returndata的0位置开始，复制32bytes个字节到内存位置0
                returndatacopy(0, 0, 32)
                // 取内存0位置数据
                innerRevertCode := mload(0)
            }
            // handleOps was called with gas limit too low. abort entire bundle.
            if (innerRevertCode == INNER_OUT_OF_GAS) {
                //report paymaster, since if it is not deliberately caused by the bundler,
                // it must be a revert caused by paymaster.
                revert FailedOp(opIndex, "AA95 out of gas");
            }

            // 实际消耗gas = _executeUserOp消耗gas + 验证消耗gas
            uint256 actualGas = preGas - gasleft() + opInfo.preOpGas;
            // 退还未使用gas
            collected = _handlePostOp(opIndex, IPaymaster.PostOpMode.postOpReverted, opInfo, context, actualGas);
        }
    }

    /**
     * Execute a batch of UserOperations.
     * no signature aggregator is used.
     * if any account requires an aggregator (that is, it returned an aggregator when
     * performing simulateValidation), then handleAggregatedOps() must be used instead.
     * @param ops the operations to execute
     * @param beneficiary the address to receive the fees
     */
    // 批量处理用户op，没有使用签名聚合器，如果要使用签名聚合器，调用handleAggregatedOps()
    function handleOps(UserOperation[] calldata ops, address payable beneficiary) public {

        // 获取op长度
        uint256 opslen = ops.length;
        // 建立op信息数组
        UserOpInfo[] memory opInfos = new UserOpInfo[](opslen);

        unchecked {
            // 验证循环
            for (uint256 i = 0; i < opslen; i++) {
                UserOpInfo memory opInfo = opInfos[i];
                // 验证预支付账户
                (uint256 validationData, uint256 pmValidationData) = _validatePrepayment(i, ops[i], opInfo);
                _validateAccountAndPaymasterValidationData(i, validationData, pmValidationData, address(0));
            }

            uint256 collected = 0;

            // 执行循环
            for (uint256 i = 0; i < opslen; i++) {
                // 返回执行op需要消耗的gas
                collected += _executeUserOp(i, ops[i], opInfos[i]);
            }

            // 用所有 UserOperations 收取的费用补偿调用者的受益人地址。
            _compensate(beneficiary, collected);
        } //unchecked
    }

    /**
     * Execute a batch of UserOperation with Aggregators
     * @param opsPerAggregator the operations to execute, grouped by aggregator (or address(0) for no-aggregator accounts)
     * @param beneficiary the address to receive the fees
     */
    function handleAggregatedOps(
        UserOpsPerAggregator[] calldata opsPerAggregator,
        address payable beneficiary
    ) public {

        uint256 opasLen = opsPerAggregator.length;
        uint256 totalOps = 0;
        for (uint256 i = 0; i < opasLen; i++) {
            UserOpsPerAggregator calldata opa = opsPerAggregator[i];
            UserOperation[] calldata ops = opa.userOps;
            IAggregator aggregator = opa.aggregator;

            //address(1) is special marker of "signature error"
            require(address(aggregator) != address(1), "AA96 invalid aggregator");

            if (address(aggregator) != address(0)) {
                // solhint-disable-next-line no-empty-blocks
                try aggregator.validateSignatures(ops, opa.signature) {}
                catch {
                    revert SignatureValidationFailed(address(aggregator));
                }
            }

            totalOps += ops.length;
        }

        UserOpInfo[] memory opInfos = new UserOpInfo[](totalOps);

        uint256 opIndex = 0;
        for (uint256 a = 0; a < opasLen; a++) {
            UserOpsPerAggregator calldata opa = opsPerAggregator[a];
            UserOperation[] calldata ops = opa.userOps;
            IAggregator aggregator = opa.aggregator;

            uint256 opslen = ops.length;
            for (uint256 i = 0; i < opslen; i++) {
                UserOpInfo memory opInfo = opInfos[opIndex];
                (uint256 validationData, uint256 paymasterValidationData) = _validatePrepayment(opIndex, ops[i], opInfo);
                _validateAccountAndPaymasterValidationData(i, validationData, paymasterValidationData, address(aggregator));
                opIndex++;
            }
        }

        uint256 collected = 0;
        opIndex = 0;
        for (uint256 a = 0; a < opasLen; a++) {
            UserOpsPerAggregator calldata opa = opsPerAggregator[a];
            emit SignatureAggregatorChanged(address(opa.aggregator));
            UserOperation[] calldata ops = opa.userOps;
            uint256 opslen = ops.length;

            for (uint256 i = 0; i < opslen; i++) {
                collected += _executeUserOp(opIndex, ops[i], opInfos[opIndex]);
                opIndex++;
            }
        }
        emit SignatureAggregatorChanged(address(0));

        _compensate(beneficiary, collected);
    }

    /// @inheritdoc IEntryPoint
    // 模拟执行处理op
    function simulateHandleOp(UserOperation calldata op, address target, bytes calldata targetCallData) external override {

        UserOpInfo memory opInfo;
        _simulationOnlyValidations(op);
        (uint256 validationData, uint256 paymasterValidationData) = _validatePrepayment(0, op, opInfo);
        ValidationData memory data = _intersectTimeRange(validationData, paymasterValidationData);

        numberMarker();
        uint256 paid = _executeUserOp(0, op, opInfo);
        numberMarker();
        bool targetSuccess;
        bytes memory targetResult;
        if (target != address(0)) {
            (targetSuccess, targetResult) = target.call(targetCallData);
        }
        revert ExecutionResult(opInfo.preOpGas, paid, data.validAfter, data.validUntil, targetSuccess, targetResult);
    }


    // A memory copy of UserOp static fields only.
    // Excluding: callData, initCode and signature. Replacing paymasterAndData with paymaster.
    struct MemoryUserOp {
        address sender;
        uint256 nonce;
        uint256 callGasLimit;
        uint256 verificationGasLimit;
        uint256 preVerificationGas;
        address paymaster;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
    }

    struct UserOpInfo {
        MemoryUserOp mUserOp;
        bytes32 userOpHash;
        uint256 prefund;
        uint256 contextOffset;
        uint256 preOpGas;
    }

    /**
     * inner function to handle a UserOperation.
     * Must be declared "external" to open a call context, but it can only be called by handleOps.
     */
    // 内部函数处理op，必须被定义为external，但是值运行当前合约的handleOps调用，模拟内部调用
    function innerHandleOp(bytes memory callData, UserOpInfo memory opInfo, bytes calldata context) external returns (uint256 actualGasCost) {
        // 当前gas
        uint256 preGas = gasleft();
        // 必须为当前合约调用
        require(msg.sender == address(this), "AA92 internal call only");
        // 获取内存中的用户操作
        MemoryUserOp memory mUserOp = opInfo.mUserOp;

        // 获取调用gasLimit
        uint callGasLimit = mUserOp.callGasLimit;
        unchecked {
            // handleOps was called with gas limit too low. abort entire bundle.
            // 调用 handleOps 时气体限制太低。中止整个包。
            if (gasleft() < callGasLimit + mUserOp.verificationGasLimit + 5000) {
                assembly {
                    // 内存位置0存储INNER_OUT_OF_GAS
                    mstore(0, INNER_OUT_OF_GAS)
                    // 返回内存0位置
                    revert(0, 32)
                }
            }
        }

        // 初始化操作成功
        IPaymaster.PostOpMode mode = IPaymaster.PostOpMode.opSucceeded;
        // calldata数据不为空
        if (callData.length > 0) {
            // 实际调用
            bool success = Exec.call(mUserOp.sender, 0, callData, callGasLimit);
            if (!success) {
                // 返回数据
                bytes memory result = Exec.getReturnData(REVERT_REASON_MAX_LEN);
                if (result.length > 0) {
                    emit UserOperationRevertReason(opInfo.userOpHash, mUserOp.sender, mUserOp.nonce, result);
                }
                mode = IPaymaster.PostOpMode.opReverted;
            }
        }

    unchecked {
        uint256 actualGas = preGas - gasleft() + opInfo.preOpGas;
        //note: opIndex is ignored (relevant only if mode==postOpReverted, which is only possible outside of innerHandleOp)
        return _handlePostOp(0, mode, opInfo, context, actualGas);
    }
    }

    /**
     * generate a request Id - unique identifier for this request.
     * the request ID is a hash over the content of the userOp (except the signature), the entrypoint and the chainid.
     */
    function getUserOpHash(UserOperation calldata userOp) public view returns (bytes32) {
        return keccak256(abi.encode(userOp.hash(), address(this), block.chainid));
    }

    /**
     * copy general fields from userOp into the memory opInfo structure.
     */
    function _copyUserOpToMemory(UserOperation calldata userOp, MemoryUserOp memory mUserOp) internal pure {
        mUserOp.sender = userOp.sender;
        mUserOp.nonce = userOp.nonce;
        mUserOp.callGasLimit = userOp.callGasLimit;
        mUserOp.verificationGasLimit = userOp.verificationGasLimit;
        mUserOp.preVerificationGas = userOp.preVerificationGas;
        mUserOp.maxFeePerGas = userOp.maxFeePerGas;
        mUserOp.maxPriorityFeePerGas = userOp.maxPriorityFeePerGas;
        bytes calldata paymasterAndData = userOp.paymasterAndData;
        if (paymasterAndData.length > 0) {
            require(paymasterAndData.length >= 20, "AA93 invalid paymasterAndData");
            mUserOp.paymaster = address(bytes20(paymasterAndData[: 20]));
        } else {
            mUserOp.paymaster = address(0);
        }
    }

    /**
     * Simulate a call to account.validateUserOp and paymaster.validatePaymasterUserOp.
     * @dev this method always revert. Successful result is ValidationResult error. other errors are failures.
     * @dev The node must also verify it doesn't use banned opcodes, and that it doesn't reference storage outside the account's data.
     * @param userOp the user operation to validate.
     */
    function simulateValidation(UserOperation calldata userOp) external {
        UserOpInfo memory outOpInfo;

        _simulationOnlyValidations(userOp);
        (uint256 validationData, uint256 paymasterValidationData) = _validatePrepayment(0, userOp, outOpInfo);
        StakeInfo memory paymasterInfo = _getStakeInfo(outOpInfo.mUserOp.paymaster);
        StakeInfo memory senderInfo = _getStakeInfo(outOpInfo.mUserOp.sender);
        StakeInfo memory factoryInfo;
        {
            bytes calldata initCode = userOp.initCode;
            address factory = initCode.length >= 20 ? address(bytes20(initCode[0 : 20])) : address(0);
            factoryInfo = _getStakeInfo(factory);
        }

        ValidationData memory data = _intersectTimeRange(validationData, paymasterValidationData);
        address aggregator = data.aggregator;
        bool sigFailed = aggregator == address(1);
        ReturnInfo memory returnInfo = ReturnInfo(outOpInfo.preOpGas, outOpInfo.prefund,
            sigFailed, data.validAfter, data.validUntil, getMemoryBytesFromOffset(outOpInfo.contextOffset));

        if (aggregator != address(0) && aggregator != address(1)) {
            AggregatorStakeInfo memory aggregatorInfo = AggregatorStakeInfo(aggregator, _getStakeInfo(aggregator));
            revert ValidationResultWithAggregation(returnInfo, senderInfo, factoryInfo, paymasterInfo, aggregatorInfo);
        }
        revert ValidationResult(returnInfo, senderInfo, factoryInfo, paymasterInfo);

    }

    function _getRequiredPrefund(MemoryUserOp memory mUserOp) internal pure returns (uint256 requiredPrefund) {
    unchecked {
        //when using a Paymaster, the verificationGasLimit is used also to as a limit for the postOp call.
        // our security model might call postOp eventually twice
        uint256 mul = mUserOp.paymaster != address(0) ? 3 : 1;
        uint256 requiredGas = mUserOp.callGasLimit + mUserOp.verificationGasLimit * mul + mUserOp.preVerificationGas;

        requiredPrefund = requiredGas * mUserOp.maxFeePerGas;
    }
    }

    // create the sender's contract if needed.
    function _createSenderIfNeeded(uint256 opIndex, UserOpInfo memory opInfo, bytes calldata initCode) internal {
        if (initCode.length != 0) {
            address sender = opInfo.mUserOp.sender;
            if (sender.code.length != 0) revert FailedOp(opIndex, "AA10 sender already constructed");
            address sender1 = senderCreator.createSender{gas : opInfo.mUserOp.verificationGasLimit}(initCode);
            if (sender1 == address(0)) revert FailedOp(opIndex, "AA13 initCode failed or OOG");
            if (sender1 != sender) revert FailedOp(opIndex, "AA14 initCode must return sender");
            if (sender1.code.length == 0) revert FailedOp(opIndex, "AA15 initCode must create sender");
            address factory = address(bytes20(initCode[0 : 20]));
            emit AccountDeployed(opInfo.userOpHash, sender, factory, opInfo.mUserOp.paymaster);
        }
    }

    /**
     * Get counterfactual sender address.
     *  Calculate the sender contract address that will be generated by the initCode and salt in the UserOperation.
     * this method always revert, and returns the address in SenderAddressResult error
     * @param initCode the constructor code to be passed into the UserOperation.
     */
    function getSenderAddress(bytes calldata initCode) public {
        revert SenderAddressResult(senderCreator.createSender(initCode));
    }

    function _simulationOnlyValidations(UserOperation calldata userOp) internal view {
        // solhint-disable-next-line no-empty-blocks
        try this._validateSenderAndPaymaster(userOp.initCode, userOp.sender, userOp.paymasterAndData) {}
        catch Error(string memory revertReason) {
            if (bytes(revertReason).length != 0) {
                revert FailedOp(0, revertReason);
            }
        }
    }

    /**
    * Called only during simulation.
    * This function always reverts to prevent warm/cold storage differentiation in simulation vs execution.
    */
    // 验证接收地址及支付地址，仅在预估时调用
    function _validateSenderAndPaymaster(bytes calldata initCode, address sender, bytes calldata paymasterAndData) external view {
        if (initCode.length == 0 && sender.code.length == 0) {
            // it would revert anyway. but give a meaningful message
            revert("AA20 account not deployed");
        }
        if (paymasterAndData.length >= 20) {
            address paymaster = address(bytes20(paymasterAndData[0 : 20]));
            if (paymaster.code.length == 0) {
                // it would revert anyway. but give a meaningful message
                revert("AA30 paymaster not deployed");
            }
        }
        // always revert
        revert("");
    }

    /**
     * call account.validateUserOp.
     * revert (with FailedOp) in case validateUserOp reverts, or account didn't send required prefund.
     * decrement account's deposit if needed
     */
    // 验证账户预支付
    // 调用 account.validateUserOp。还原（使用 FailedOp）以防 validateUserOp 还原，或帐户未发送所需的预付款。
    // 如果需要，减少帐户的存款
    function _validateAccountPrepayment(uint256 opIndex, UserOperation calldata op, UserOpInfo memory opInfo, uint256 requiredPrefund)
    internal returns (uint256 gasUsedByValidateAccountPrepayment, uint256 validationData) {
    unchecked {
        uint256 preGas = gasleft();
        MemoryUserOp memory mUserOp = opInfo.mUserOp;
        address sender = mUserOp.sender;
        _createSenderIfNeeded(opIndex, opInfo, op.initCode);
        address paymaster = mUserOp.paymaster;
        numberMarker();
        uint256 missingAccountFunds = 0;
        if (paymaster == address(0)) {
            uint256 bal = balanceOf(sender);
            missingAccountFunds = bal > requiredPrefund ? 0 : requiredPrefund - bal;
        }
        try IAccount(sender).validateUserOp{gas : mUserOp.verificationGasLimit}(op, opInfo.userOpHash, missingAccountFunds)
        returns (uint256 _validationData) {
            validationData = _validationData;
        } catch Error(string memory revertReason) {
            revert FailedOp(opIndex, string.concat("AA23 reverted: ", revertReason));
        } catch {
            revert FailedOp(opIndex, "AA23 reverted (or OOG)");
        }
        if (paymaster == address(0)) {
            DepositInfo storage senderInfo = deposits[sender];
            uint256 deposit = senderInfo.deposit;
            if (requiredPrefund > deposit) {
                revert FailedOp(opIndex, "AA21 didn't pay prefund");
            }
            senderInfo.deposit = uint112(deposit - requiredPrefund);
        }
        gasUsedByValidateAccountPrepayment = preGas - gasleft();
    }
    }

    /**
     * In case the request has a paymaster:
     * Validate paymaster has enough deposit.
     * Call paymaster.validatePaymasterUserOp.
     * Revert with proper FailedOp in case paymaster reverts.
     * Decrement paymaster's deposit
     */
    function _validatePaymasterPrepayment(uint256 opIndex, UserOperation calldata op, UserOpInfo memory opInfo, uint256 requiredPreFund, uint256 gasUsedByValidateAccountPrepayment)
    internal returns (bytes memory context, uint256 validationData) {
    unchecked {
        MemoryUserOp memory mUserOp = opInfo.mUserOp;
        uint256 verificationGasLimit = mUserOp.verificationGasLimit;
        require(verificationGasLimit > gasUsedByValidateAccountPrepayment, "AA41 too little verificationGas");
        uint256 gas = verificationGasLimit - gasUsedByValidateAccountPrepayment;

        address paymaster = mUserOp.paymaster;
        DepositInfo storage paymasterInfo = deposits[paymaster];
        uint256 deposit = paymasterInfo.deposit;
        if (deposit < requiredPreFund) {
            revert FailedOp(opIndex, "AA31 paymaster deposit too low");
        }
        paymasterInfo.deposit = uint112(deposit - requiredPreFund);
        try IPaymaster(paymaster).validatePaymasterUserOp{gas : gas}(op, opInfo.userOpHash, requiredPreFund) returns (bytes memory _context, uint256 _validationData){
            context = _context;
            validationData = _validationData;
        } catch Error(string memory revertReason) {
            revert FailedOp(opIndex, string.concat("AA33 reverted: ", revertReason));
        } catch {
            revert FailedOp(opIndex, "AA33 reverted (or OOG)");
        }
    }
    }

    /**
     * revert if either account validationData or paymaster validationData is expired
     */
    // 验证账户和支付账户验证数据
    function _validateAccountAndPaymasterValidationData(uint256 opIndex, uint256 validationData, uint256 paymasterValidationData, address expectedAggregator) internal view {
        (address aggregator, bool outOfTimeRange) = _getValidationData(validationData);
        if (expectedAggregator != aggregator) {
            revert FailedOp(opIndex, "AA24 signature error");
        }
        if (outOfTimeRange) {
            revert FailedOp(opIndex, "AA22 expired or not due");
        }
        //pmAggregator is not a real signature aggregator: we don't have logic to handle it as address.
        // non-zero address means that the paymaster fails due to some signature check (which is ok only during estimation)
        address pmAggregator;
        (pmAggregator, outOfTimeRange) = _getValidationData(paymasterValidationData);
        if (pmAggregator != address(0)) {
            revert FailedOp(opIndex, "AA34 signature error");
        }
        if (outOfTimeRange) {
            revert FailedOp(opIndex, "AA32 paymaster expired or not due");
        }
    }

    // 获取验证数据
    function _getValidationData(uint256 validationData) internal view returns (address aggregator, bool outOfTimeRange) {
        if (validationData == 0) {
            return (address(0), false);
        }
        ValidationData memory data = _parseValidationData(validationData);
        // solhint-disable-next-line not-rely-on-time
        outOfTimeRange = block.timestamp > data.validUntil || block.timestamp < data.validAfter;
        aggregator = data.aggregator;
    }

    /**
     * validate account and paymaster (if defined).
     * also make sure total validation doesn't exceed verificationGasLimit
     * this method is called off-chain (simulateValidation()) and on-chain (from handleOps)
     * @param opIndex the index of this userOp into the "opInfos" array
     * @param userOp the userOp to validate
     */
    // 验证帐户和出纳员（如果已定义）。
    // 还要确保总验证gas不超过 verificationGasLimit
    // 此方法链下调用时，由 simulateValidation() 触发， 链上调用时，由 handleOps 触发
    // 返回验证数据
    function _validatePrepayment(uint256 opIndex, UserOperation calldata userOp, UserOpInfo memory outOpInfo) private returns (uint256 validationData, uint256 paymasterValidationData) {
        // 当前gas
        uint256 preGas = gasleft();
        // 用户op信息
        MemoryUserOp memory mUserOp = outOpInfo.mUserOp;
        // 拷贝用户op信息到内存
        _copyUserOpToMemory(userOp, mUserOp);
        // 计算userOp哈希
        outOpInfo.userOpHash = getUserOpHash(userOp);

        // validate all numeric values in userOp are well below 128 bit, so they can safely be added
        // and multiplied without causing overflow
        // 验证 userOp 中的所有数值都远低于 128 位，因此可以安全地相加和相乘而不会导致溢出
        uint256 maxGasValues = mUserOp.preVerificationGas | mUserOp.verificationGasLimit | mUserOp.callGasLimit |
        userOp.maxFeePerGas | userOp.maxPriorityFeePerGas;
        // 超过gas上限，则revert
        require(maxGasValues <= type(uint120).max, "AA94 gas values overflow");

        // 初始化gasUsedByValidateAccountPrepayment
        uint256 gasUsedByValidateAccountPrepayment;
        (uint256 requiredPreFund) = _getRequiredPrefund(mUserOp);
        // 验证账户预支付账户的gas消耗，验证数据
        (gasUsedByValidateAccountPrepayment, validationData) = _validateAccountPrepayment(opIndex, userOp, outOpInfo, requiredPreFund);
        //a "marker" where account opcode validation is done and paymaster opcode validation is about to start
        // (used only by off-chain simulateValidation)
        numberMarker();

        bytes memory context;
        if (mUserOp.paymaster != address(0)) {
            (context, paymasterValidationData) = _validatePaymasterPrepayment(opIndex, userOp, outOpInfo, requiredPreFund, gasUsedByValidateAccountPrepayment);
        }
        unchecked {
            uint256 gasUsed = preGas - gasleft();

            if (userOp.verificationGasLimit < gasUsed) {
                revert FailedOp(opIndex, "AA40 over verificationGasLimit");
            }
            outOpInfo.prefund = requiredPreFund;
            outOpInfo.contextOffset = getOffsetOfMemoryBytes(context);
            outOpInfo.preOpGas = preGas - gasleft() + userOp.preVerificationGas;
        }
    }

    /**
     * process post-operation.
     * called just after the callData is executed.
     * if a paymaster is defined and its validation returned a non-empty context, its postOp is called.
     * the excess amount is refunded to the account (or paymaster - if it was used in the request)
     * @param opIndex index in the batch
     * @param mode - whether is called from innerHandleOp, or outside (postOpReverted)
     * @param opInfo userOp fields and info collected during validation
     * @param context the context returned in validatePaymasterUserOp
     * @param actualGas the gas used so far by this user operation
     */
    // 退还未使用的gasFee，返回实际消耗的gas费
    // 在执行 callData 之后立即调用。
    // 如果定义了 paymaster 并且其验证返回非空上下文，则调用其 postOp 。超出的金额将退还到帐户（或 paymaster - 如果在请求中使用过）
    // @param opIndex 批次中的索引
    // @param mode - 是从 innerHandleOp 调用还是从外部调用 (postOpReverted)
    // @param opInfo userOp 字段和验证期间收集的信息
    // @param context validatePaymasterUserOp 返回的上下文
    // @param actualGas 此用户操作到目前为止使用的气体
    function _handlePostOp(uint256 opIndex, IPaymaster.PostOpMode mode, UserOpInfo memory opInfo, bytes memory context, uint256 actualGas) private returns (uint256 actualGasCost) {
        uint256 preGas = gasleft();
        unchecked {
            // 退款地址
            address refundAddress;
            // 用户操作信息
            MemoryUserOp memory mUserOp = opInfo.mUserOp;
            // 获取用户gasPrice
            uint256 gasPrice = getUserOpGasPrice(mUserOp);

            // 预支付账户
            address paymaster = mUserOp.paymaster;
            if (paymaster == address(0)) {
                // 退款地址为当前调用者
                refundAddress = mUserOp.sender;
            } else {
                // 退款地址为预支付地址
                refundAddress = paymaster;
                if (context.length > 0) {
                    // 实际消耗gas费 = 实际消耗gas数量 * gas价格
                    actualGasCost = actualGas * gasPrice;
                    if (mode != IPaymaster.PostOpMode.postOpReverted) {
                        IPaymaster(paymaster).postOp{gas : mUserOp.verificationGasLimit}(mode, context, actualGasCost);
                    } else {
                        // solhint-disable-next-line no-empty-blocks
                        try IPaymaster(paymaster).postOp{gas : mUserOp.verificationGasLimit}(mode, context, actualGasCost) {}
                        catch Error(string memory reason) {
                            revert FailedOp(opIndex, string.concat("AA50 postOp reverted: ", reason));
                        }
                        catch {
                            revert FailedOp(opIndex, "AA50 postOp revert");
                        }
                    }
                }
            }
            actualGas += preGas - gasleft();
            actualGasCost = actualGas * gasPrice;
            if (opInfo.prefund < actualGasCost) {
                revert FailedOp(opIndex, "AA51 prefund below actualGasCost");
            }
            uint256 refund = opInfo.prefund - actualGasCost;
            _incrementDeposit(refundAddress, refund);
            bool success = mode == IPaymaster.PostOpMode.opSucceeded;
            emit UserOperationEvent(opInfo.userOpHash, mUserOp.sender, mUserOp.paymaster, mUserOp.nonce, success, actualGasCost, actualGas);
        } // unchecked
    }

    /**
     * the gas price this UserOp agrees to pay.
     * relayer/block builder might submit the TX with higher priorityFee, but the user should not
     */
    // 获取用户op同意支付的gasPrice
    function getUserOpGasPrice(MemoryUserOp memory mUserOp) internal view returns (uint256) {
    unchecked {
        uint256 maxFeePerGas = mUserOp.maxFeePerGas;
        uint256 maxPriorityFeePerGas = mUserOp.maxPriorityFeePerGas;
        if (maxFeePerGas == maxPriorityFeePerGas) {
            //legacy mode (for networks that don't support basefee opcode)
            return maxFeePerGas;
        }
        return min(maxFeePerGas, maxPriorityFeePerGas + block.basefee);
    }
    }

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    // 获取bytes的偏移量
    function getOffsetOfMemoryBytes(bytes memory data) internal pure returns (uint256 offset) {
        assembly {offset := data}
    }

    // 从指定偏移量获取数据
    function getMemoryBytesFromOffset(uint256 offset) internal pure returns (bytes memory data) {
        assembly {data := offset}
    }

    //place the NUMBER opcode in the code.
    // this is used as a marker during simulation, as this OP is completely banned from the simulated code of the
    // account and paymaster.
    // 将 NUMBER 操作码放在代码中。
    // 这在模拟期间用作标记，因为此 OP 完全禁止在模拟代码中使用
    // 帐户和付款人。
    function numberMarker() internal view {
        // 在内存0位置存储当前区块号
        assembly {mstore(0, number())}
    }
}

