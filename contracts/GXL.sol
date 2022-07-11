// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract GXL is AccessControl, Pausable {
    using ECDSA for bytes32;

    bytes32 public constant OWNER_ROLE = keccak256("OWNER_ROLE");
    bytes32 public constant OPERATION_ROLE = keccak256("OPERATION_ROLE");
    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");

    uint public chainId;

    mapping(string => uint) private isWithdrawn;
    mapping(address => bool) public supportedAssets;

    address public POOL_STORE_ADDRESS;

    event LogDeposit(address user, address asset, uint amount, uint timestamp);
    event LogWithdrawWithPermit(string itx, address user, address asset, uint amount, uint timestamp);
    event LogWithdraw(string itx, address user, address asset, uint amount, uint timestamp);
    event LogWithdrawRevenue(address[] assets, uint[] amounts);
    event LogSetPoolStoreAddress(address poolStore);

    constructor() {
        uint _chainId;
        assembly {_chainId := chainid()}
        chainId = _chainId;

        _setRoleAdmin(OPERATION_ROLE, OWNER_ROLE);
        _setRoleAdmin(SIGNER_ROLE, OWNER_ROLE);
        _setRoleAdmin(OWNER_ROLE, OWNER_ROLE);
        _setupRole(OWNER_ROLE, msg.sender);
    }

    modifier supportedAsset(address asset) {
        require(supportedAssets[asset], "unsupported asset");
        _;
    }

    modifier validItx(string calldata itx) {
        require(isWithdrawn[itx] == 0, "withdrawn");
        isWithdrawn[itx] = block.number;
        _;
    }

    function getWithdrawnStatus(string calldata itx) external view returns (uint) {
        return isWithdrawn[itx];
    }

    function deposit(address asset, uint amount)
    supportedAsset(asset)
    payable
    external {
        uint _amount = asset == address(0) ? msg.value : amount;
        require(_amount > 0, "invalid amount");
        if (asset != address(0)) {
            bool transferred = IERC20(asset).transferFrom(msg.sender, address(this), _amount);
            require(transferred, "cannot transfer");
        }
        emit LogDeposit(msg.sender, asset, _amount, block.timestamp);
    }

    function withdrawWithPermit(string calldata itx,
        address user,
        address asset,
        uint amount,
        bytes calldata signature)
    whenNotPaused
    validItx(itx)
    supportedAsset(asset)
    external {
        bytes32 hash = keccak256(abi.encodePacked(
                chainId,
                user,
                itx,
                asset,
                amount,
                address(this)
            ));
        require(verifySignature(hash, signature), "invalid signature");
        _withdraw(asset, user, amount);
        emit LogWithdrawWithPermit(itx, user, asset, amount, block.timestamp);
    }

    function withdraw(string calldata itx, address asset, address user, uint amount)
    external
    whenNotPaused
    validItx(itx)
    onlyRole(OPERATION_ROLE) {
        _withdraw(asset, user, amount);
        emit LogWithdraw(itx, user, asset, amount, block.timestamp);
    }

    function withdrawRevenue(address[] calldata assets, uint[] calldata amounts) external
    onlyRole(OPERATION_ROLE) {
        uint length = assets.length;
        require(length > 0, "invalid asset");
        require(assets.length == amounts.length, "miss match length");
        require(POOL_STORE_ADDRESS != address(0), "must be config pool store");
        for (uint i; i < length; ++i) {
            _withdraw(POOL_STORE_ADDRESS, assets[i], amounts[i]);
        }
        emit LogWithdrawRevenue(assets, amounts);
    }

    function setPoolStoreAddress(address pool) external onlyRole(OWNER_ROLE) {
        POOL_STORE_ADDRESS = pool;
        emit LogSetPoolStoreAddress(pool);
    }

    function _withdraw(address asset, address user, uint amount) internal {
        require(amount > 0, "invalid amount");
        if (asset == address(0)) {
            address payable receiver = payable(user);
            (bool sent,) = receiver.call{value : amount}("");
            require(sent, "cannot withdraw native");
        } else {
            bool transferred = IERC20(asset).transfer(user, amount);
            require(transferred, "cannot transfer");
        }
    }

    function verifySignature(bytes32 hash, bytes calldata signature)
    internal view returns (bool) {
        bytes32 messageHash = hash.toEthSignedMessageHash();
        address signatory = messageHash.recover(signature);
        return hasRole(SIGNER_ROLE, signatory);
    }

    //operation function
    function setSupportAsset(address asset, bool status) onlyRole(OWNER_ROLE) external {
        supportedAssets[asset] = status;
    }

    receive() payable external {}

    //emergency function
    function pause() public onlyRole(OWNER_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(OWNER_ROLE) {
        _unpause();
    }

    function emergencyWithdrawERC20(
        address token,
        uint amount,
        address sendTo
    ) external onlyRole(OWNER_ROLE) {
        IERC20(token).transfer(sendTo, amount);
    }

    function emergencyWithdrawNative(uint amount, address payable sendTo) external onlyRole(OWNER_ROLE) {
        (bool success,) = sendTo.call{value : amount}("");
        require(success, "withdraw failed");
    }

    function emergencyWithdrawERC721(
        address sendTo,
        address token,
        uint tokenId
    ) external onlyRole(OWNER_ROLE) {
        IERC721(token).transferFrom(address(this), sendTo, tokenId);
    }
}
