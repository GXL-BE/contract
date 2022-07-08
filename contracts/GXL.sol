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
    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");

    uint public chainId;

    mapping(string => uint) private isWithdrawn;
    mapping(address => bool) public supportedAssets;


    event LogDeposit(address user, address asset, uint amount, uint timestamp);
    event LogWithdraw(string itx, address user, address asset, uint amount, uint timestamp);

    constructor() {
        uint _chainId;
        assembly {_chainId := chainid()}
        chainId = _chainId;
        _setRoleAdmin(SIGNER_ROLE, OWNER_ROLE);
        _setRoleAdmin(OWNER_ROLE, OWNER_ROLE);
        _setupRole(OWNER_ROLE, msg.sender);
    }

    modifier supportedAsset(address asset) {
        require(supportedAssets[asset], "unsupported asset");
        _;
    }

    function deposit(address asset, uint amount)
    supportedAsset(asset)
    external {
        require(amount > 0, "invalid amount");
        bool transferred = IERC20(asset).transferFrom(msg.sender, address(this), amount);
        require(transferred, "cannot transfer");

        emit LogDeposit(msg.sender, asset, amount, block.timestamp);
    }

    function withdraw(string calldata itx,
        address user,
        address asset,
        uint amount,
        bytes calldata signature)
    whenNotPaused
    supportedAsset(asset)
    external {
        require(isWithdrawn[itx] == 0, "withdrawn");
        bytes32 hash = keccak256(abi.encodePacked(
                chainId,
                user,
                itx,
                asset,
                amount,
                address(this)
            ));
        require(verifySignature(hash, signature), "invalid signature");
        isWithdrawn[itx] = block.number;
        bool transferred = IERC20(asset).transfer(user, amount);
        require(transferred, "cannot transfer");
        emit LogWithdraw(itx, user, asset, amount, block.timestamp);
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
