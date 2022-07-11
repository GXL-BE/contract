/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { ethers } from "ethers";
import {
  FactoryOptions,
  HardhatEthersHelpers as HardhatEthersHelpersBase,
} from "@nomiclabs/hardhat-ethers/types";

import * as Contracts from ".";

declare module "hardhat/types/runtime" {
  interface HardhatEthersHelpers extends HardhatEthersHelpersBase {
    getContractFactory(
      name: "AccessControl",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.AccessControl__factory>;
    getContractFactory(
      name: "IAccessControl",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IAccessControl__factory>;
    getContractFactory(
      name: "Pausable",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.Pausable__factory>;
    getContractFactory(
      name: "ERC20",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.ERC20__factory>;
    getContractFactory(
      name: "ERC20Burnable",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.ERC20Burnable__factory>;
    getContractFactory(
      name: "ERC20Pausable",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.ERC20Pausable__factory>;
    getContractFactory(
      name: "ERC20Snapshot",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.ERC20Snapshot__factory>;
    getContractFactory(
      name: "IERC20Metadata",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC20Metadata__factory>;
    getContractFactory(
      name: "IERC20",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC20__factory>;
    getContractFactory(
      name: "ERC721",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.ERC721__factory>;
    getContractFactory(
      name: "IERC721Metadata",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC721Metadata__factory>;
    getContractFactory(
      name: "IERC721",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC721__factory>;
    getContractFactory(
      name: "IERC721Receiver",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC721Receiver__factory>;
    getContractFactory(
      name: "ERC165",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.ERC165__factory>;
    getContractFactory(
      name: "IERC165",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC165__factory>;
    getContractFactory(
      name: "AccessControl",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.AccessControl__factory>;
    getContractFactory(
      name: "IAccessControl",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IAccessControl__factory>;
    getContractFactory(
      name: "ERC20",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.ERC20__factory>;
    getContractFactory(
      name: "IERC20Metadata",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC20Metadata__factory>;
    getContractFactory(
      name: "IERC20",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC20__factory>;
    getContractFactory(
      name: "ERC721",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.ERC721__factory>;
    getContractFactory(
      name: "IERC721Metadata",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC721Metadata__factory>;
    getContractFactory(
      name: "IERC721",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC721__factory>;
    getContractFactory(
      name: "IERC721Receiver",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC721Receiver__factory>;
    getContractFactory(
      name: "ERC165",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.ERC165__factory>;
    getContractFactory(
      name: "IERC165",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IERC165__factory>;
    getContractFactory(
      name: "AON",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.AON__factory>;
    getContractFactory(
      name: "AONHoldPool",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.AONHoldPool__factory>;
    getContractFactory(
      name: "AONStakingPoolRewardNFT",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.AONStakingPoolRewardNFT__factory>;
    getContractFactory(
      name: "AONStakingPoolRewardToken",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.AONStakingPoolRewardToken__factory>;
    getContractFactory(
      name: "ArenaBox",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.ArenaBox__factory>;
    getContractFactory(
      name: "INFTContract",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.INFTContract__factory>;
    getContractFactory(
      name: "ArenaNFT",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.ArenaNFT__factory>;
    getContractFactory(
      name: "BoxShop",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.BoxShop__factory>;
    getContractFactory(
      name: "IArenaBox",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IArenaBox__factory>;
    getContractFactory(
      name: "ClaimGacha",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.ClaimGacha__factory>;
    getContractFactory(
      name: "INFTContract",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.INFTContract__factory>;
    getContractFactory(
      name: "BPContract",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.BPContract__factory>;
    getContractFactory(
      name: "GXL",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.GXL__factory>;
    getContractFactory(
      name: "IMarketServicePartnerV1",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IMarketServicePartnerV1__factory>;
    getContractFactory(
      name: "IMarketServiceReadableV1",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IMarketServiceReadableV1__factory>;
    getContractFactory(
      name: "IMarketServiceUserV1",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IMarketServiceUserV1__factory>;
    getContractFactory(
      name: "IMarketServiceV1",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.IMarketServiceV1__factory>;
    getContractFactory(
      name: "LPWrapper",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.LPWrapper__factory>;
    getContractFactory(
      name: "NFT",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.NFT__factory>;
    getContractFactory(
      name: "Token",
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<Contracts.Token__factory>;

    // default types
    getContractFactory(
      name: string,
      signerOrOptions?: ethers.Signer | FactoryOptions
    ): Promise<ethers.ContractFactory>;
    getContractFactory(
      abi: any[],
      bytecode: ethers.utils.BytesLike,
      signer?: ethers.Signer
    ): Promise<ethers.ContractFactory>;
  }
}
