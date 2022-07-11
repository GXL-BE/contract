/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Contract, Signer, utils } from "ethers";
import { Provider } from "@ethersproject/providers";
import type { IArenaBox, IArenaBoxInterface } from "../IArenaBox";

const _abi = [
  {
    inputs: [
      {
        internalType: "address",
        name: "user",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "quantity",
        type: "uint256",
      },
    ],
    name: "mintMany",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
];

export class IArenaBox__factory {
  static readonly abi = _abi;
  static createInterface(): IArenaBoxInterface {
    return new utils.Interface(_abi) as IArenaBoxInterface;
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): IArenaBox {
    return new Contract(address, _abi, signerOrProvider) as IArenaBox;
  }
}
