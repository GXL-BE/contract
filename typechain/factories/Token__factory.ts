/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Signer, utils, Contract, ContractFactory, Overrides } from "ethers";
import { Provider, TransactionRequest } from "@ethersproject/providers";
import type { Token, TokenInterface } from "../Token";

const _abi = [
  {
    inputs: [
      {
        internalType: "string",
        name: "_name",
        type: "string",
      },
      {
        internalType: "string",
        name: "_symbol",
        type: "string",
      },
    ],
    stateMutability: "nonpayable",
    type: "constructor",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "owner",
        type: "address",
      },
      {
        indexed: true,
        internalType: "address",
        name: "spender",
        type: "address",
      },
      {
        indexed: false,
        internalType: "uint256",
        name: "value",
        type: "uint256",
      },
    ],
    name: "Approval",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "from",
        type: "address",
      },
      {
        indexed: true,
        internalType: "address",
        name: "to",
        type: "address",
      },
      {
        indexed: false,
        internalType: "uint256",
        name: "value",
        type: "uint256",
      },
    ],
    name: "Transfer",
    type: "event",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "owner",
        type: "address",
      },
      {
        internalType: "address",
        name: "spender",
        type: "address",
      },
    ],
    name: "allowance",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "spender",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "amount",
        type: "uint256",
      },
    ],
    name: "approve",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "account",
        type: "address",
      },
    ],
    name: "balanceOf",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "decimals",
    outputs: [
      {
        internalType: "uint8",
        name: "",
        type: "uint8",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "spender",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "subtractedValue",
        type: "uint256",
      },
    ],
    name: "decreaseAllowance",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "spender",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "addedValue",
        type: "uint256",
      },
    ],
    name: "increaseAllowance",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "user",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "amount",
        type: "uint256",
      },
    ],
    name: "mint",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "name",
    outputs: [
      {
        internalType: "string",
        name: "",
        type: "string",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "symbol",
    outputs: [
      {
        internalType: "string",
        name: "",
        type: "string",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "totalSupply",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "recipient",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "amount",
        type: "uint256",
      },
    ],
    name: "transfer",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "sender",
        type: "address",
      },
      {
        internalType: "address",
        name: "recipient",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "amount",
        type: "uint256",
      },
    ],
    name: "transferFrom",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
];

const _bytecode =
  "0x60806040523480156200001157600080fd5b5060405162000f6a38038062000f6a8339810160408190526200003491620002ec565b8151829082906200004d90600390602085019062000193565b5080516200006390600490602084019062000193565b5050506200009e336200007b620000a660201b60201c565b6200008890600a620003b7565b6200009890633b9aca0062000485565b620000ab565b505062000510565b601290565b6001600160a01b038216620001065760405162461bcd60e51b815260206004820152601f60248201527f45524332303a206d696e7420746f20746865207a65726f206164647265737300604482015260640160405180910390fd5b80600260008282546200011a919062000353565b90915550506001600160a01b038216600090815260208190526040812080548392906200014990849062000353565b90915550506040518181526001600160a01b038316906000907fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef9060200160405180910390a35050565b828054620001a190620004a7565b90600052602060002090601f016020900481019282620001c5576000855562000210565b82601f10620001e057805160ff191683800117855562000210565b8280016001018555821562000210579182015b8281111562000210578251825591602001919060010190620001f3565b506200021e92915062000222565b5090565b5b808211156200021e576000815560010162000223565b600082601f8301126200024a578081fd5b81516001600160401b0380821115620002675762000267620004fa565b604051601f8301601f19908116603f01168101908282118183101715620002925762000292620004fa565b81604052838152602092508683858801011115620002ae578485fd5b8491505b83821015620002d15785820183015181830184015290820190620002b2565b83821115620002e257848385830101525b9695505050505050565b60008060408385031215620002ff578182fd5b82516001600160401b038082111562000316578384fd5b620003248683870162000239565b935060208501519150808211156200033a578283fd5b50620003498582860162000239565b9150509250929050565b60008219821115620003695762000369620004e4565b500190565b600181815b80851115620003af578160001904821115620003935762000393620004e4565b80851615620003a157918102915b93841c939080029062000373565b509250929050565b6000620003c860ff841683620003cf565b9392505050565b600082620003e0575060016200047f565b81620003ef575060006200047f565b8160018114620004085760028114620004135762000433565b60019150506200047f565b60ff841115620004275762000427620004e4565b50506001821b6200047f565b5060208310610133831016604e8410600b841016171562000458575081810a6200047f565b6200046483836200036e565b80600019048211156200047b576200047b620004e4565b0290505b92915050565b6000816000190483118215151615620004a257620004a2620004e4565b500290565b600181811c90821680620004bc57607f821691505b60208210811415620004de57634e487b7160e01b600052602260045260246000fd5b50919050565b634e487b7160e01b600052601160045260246000fd5b634e487b7160e01b600052604160045260246000fd5b610a4a80620005206000396000f3fe608060405234801561001057600080fd5b50600436106100d45760003560e01c806340c10f1911610081578063a457c2d71161005b578063a457c2d7146101a7578063a9059cbb146101ba578063dd62ed3e146101cd57600080fd5b806340c10f191461016157806370a082311461017657806395d89b411461019f57600080fd5b806323b872dd116100b257806323b872dd1461012c578063313ce5671461013f578063395093511461014e57600080fd5b806306fdde03146100d9578063095ea7b3146100f757806318160ddd1461011a575b600080fd5b6100e1610206565b6040516100ee919061096a565b60405180910390f35b61010a610105366004610941565b610298565b60405190151581526020016100ee565b6002545b6040519081526020016100ee565b61010a61013a366004610906565b6102ae565b604051601281526020016100ee565b61010a61015c366004610941565b610379565b61017461016f366004610941565b6103b0565b005b61011e6101843660046108b3565b6001600160a01b031660009081526020819052604090205490565b6100e16103be565b61010a6101b5366004610941565b6103cd565b61010a6101c8366004610941565b610480565b61011e6101db3660046108d4565b6001600160a01b03918216600090815260016020908152604080832093909416825291909152205490565b606060038054610215906109ec565b80601f0160208091040260200160405190810160405280929190818152602001828054610241906109ec565b801561028e5780601f106102635761010080835404028352916020019161028e565b820191906000526020600020905b81548152906001019060200180831161027157829003601f168201915b5050505050905090565b60006102a533848461048d565b50600192915050565b60006102bb8484846105b1565b6001600160a01b03841660009081526001602090815260408083203384529091529020548281101561035a5760405162461bcd60e51b815260206004820152602860248201527f45524332303a207472616e7366657220616d6f756e742065786365656473206160448201527f6c6c6f77616e636500000000000000000000000000000000000000000000000060648201526084015b60405180910390fd5b61036e853361036986856109d5565b61048d565b506001949350505050565b3360008181526001602090815260408083206001600160a01b038716845290915281205490916102a59185906103699086906109bd565b6103ba82826107b8565b5050565b606060048054610215906109ec565b3360009081526001602090815260408083206001600160a01b0386168452909152812054828110156104675760405162461bcd60e51b815260206004820152602560248201527f45524332303a2064656372656173656420616c6c6f77616e63652062656c6f7760448201527f207a65726f0000000000000000000000000000000000000000000000000000006064820152608401610351565b610476338561036986856109d5565b5060019392505050565b60006102a53384846105b1565b6001600160a01b0383166104ef5760405162461bcd60e51b8152602060048201526024808201527f45524332303a20617070726f76652066726f6d20746865207a65726f206164646044820152637265737360e01b6064820152608401610351565b6001600160a01b0382166105505760405162461bcd60e51b815260206004820152602260248201527f45524332303a20617070726f766520746f20746865207a65726f206164647265604482015261737360f01b6064820152608401610351565b6001600160a01b0383811660008181526001602090815260408083209487168084529482529182902085905590518481527f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925910160405180910390a3505050565b6001600160a01b03831661062d5760405162461bcd60e51b815260206004820152602560248201527f45524332303a207472616e736665722066726f6d20746865207a65726f20616460448201527f64726573730000000000000000000000000000000000000000000000000000006064820152608401610351565b6001600160a01b03821661068f5760405162461bcd60e51b815260206004820152602360248201527f45524332303a207472616e7366657220746f20746865207a65726f206164647260448201526265737360e81b6064820152608401610351565b6001600160a01b0383166000908152602081905260409020548181101561071e5760405162461bcd60e51b815260206004820152602660248201527f45524332303a207472616e7366657220616d6f756e742065786365656473206260448201527f616c616e636500000000000000000000000000000000000000000000000000006064820152608401610351565b61072882826109d5565b6001600160a01b03808616600090815260208190526040808220939093559085168152908120805484929061075e9084906109bd565b92505081905550826001600160a01b0316846001600160a01b03167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040516107aa91815260200190565b60405180910390a350505050565b6001600160a01b03821661080e5760405162461bcd60e51b815260206004820152601f60248201527f45524332303a206d696e7420746f20746865207a65726f2061646472657373006044820152606401610351565b806002600082825461082091906109bd565b90915550506001600160a01b0382166000908152602081905260408120805483929061084d9084906109bd565b90915550506040518181526001600160a01b038316906000907fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef9060200160405180910390a35050565b80356001600160a01b03811681146108ae57600080fd5b919050565b6000602082840312156108c4578081fd5b6108cd82610897565b9392505050565b600080604083850312156108e6578081fd5b6108ef83610897565b91506108fd60208401610897565b90509250929050565b60008060006060848603121561091a578081fd5b61092384610897565b925061093160208501610897565b9150604084013590509250925092565b60008060408385031215610953578182fd5b61095c83610897565b946020939093013593505050565b6000602080835283518082850152825b818110156109965785810183015185820160400152820161097a565b818111156109a75783604083870101525b50601f01601f1916929092016040019392505050565b600082198211156109d0576109d0610a27565b500190565b6000828210156109e7576109e7610a27565b500390565b600181811c90821680610a0057607f821691505b60208210811415610a2157634e487b7160e01b600052602260045260246000fd5b50919050565b634e487b7160e01b600052601160045260246000fdfea164736f6c6343000804000a";

export class Token__factory extends ContractFactory {
  constructor(signer?: Signer) {
    super(_abi, _bytecode, signer);
  }

  deploy(
    _name: string,
    _symbol: string,
    overrides?: Overrides & { from?: string | Promise<string> }
  ): Promise<Token> {
    return super.deploy(_name, _symbol, overrides || {}) as Promise<Token>;
  }
  getDeployTransaction(
    _name: string,
    _symbol: string,
    overrides?: Overrides & { from?: string | Promise<string> }
  ): TransactionRequest {
    return super.getDeployTransaction(_name, _symbol, overrides || {});
  }
  attach(address: string): Token {
    return super.attach(address) as Token;
  }
  connect(signer: Signer): Token__factory {
    return super.connect(signer) as Token__factory;
  }
  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): TokenInterface {
    return new utils.Interface(_abi) as TokenInterface;
  }
  static connect(address: string, signerOrProvider: Signer | Provider): Token {
    return new Contract(address, _abi, signerOrProvider) as Token;
  }
}