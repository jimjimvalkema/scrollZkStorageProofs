import { ethers } from 'ethers';
window.ethers = ethers

import circuit from '../circuits/smolProver/target/zkwormholesEIP7503.json';
import { BarretenbergBackend, BarretenbergVerifier as Verifier } from '@noir-lang/backend_barretenberg';
import { Noir } from '@noir-lang/noir_js';


import { abi as contractAbi } from '../artifacts/contracts/Token.sol/Token.json'
import { getSafeRandomNumber , getProofInputs, hashNullifier, hashBurnAddress} from '../scripts/getProofInputs'
const CONTRACT_ADDRESS = "0x20EF4cC5d68198acacDe4468107314A629522d6E"
const FIELD_LIMIT = 21888242871839275222246405745257275088548364400416034343698204186575808495617n //using poseidon so we work with 254 bits instead of 256
const CHAININFO = {
  chainId: "0x8274f",
  rpcUrls: ["https://sepolia-rpc.scroll.io/"],
  chainName: "scroll sepolia",
  nativeCurrency: {
    name: "Ethereum",
    symbol: "ETH",
    decimals: 18
  },
  blockExplorerUrls: ["https://sepolia.scrollscan.com"]
}


async function dumpErrorsInUi(func, args = []) {
  try {
    return await func(...args)
  } catch (error) {
    console.error(error)
    document.querySelector("#errors").innerText += `${func.name}:${error}`
  }
}

async function switchNetwork(network, provider) {
  try {
    await provider.send("wallet_switchEthereumChain", [{ chainId: network.chainId }]);

  } catch (switchError) {
    window.switchError = switchError
    // This error code indicates that the chain has not been added to MetaMask.
    if (switchError.error && switchError.error.code === 4902) {
      try {
        await provider.send("wallet_addEthereumChain", [network]);

      } catch (addError) {
        // handle "add" error
      }
    }
    // handle other "switch" errors
  }
}

async function getContractWithSigner({ abi = contractAbi, chain = CHAININFO, contractAddress = CONTRACT_ADDRESS } = {}) {
  return await dumpErrorsInUi(
    async () => {
      const provider = new ethers.BrowserProvider(window.ethereum)
      window.provider = provider //debug moment
      await switchNetwork(chain, provider)
      const signer = await provider.getSigner();
      const contract = new ethers.Contract(contractAddress, abi, signer)
      return { contract, signer }
    }
  )
}

async function getContractInfo(contract, signer) {
  const [userBalance, decimals, name, symbol, totalSupply] = await Promise.all([
    contract.balanceOf(signer.address),
    contract.decimals(),
    contract.name(),
    contract.symbol(),
    contract.totalSupply()
  ])
  return {
    userBalance: ethers.formatUnits(userBalance, decimals),
    totalSupply: ethers.formatUnits(totalSupply, decimals),
    decimals, name, symbol
  }
}

function setContractInfoUi({ userBalance, name, symbol }) {
  //console.log({ userBalance, name, symbol });
  [...document.querySelectorAll(".userBalance")].map((el) => el.innerText = userBalance);
  [...document.querySelectorAll(".tokenName")].map((el) => el.innerText = name);
  [...document.querySelectorAll(".ticker")].map((el) => el.innerText = symbol);
}

async function refreshUiInfo({ contract,signer }) {
  const { userBalance, totalSupply, decimals, name, symbol } = await getContractInfo(contract, signer)
  setContractInfoUi({ userBalance, name, symbol })
  await listRemintableBurnsLocalstorage({ contract, signer})
}

function messageUi(message, append=false) {
  if (append) {
    document.getElementById("messages").innerHTML += message
  } else {
    document.getElementById("messages").innerHTML = message
  }
  console.log(message)
}

async function putTxInUi(tx) {
  const explorer = CHAININFO.blockExplorerUrls[0]
  const url = `${explorer}/tx/${tx.hash}`
  messageUi(`tx submitted: <a href=${url}>${url}</a>`)
  return tx
}

async function mintBtnHandler({ contract, decimals, signer }) {
  return await dumpErrorsInUi(async () => {
    const amountUnparsed = document.getElementById("mintAmountInput").value
    const amount = ethers.parseUnits(amountUnparsed, decimals)
    const tx = await contract.mint(signer.address, amount)
    await putTxInUi(tx)
    await tx.wait(1)

    //TODO this is janky af
    await refreshUiInfo({ contract,signer })
  })
}

function addBurnToLocalStorage({ secret, burnAddress, from, txHash }) {
  secret = ethers.toBeHex(secret)
  const prevBurns = JSON.parse(localStorage.getItem(CONTRACT_ADDRESS))
  let allBurns = {}
  if (prevBurns !== null) allBurns = prevBurns
  allBurns[burnAddress] = { secret, txHash, from }
  localStorage.setItem(CONTRACT_ADDRESS, JSON.stringify(allBurns))
}

async function listRemintableBurnsLocalstorage({ contract,signer }) {
  return await dumpErrorsInUi(async () => {
    const decimals = await contract.decimals()
    const burnedTokensUi = document.getElementById("burnedTokens")
    burnedTokensUi.innerHTML = ""
    const allBurns = JSON.parse(localStorage.getItem(CONTRACT_ADDRESS))
    if (!allBurns) return;
    
    for (const burnAddress in allBurns) {
      const { secret, txHash, from } = allBurns[burnAddress]
      //console.log( { secret, txHash, from } )
      //TODO do async
      const burnBalance = await contract.balanceOf(burnAddress)
      if (txHash || burnBalance > 0n) { // no tx? no balance? nothing there!
        const remintUiLi = await makeRemintUi({secret, burnBalance, burnAddress, txHash, from, contract,decimals,signer })
        burnedTokensUi.append(remintUiLi)
      }
    }
  })
}


function br() {
  return document.createElement("br")
}


async function makeRemintUi({ secret,burnBalance, burnAddress, txHash, from, contract,decimals ,signer}) {
  const explorer = CHAININFO.blockExplorerUrls[0]

  //info
  const li = document.createElement("li")
  const fromEl = document.createElement("a")
  const burnEl = document.createElement("a")
  fromEl.className = "address"
  burnEl.className = "address"
  fromEl.innerText = from
  burnEl.innerText = burnAddress
  fromEl.href = `${explorer}/address/${from}`
  burnEl.href = `${explorer}/address/${burnAddress}`
  li.append(
    `from-address: `,fromEl,
    br(),
    ` burn-address: `,burnEl,
    br(),
    `amount: ${ethers.formatUnits(burnBalance, decimals)},`,
  )
  if (txHash) {
    const txHashEl = document.createElement("a")
    txHashEl.innerText = `${txHash}`
    txHashEl.href = `${explorer}/tx/${txHash}`
    li.append(br(), `tx: `,txHashEl)
  }

  //button
  const nullifier = hashNullifier(secret)

  const isNullified = await contract.nullifiers(nullifier)
  console.log({secret, burnAddress, nullifier,isNullified})
  if (isNullified) {
    li.append(
      br(),
      "already reminted"
    )
    li.style.textDecoration = "line-through"
  } else {
    const remintBtn = document.createElement("button")
    remintBtn.innerText = "remint"
    li.append(
      br(),
      remintBtn
    )
    remintBtn.addEventListener("click", ()=>remintBtnHandler({ to:signer.address, contract, secret,signer }))
  }
  return li
}

async function creatSnarkProof({ proofInputsNoirJs, circuit = circuit }) {
  if (window.crossOriginIsolated === false) {
    messageUi(`
      <b>NOTICE</b>: prover can only use <b>1 core</b>. This can take  <b>7~10min :/</b>\n <br>
      This is because window.crossOriginIsolated = false. <br>
      This is likely because the server running this has not set it's cors header properly \n <br>
      They need to be like this: \n <br>
      <code>
        ...<br>
        "Cross-Origin-Embedder-Policy":"require-corp"<br>
        "Cross-Origin-Opener-Policy":"same-origin"<br>
        ...<br>
      </code>
      `)
  }
  const backend = new BarretenbergBackend(circuit);
  
  //---debug
  if (window.crossOriginIsolated === true) {
    messageUi("initializing prover 🤖")
    await backend.instantiate()
    messageUi(`
      wow window.crossOriginIsolated is set to true
      i can use ${backend.options.threads} cores now 😎
      `)
  }
  //--
  
  const noir = new Noir(circuit, backend)

  // pre noirjs 0.31.0 \/
  //const proof = await noir.generateProof(proofInputsNoirJs);
  const { witness } = await noir.execute(proofInputsNoirJs);
  const proof = await backend.generateProof(witness);

  //TODO remove this debug

  // pre noirjs 0.31.0 \/
  //const verified = await noir.verifyProof(proof)
  const verified = await backend.verifyProof(proof)
  console.log({ verified })

  return proof 
}

async function remintBtnHandler({ to, contract, secret , signer}) {
  return await dumpErrorsInUi(async () => {
    const provider = contract.runner.provider
    const MAX_HASH_PATH_SIZE = 26;//248;//30; //this is the max tree depth in scroll: https://docs.scroll.io/en/technology/sequencer/zktrie/#tree-construction
    const MAX_RLP_SIZE = 650

    const blockNumber = BigInt(await provider.getBlockNumber("latest"))
    const proofInputs = await getProofInputs(contract.target, blockNumber, to, secret, provider, MAX_HASH_PATH_SIZE, MAX_RLP_SIZE)
    console.log({proofInputs})
    const amount = proofInputs.proofData.burnedTokenBalance

    const proof = await creatSnarkProof({ proofInputsNoirJs: proofInputs.noirJsInputs, circuit: circuit })
    //console.log({proof})
    
    const remintInputs = {
      to,
      amount,
      blockNumber, //blockNumber: BigInt(proofInputs.blockData.block.number),
      nullifier: ethers.toBeHex(proofInputs.proofData.nullifier),
      snarkProof: ethers.hexlify(proof.proof),

    }
    // console.log("------------remint tx inputs----------------")
    console.log({ remintInputs })
    // console.log("---------------------------------------")

    const setBlockHashTx = await contract.setBlockHash(proofInputs.blockData.block.hash,remintInputs.blockNumber)
    await putTxInUi(await setBlockHashTx)
    messageUi("\n waiting for 2 confirmations for `setBlockHash` transaction to confirm\n after that you can finally remint!!!",true)
    await setBlockHashTx.wait(2)
    const remintTx =await contract.reMint(remintInputs.to, remintInputs.amount, remintInputs.blockNumber, remintInputs.nullifier, remintInputs.snarkProof)
    await putTxInUi(await remintTx)
    await remintTx.wait(1)

    //TODO this is janky af
    await refreshUiInfo({ contract,signer})
  })

}

async function burnBtnHandler({ contract, decimals, signer }) {
  return await dumpErrorsInUi(async () => {
    const amountUnparsed = document.getElementById("burnAmount").value
    const amount = ethers.parseUnits(amountUnparsed, decimals)

    const secret = getSafeRandomNumber()
    const burnAddress = hashBurnAddress(secret) // take only last 20 bytes (because eth address are 20 bytes)
    const from = signer.address
    addBurnToLocalStorage({ secret, burnAddress, from, txHash: null }) // user can exit page and then submit the txs so we save it before the burn just in case
    const burnTx = await contract.transfer(burnAddress, amount)
    addBurnToLocalStorage({ secret, burnAddress, from, txHash: burnTx.hash }) // we got a txhash now
    await putTxInUi(burnTx)
    await burnTx.wait(1)
    await refreshUiInfo({contract,signer})
  })

}

function setEventListeners({ contract, decimals, signer }) {
  document.getElementById("mintBtn").addEventListener("click", async () => await mintBtnHandler({ contract, decimals, signer }))
  document.getElementById("burnBtn").addEventListener("click", async () => await burnBtnHandler({ contract, decimals, signer }))
}

async function main() {
  const { contract, signer } = await getContractWithSigner()
  const { userBalance, totalSupply, decimals, name, symbol } = await getContractInfo(contract, signer)
  setContractInfoUi({ userBalance, name, symbol })
  setEventListeners({ contract, decimals, signer })
  await listRemintableBurnsLocalstorage({contract, signer})



  //--------------------------
  window.contract = contract
  window.signer = signer
}

await main()