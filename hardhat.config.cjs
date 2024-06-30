require("@nomicfoundation/hardhat-toolbox");



const SEPOLIA_PRIVATE_KEY = vars.get("SEPOLIA_PRIVATE_KEY");

const SEPOLIA_SCROLL_ETHERSCAN_KEY = vars.get("SEPOLIA_SCROLL_ETHERSCAN_KEY");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  optimizer: {
    enabled: true,
    runs: 1000,
    viaIR: true,
  },
  solidity: "0.8.23",
  networks: {
    scrollSepolia: {
      url: 'https://sepolia-rpc.scroll.io' || '',
      accounts:
        SEPOLIA_PRIVATE_KEY !== undefined ? [SEPOLIA_PRIVATE_KEY] : [],
      
        //process.env.PRIVATE_KEY !== undefined ? [process.env.PRIVATE_KEY] : [],
    },
  },
  etherscan: {
    apiKey: {
      scrollSepolia:  SEPOLIA_SCROLL_ETHERSCAN_KEY//process.env.SEPOLIA_SCROLL_ETHERSCAN_KEY,
    },
    customChains: [
      {
        network: 'scrollSepolia',
        chainId: 534351,
        urls: {
          apiURL: 'https://api-sepolia.scrollscan.com/api',
          browserURL: 'https://sepolia.scrollscan.com/',
        },
      },
    ],
  },
};