// https://hardhat.org/ignition/docs/getting-started#creating-your-first-module
const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");

module.exports = buildModule("Token", (m) => {
  const verifier = m.contract("plonk_vk", []);
  const verifierAddress = token.getAddress()

  const token = m.contract("Token", [verifierAddress]);

  //m.call(apollo, "launch", []);

  return { token };
});