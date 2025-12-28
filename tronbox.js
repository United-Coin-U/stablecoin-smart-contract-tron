require('dotenv').config();

module.exports = {
  contracts_directory: './contracts',
  migrations_directory: './migrations',
  test_directory: './tests',
  networks: {
    // Default development network (used when no network is specified)
    development: {
      privateKey: process.env.PRIVATE_KEY_NILE,
      consume_user_resource_percent: 50,
      fee_limit: 1e9,
      fullHost: process.env.FULL_NODE_NILE || "https://nile.trongrid.io",
      network_id: '3448148188',
    },
    prod: {
      privateKey: process.env.PRIVATE_KEY_PROD,
      consume_user_resource_percent: 30,
      fee_limit: 1e10, // Increased to 10000 TRX for deployment
      fullHost: process.env.FULL_NODE_PROD,
      network_id: "1" // Tron mainnet
    },
    nile: {
      privateKey: process.env.PRIVATE_KEY_NILE,
      consume_user_resource_percent: 50,
      fee_limit: 1e9,
      fullHost: process.env.FULL_NODE_NILE,
      network_id: '3448148188',
    },
    shasta: {
      privateKey: process.env.PRIVATE_KEY_SHASTA,
      consume_user_resource_percent: 30,
      fee_limit: 1e10,
      fullHost: "https://api.shasta.trongrid.io",
      network_id: "2494104990" // Shasta testnet
    },
    local: {
      privateKey: process.env.PRIVATE_KEY_DEVELOPMENT,
      consume_user_resource_percent: 30,
      fee_limit: 1e10,
      fullHost: process.env.FULL_NODE_DEVELOPMENT,
      network_id: "*"
    }
  },
  compilers: {
    solc: {
      version: "0.8.22",
      settings: {
        optimizer: {
          enabled: true, // Optional optimization settings
          runs: 200,
        },
      },
    },
  }
};
