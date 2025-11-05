// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Script} from "forge-std/Script.sol";

contract HelperConfig is Script {
    // This struct holds all the parameters for our Raffle constructor
    struct NetworkConfig {
        address vrfCoordinator;
        bytes32 keyHash;
        uint256 subscriptionId;
        uint32 callbackGasLimit;
        uint256 entranceFee;
        uint256 intervalSeconds;
    }

    NetworkConfig public activeNetworkConfig;

    constructor() {
        // 11155111 is the chainId for Sepolia
        if (block.chainid == 11155111) {
            activeNetworkConfig = getSepoliaConfig();
        } else {
            // Default to local/Anvil config
            activeNetworkConfig = getAnvilConfig();
        }
    }

    function getSepoliaConfig() public pure returns (NetworkConfig memory) {
        return NetworkConfig({
            // Sepolia VRF v2.5 Coordinator
            vrfCoordinator: 0x9DdfaCa8183c41ad55329BdeeD9F6A8d53168B1B,
            // 150 gwei KeyHash (150,000,000,000)
            keyHash: 0x787d74caea10b2b357790d5b5247c2f63d1d91572a9846f780606e4d953677ae,
            // Your Sepolia subscription ID (replace this)
            subscriptionId: 96044357289078877141748840037071824057617118572030550441307414427372018905762, 
            callbackGasLimit: 500000, // 500,000 gas
            entranceFee: 0.01 ether,
            intervalSeconds: 30
        });
    }

    function getAnvilConfig() public pure returns (NetworkConfig memory) {
        return NetworkConfig({
            vrfCoordinator: address(0), // Will be replaced by mock
            keyHash: 0x474e34a077df58807dbe9c96d3c009b23b3c6d0cce433e59bbf5b34f823bc56c, // Can be the same
            subscriptionId: 0, // Will be created in deploy script
            callbackGasLimit: 500000,
            entranceFee: 0.01 ether,
            intervalSeconds: 30
        });
    }
}