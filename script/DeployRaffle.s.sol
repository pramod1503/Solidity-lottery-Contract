// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Script} from "forge-std/Script.sol";
import {Raffle} from "../src/Raffle.sol";
import {HelperConfig} from "./HelperConfig.s.sol";
import {VRFCoordinatorV2_5Mock} from "@chainlink/contracts/src/v0.8/vrf/mocks/VRFCoordinatorV2_5Mock.sol";

contract DeployRaffle is Script {
    // These are the mock's parameters
    uint96 private constant MOCK_BASE_FEE = 0.25 ether;
    uint96 private constant MOCK_GAS_PRICE_LINK = 1e9; // 1 gwei LINK
    // FIX: Add the 3rd mock parameter (1 ETH = 200 LINK)
    int256 private constant MOCK_WEI_PER_UNIT_LINK = 5e15;

    Raffle public raffle;
    HelperConfig public helperConfig;

    function run() external returns (Raffle, HelperConfig) {
        // 1. Get the configuration for the current network
        helperConfig = new HelperConfig();

        // FIX: "Catch" all 6 return values from the getter function
        (
            address vrfCoordinator,
            bytes32 keyHash,
            uint256 subscriptionId,
            uint32 callbackGasLimit,
            uint256 entranceFee,
            uint256 intervalSeconds
        ) = helperConfig.activeNetworkConfig();

        // 2. Check if we are on a local network
        if (block.chainid == 31337) {
            // We are on Anvil (local)
            vm.startBroadcast();

            // FIX: Pass all 3 arguments to the mock constructor
            VRFCoordinatorV2_5Mock vrfCoordinatorMock =
                new VRFCoordinatorV2_5Mock(MOCK_BASE_FEE, MOCK_GAS_PRICE_LINK, MOCK_WEI_PER_UNIT_LINK);

            uint256 subId = vrfCoordinatorMock.createSubscription();
            vrfCoordinatorMock.fundSubscription(subId, 10 ether);

            // 2d. Update the config with the mock's real address and new subId
            vrfCoordinator = address(vrfCoordinatorMock);
            subscriptionId = subId;
            vm.stopBroadcast();
        }

        // 3. Deploy the Raffle contract using the config
        vm.startBroadcast();
        raffle = new Raffle(vrfCoordinator, keyHash, subscriptionId, callbackGasLimit, entranceFee, intervalSeconds);
        vm.stopBroadcast();

        // 4. If local, add the new raffle contract as a consumer
        if (block.chainid == 31337) {
            vm.startBroadcast();
            VRFCoordinatorV2_5Mock(vrfCoordinator).addConsumer(subscriptionId, address(raffle));
            vm.stopBroadcast();
        }

        return (raffle, helperConfig);
    }
}
