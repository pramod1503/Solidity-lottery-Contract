// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {Raffle} from "../src/Raffle.sol";
import {HelperConfig} from "../script/HelperConfig.s.sol";
import {VRFCoordinatorV2_5Mock} from "@chainlink/contracts/src/v0.8/vrf/mocks/VRFCoordinatorV2_5Mock.sol";

contract RaffleTest is Test {
    /* ========== STATE VARIABLES ========== */
    Raffle public raffle;
    HelperConfig public helperConfig;
    VRFCoordinatorV2_5Mock public vrfCoordinatorMock;

    // We will store all the config variables here for easy access in tests
    address public vrfCoordinatorAddress;
    bytes32 public keyHash;
    uint256 public subscriptionId;
    uint32 public callbackGasLimit;
    uint256 public entranceFee;
    uint256 public intervalSeconds;

    // Variables for test users
    uint256 public constant STARTING_USER_BALANCE = 10 ether;
    address public constant PLAYER = address(1);
    address public constant PLAYER_2 = address(2);

    /* ========== SETUP ========== */

    /// @notice This function is run before each test
    function setUp() public {
        // 1. Get the configuration (this will be ANVIL config by default)
        helperConfig = new HelperConfig();
        (vrfCoordinatorAddress, keyHash, subscriptionId, callbackGasLimit, entranceFee, intervalSeconds) =
            helperConfig.activeNetworkConfig();

        // 2. Deploy the mock VRF coordinator
        uint96 mockBaseFee = 0.25 ether;
        uint96 mockGasPriceLink = 1e9;
        int256 mockWeiPerUnitLink = 5e15;
        vrfCoordinatorMock = new VRFCoordinatorV2_5Mock(mockBaseFee, mockGasPriceLink, mockWeiPerUnitLink);

        // 3. Update our config with the real mock address
        vrfCoordinatorAddress = address(vrfCoordinatorMock);

        // 4. Create and fund a new subscription on the mock
        subscriptionId = vrfCoordinatorMock.createSubscription();
        vrfCoordinatorMock.fundSubscription(subscriptionId, 10 ether); // Fund with 10 mock LINK

        // 5. Deploy the Raffle contract
        raffle =
            new Raffle(vrfCoordinatorAddress, keyHash, subscriptionId, callbackGasLimit, entranceFee, intervalSeconds);

        // 6. Add the Raffle contract as a consumer on the mock
        vrfCoordinatorMock.addConsumer(subscriptionId, address(raffle));

        // 7. Give our test players some ETH
        vm.deal(PLAYER, STARTING_USER_BALANCE);
        vm.deal(PLAYER_2, STARTING_USER_BALANCE);
    }

    /* ========== TESTS ========== */

    function test_ConstructorSetsStateCorrectly() public view {
        assertEq(raffle.getEntranceFee(), entranceFee);
        assertEq(raffle.getInterval(), intervalSeconds);
        assertEq(uint256(raffle.getRaffleState()), uint256(Raffle.RaffleState.OPEN));
        // The deployer of Raffle is this test contract (address(this))
        assertEq(raffle.owner(), address(this));
    }

    function test_EnterRaffleFails_WhenNotEnoughEth() public {
        vm.prank(PLAYER); // The next transaction will be from PLAYER

        // We expect the contract to revert with our custom error
        vm.expectRevert(Raffle.Raffle__NotEnoughETHToEnter.selector);

        // Send 1 wei less than the entrance fee
        raffle.enterRaffle{value: entranceFee - 1 wei}();
    }

    function test_EnterRaffleSuccess_AddsPlayer() public {
        vm.prank(PLAYER);
        raffle.enterRaffle{value: entranceFee}();

        assertEq(raffle.getPlayer(0), PLAYER);
        assertEq(raffle.getPlayersCount(), 1);
    }

    function test_CheckUpkeepReturnsTrue_WhenAllConditionsMet() public {
        // 1. Enter a player
        vm.prank(PLAYER);
        raffle.enterRaffle{value: entranceFee}();

        // 2. Fast-forward time to pass the interval
        vm.warp(block.timestamp + intervalSeconds + 1);

        // 3. Check upkeep
        (bool upkeepNeeded,) = raffle.checkUpkeep("");
        assertEq(upkeepNeeded, true);
    }

    function test_PerformUpkeepFails_WhenCheckUpkeepIsFalse() public {
        // We expect the contract to revert with our custom error
        vm.expectRevert(abi.encodeWithSelector(Raffle.Raffle__UpkeepNotNeeded.selector, 0, 0, 0));
        raffle.performUpkeep("");
    }

    /*
     * This is the most important test!
     * It tests the entire lifecycle of the lottery in one go.
     */
    function test_FullLifecycle_PicksWinnerAndResets() public {
        // --- 1. ARRANGE (Setup the test) ---
        vm.prank(PLAYER);
        raffle.enterRaffle{value: entranceFee}();
        vm.prank(PLAYER_2);
        raffle.enterRaffle{value: entranceFee}();

        address PLAYER_3 = address(3);
        vm.deal(PLAYER_3, STARTING_USER_BALANCE);
        vm.prank(PLAYER_3);
        raffle.enterRaffle{value: entranceFee}();

        vm.warp(block.timestamp + intervalSeconds + 1);

        // --- 2. ACT (Run the functions we want to test) ---
        raffle.performUpkeep("");
        uint256 requestId = raffle.getRequestId();

        uint256[] memory randomWords = new uint256[](1);
        randomWords[0] = 101; // Results in winner index 2 (PLAYER_3)

        // --- THIS IS THE FIX ---
        // We must 'prank' as the VRF Coordinator
        vm.prank(vrfCoordinatorAddress);
        // We call the PUBLIC `rawFulfillRandomWords` which safely calls the INTERNAL `fulfillRandomWords`
        raffle.rawFulfillRandomWords(requestId, randomWords);
        // --- END FIX ---

        // --- 3. ASSERT (Check the results) ---
        assertEq(raffle.getPlayersCount(), 0);
        assertEq(uint256(raffle.getRaffleState()), uint256(Raffle.RaffleState.OPEN));
        assertEq(address(raffle).balance, 0);
        assertEq(raffle.getRecentWinner(), PLAYER_3);

        uint256 prize = entranceFee * 3;
        assertEq(PLAYER_3.balance, STARTING_USER_BALANCE - entranceFee + prize);
    }
}
