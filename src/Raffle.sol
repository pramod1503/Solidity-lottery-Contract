// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/* ========== IMPORTS ========== */

// Chainlink VRF v2.5+
import "@chainlink/contracts/src/v0.8/vrf/dev/VRFConsumerBaseV2Plus.sol";
import "@chainlink/contracts/src/v0.8/vrf/dev/interfaces/IVRFCoordinatorV2Plus.sol";
import "@chainlink/contracts/src/v0.8/vrf/dev/libraries/VRFV2PlusClient.sol";

// Chainlink Automation
import "@chainlink/contracts/src/v0.8/automation/AutomationCompatible.sol";

// OpenZeppelin v5+ (REMOVED Ownable.sol)
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/* ========== CONTRACT ========== */

// FIX: Removed "Ownable" from the inheritance list
contract Raffle is VRFConsumerBaseV2Plus, AutomationCompatible, ReentrancyGuard, Pausable {
    /* ========== ERRORS ========== */
    error Raffle__NotEnoughETHToEnter();
    error Raffle__NotEnoughTimePassed();
    error Raffle__TransferFailed();
    error Raffle__NotOpen();
    error Raffle__UpkeepNotNeeded(uint256 playersCount, uint256 contractBalance, uint256 raffleState);
    error Raffle__InvalidConstructorParam();
    error Raffle__NotFromCoordinator();
    error Raffle__NoRandomWords();
    error Raffle__WithdrawFailed();

    /* ========== TYPES ========== */
    enum RaffleState {
        OPEN,
        CALCULATING,
        PAUSED
    }

    /* ========== STATE VARIABLES ========== */
    uint256 public immutable i_entranceFee;
    address payable[] private s_players;
    uint256 private i_interval;
    uint256 private s_lastTimeStamp;
    address payable public s_recentWinner;
    RaffleState private s_raffleState;

    /* Chainlink VRF v2.5+ variables */
    IVRFCoordinatorV2Plus private immutable i_vrfCoordinator;
    bytes32 private immutable i_keyHash;
    uint256 public immutable i_subscriptionId;
    uint32 private immutable i_callbackGasLimit;
    uint16 private constant REQUEST_CONFIRMATIONS = 3;
    uint32 private constant NUM_WORDS = 1;
    uint256 private s_requestId;

    /* ========== EVENTS ========== */
    event RaffleEnter(address indexed player);
    event RequestedRandomWords(uint256 indexed requestId);
    event WinnerPicked(address indexed winner);
    event EmergencyWithdraw(address indexed to, uint256 amount);
    event RafflePaused();
    event RaffleUnpaused();
    
    // NOTE: We will use the OwnershipTransferred event already built into VRFConsumerBaseV2Plus's parent

    /* ========== CONSTRUCTOR ========== */
    constructor(
        address vrfCoordinator,
        bytes32 keyHash,
        uint256 subscriptionId,
        uint32 callbackGasLimit,
        uint256 entranceFee,
        uint256 intervalSeconds
    )
        VRFConsumerBaseV2Plus(vrfCoordinator)
        // FIX: Removed "Ownable(msg.sender)"
    {
        // Basic input validation
        if (
            vrfCoordinator == address(0) || subscriptionId == 0 || callbackGasLimit == 0 || entranceFee == 0
                || intervalSeconds == 0
        ) {
            revert Raffle__InvalidConstructorParam();
        }

        i_vrfCoordinator = IVRFCoordinatorV2Plus(vrfCoordinator);
        i_keyHash = keyHash;
        i_subscriptionId = subscriptionId;
        i_callbackGasLimit = callbackGasLimit;
        i_entranceFee = entranceFee;
        i_interval = intervalSeconds;
        s_lastTimeStamp = block.timestamp;
        s_raffleState = RaffleState.OPEN;

        // NOTE: msg.sender is AUTOMATICALLY set as the owner
        // by the constructor of the "ConfirmedOwner" contract
        // which VRFConsumerBaseV2Plus inherits.
    }

    /* ========== PUBLIC FUNCTIONS ========== */

    /// @notice Enter the raffle by paying exactly the entrance fee
    function enterRaffle() external payable whenNotPaused nonReentrant {
        if (s_raffleState != RaffleState.OPEN) {
            revert Raffle__NotOpen();
        }
        if (msg.value < i_entranceFee) {
            revert Raffle__NotEnoughETHToEnter();
        }

        s_players.push(payable(msg.sender));
        emit RaffleEnter(msg.sender);
    }

    /// @notice Chainlink Automation reads this to determine if performUpkeep should be called
    function checkUpkeep(bytes calldata) external view override returns (bool upkeepNeeded, bytes memory) {
        return _checkUpkeep();
    }

    /// @notice Called by Chainlink Automation to trigger randomness request
    function performUpkeep(bytes calldata) external override whenNotPaused {
        (bool upkeepNeeded,) = _checkUpkeep();
        if (!upkeepNeeded) {
            revert Raffle__UpkeepNotNeeded(s_players.length, address(this).balance, uint256(s_raffleState));
        }

        s_raffleState = RaffleState.CALCULATING;

        VRFV2PlusClient.RandomWordsRequest memory request = VRFV2PlusClient.RandomWordsRequest({
            keyHash: i_keyHash,
            subId: i_subscriptionId,
            requestConfirmations: REQUEST_CONFIRMATIONS,
            callbackGasLimit: i_callbackGasLimit,
            numWords: NUM_WORDS,
           extraArgs: VRFV2PlusClient._argsToBytes(
           VRFV2PlusClient.ExtraArgsV1({nativePayment: false})
)
        });

        uint256 requestId = i_vrfCoordinator.requestRandomWords(request);
        s_requestId = requestId;
        emit RequestedRandomWords(requestId);
    }

    /* ========== VRF CALLBACK ========== */

    /// @dev VRFCoordinator will call this.
    // FIX: Renamed from _fulfillRandomWords to fulfillRandomWords
    function fulfillRandomWords(uint256, uint256[] calldata randomWords) internal override {
        if (msg.sender != address(i_vrfCoordinator)) {
            revert Raffle__NotFromCoordinator();
        }

        if (randomWords.length == 0) {
            revert Raffle__NoRandomWords();
        }

        uint256 randomNumber = randomWords[0];
        uint256 playersCount = s_players.length;
        
        if (playersCount == 0) {
            s_raffleState = RaffleState.OPEN;
            return;
        }

        uint256 winnerIndex = randomNumber % playersCount;
        address payable winner = s_players[winnerIndex];

        // Effects
        s_recentWinner = winner;
        s_raffleState = RaffleState.OPEN;
        s_lastTimeStamp = block.timestamp;
        delete s_players; // Resets array

        emit WinnerPicked(s_recentWinner);

        // Interaction
        (bool success,) = s_recentWinner.call{value: address(this).balance}("");
        if (!success) {
            revert Raffle__TransferFailed();
        }
    }

    /* ========== OWNER / EMERGENCY FUNCTIONS ========== */

    /// @notice Pause new entries and upkeep (emergency)
    // NOTE: "onlyOwner" modifier is inherited from VRFConsumerBaseV2Plus
    function pauseRaffle() external onlyOwner {
        _pause();
        s_raffleState = RaffleState.PAUSED;
        emit RafflePaused();
    }

    /// @notice Unpause raffle (owner)
    // NOTE: "onlyOwner" modifier is inherited from VRFConsumerBaseV2Plus
    function unpauseRaffle() external onlyOwner {
        _unpause();
        s_raffleState = RaffleState.OPEN;
        emit RaffleUnpaused();
    }

    /// @notice Emergency withdraw by owner
    // NOTE: "onlyOwner" modifier is inherited from VRFConsumerBaseV2Plus
    function emergencyWithdraw(address payable to) external onlyOwner {
        uint256 bal = address(this).balance;
        (bool sent,) = to.call{value: bal}("");
        if (!sent) revert Raffle__WithdrawFailed();
        emit EmergencyWithdraw(to, bal);
    }
    
    // NOTE: The functions transferOwnership(), owner(), etc.
    // are all inherited from VRFConsumerBaseV2Plus and will work.

    /* ========== VIEW / GETTERS ========== */

    function getEntranceFee() external view returns (uint256) {
        return i_entranceFee;
    }

    function getRecentWinner() external view returns (address) {
        return s_recentWinner;
    }

    function getPlayer(uint256 index) external view returns (address) {
        return s_players[index];
    }

    function getPlayersCount() external view returns (uint256) {
        return s_players.length;
    }

    function getRaffleState() external view returns (RaffleState) {
        return s_raffleState;
    }

    function getRequestId() external view returns (uint256) {
        return s_requestId;
    }

    function getLastTimeStamp() external view returns (uint256) {
        return s_lastTimeStamp;
    }

    function getInterval() external view returns (uint256) {
        return i_interval;
    }

    /* ========== INTERNAL HELPERS ========== */

    /// @dev Internal view of checkUpkeep. This is the single source of truth.
    function _checkUpkeep() internal view returns (bool upkeepNeeded, bytes memory) {
        bool timeHasPassed = (block.timestamp - s_lastTimeStamp) >= i_interval;
        bool isOpen = (s_raffleState == RaffleState.OPEN);
        bool hasPlayers = s_players.length > 0;
        bool hasBalance = address(this).balance > 0;
        upkeepNeeded = (timeHasPassed && isOpen && hasPlayers && hasBalance);
        return (upkeepNeeded, bytes(""));
    }

    /* ========== RECEIVE / FALLBACK ========== */
    
    receive() external payable {
        revert("Use enterRaffle()");
    }

    fallback() external payable {
        revert("Use enterRaffle()");
    }
}