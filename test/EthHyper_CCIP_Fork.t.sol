// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

// CCIP Local (fork mode)
import {CCIPLocalSimulatorFork, Register} from "@chainlink/local/src/ccip/CCIPLocalSimulatorFork.sol";

// CCIP client + pools
import {IRouterClient} from "@chainlink/contracts-ccip/contracts/interfaces/IRouterClient.sol";
import {Client} from "@chainlink/contracts-ccip/contracts/libraries/Client.sol";
import {BurnMintTokenPool} from "@chainlink/contracts-ccip/contracts/pools/BurnMintTokenPool.sol";
import {IBurnMintERC20} from "@chainlink/contracts/src/v0.8/shared/token/ERC20/IBurnMintERC20.sol";

import {ERC20, ERC20Burnable} from "@chainlink/contracts/src/v0.8/vendor/openzeppelin-solidity/v4.8.3/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import {AccessControl} from "@chainlink/contracts/src/v0.8/vendor/openzeppelin-solidity/v4.8.3/contracts/access/AccessControl.sol";
import {TokenPool} from "@chainlink/contracts-ccip/contracts/pools/TokenPool.sol";
import {RateLimiter} from "@chainlink/contracts-ccip/contracts/libraries/RateLimiter.sol";
import {TokenAdminRegistry} from "@chainlink/contracts-ccip/contracts/tokenadminregistry/TokenAdminRegistry.sol";
import {RegistryModuleOwnerCustom} from "@chainlink/contracts-ccip/contracts/tokenAdminRegistry/RegistryModuleOwnerCustom.sol";

/// @dev Simple Burn/Mint token with getCCIPAdmin() per CCT guides.
contract MockCCT is ERC20Burnable, AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
    address internal immutable i_admin;

    constructor(
        string memory name_,
        string memory symbol_
    ) ERC20(name_, symbol_) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);
        _grantRole(BURNER_ROLE, msg.sender);
        i_admin = msg.sender;
    }

    // --- IBurnMintERC20 specific ---
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        _mint(to, amount);
    }

    function burn(
        address account,
        uint256 amount
    ) public onlyRole(BURNER_ROLE) {
        _burn(account, amount);
    }

    function burnFrom(
        address account,
        uint256 amount
    ) public override onlyRole(BURNER_ROLE) {
        _burn(account, amount);
    }

    function getCCIPAdmin() external view returns (address) {
        return i_admin;
    }
}

/// @dev End-to-end CCIP token transfer test on forks: Ethereum -> HyperEVM (and back).
contract EthHyper_CCT_Fork is Test {
    // Chain IDs
    uint256 constant ETHEREUM = 1;
    uint256 constant HYPER_EVM = 999;

    // CCIP Chain Selectors & Routers (from CCIP Directory)
    uint64 constant ETH_SELECTOR = 5009297550715157269;
    address constant ETH_ROUTER = 0x80226fc0Ee2b096224EeAc085Bb9a8cba1146f7D;

    uint64 constant HYPER_SELECTOR = 2442541497099098535;
    address constant HYPER_ROUTER = 0x13b3332b66389B1467CA6eBd6fa79775CCeF65ec;

    CCIPLocalSimulatorFork internal sim;

    // Fork ids
    uint256 internal ethFork;
    uint256 internal hyperFork;

    // Deployed artifacts per chain
    MockCCT internal tokenETH;
    MockCCT internal tokenHYP;
    BurnMintTokenPool internal poolETH;
    BurnMintTokenPool internal poolHYP;

    IRouterClient internal routerETH;
    IRouterClient internal routerHYP;

    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);

    function setUp() public {
        // Create forks
        ethFork = vm.createSelectFork(vm.envString("ETHEREUM_MAINNET_RPC_URL"));
        hyperFork = vm.createFork(vm.envString("HYPEREVM_RPC_URL"));

        // Deploy the fork simulator (persists across forks)
        sim = new CCIPLocalSimulatorFork();
        vm.makePersistent(address(sim));

        Register.NetworkDetails memory ethDetails = Register.NetworkDetails({
            chainSelector: 5009297550715157269,
            routerAddress: 0x80226fc0Ee2b096224EeAc085Bb9a8cba1146f7D,
            linkAddress: 0x514910771AF9Ca656af840dff83E8264EcF986CA,
            wrappedNativeAddress: 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2,
            ccipBnMAddress: address(0),
            ccipLnMAddress: address(0),
            rmnProxyAddress: 0x411dE17f12D1A34ecC7F45f49844626267c75e81,
            registryModuleOwnerCustomAddress: 0x4855174E9479E211337832E109E7721d43A4CA64,
            tokenAdminRegistryAddress: 0xb22764f98dD05c789929716D677382Df22C05Cb6
        });

        sim.setNetworkDetails(1, ethDetails);

        // Register network details if not present in the simulator defaults
        // (We include Router + Selector; LINK/RMN/Registries can be filled by defaults)
        Register.NetworkDetails memory ethND = sim.getNetworkDetails(ETHEREUM);
        if (ethND.routerAddress == address(0) || ethND.chainSelector == 0) {
            ethND.chainSelector = ETH_SELECTOR;
            ethND.routerAddress = ETH_ROUTER;
            sim.setNetworkDetails(ETHEREUM, ethND);
        }
        Register.NetworkDetails memory hypND = sim.getNetworkDetails(HYPER_EVM);
        if (hypND.routerAddress == address(0) || hypND.chainSelector == 0) {
            hypND.chainSelector = HYPER_SELECTOR;
            hypND.routerAddress = HYPER_ROUTER;
            sim.setNetworkDetails(HYPER_EVM, hypND);
        }

        // ========= Deploy token & pool on Ethereum fork =========
        vm.selectFork(ethFork);
        tokenETH = new MockCCT("MockCCT", "MCCT");
        
        routerETH = IRouterClient(ETH_ROUTER);
        // Use RMN from simulator details (safer than hardcoding)
        address rmnETH = sim.getNetworkDetails(ETHEREUM).rmnProxyAddress;
        poolETH = new BurnMintTokenPool(
            IBurnMintERC20(address(tokenETH)),
            18,
            new address[](0),
            rmnETH,
            address(routerETH)
        );
        
        tokenETH.grantRole(tokenETH.MINTER_ROLE(), address(poolETH));
        tokenETH.grantRole(tokenETH.BURNER_ROLE(), address(poolETH));

        // ========= Deploy token & pool on HyperEVM fork =========
        vm.selectFork(hyperFork);
        Register.NetworkDetails memory hypDetails = Register.NetworkDetails({
            chainSelector: 2442541497099098535,
            routerAddress: 0x13b3332b66389B1467CA6eBd6fa79775CCeF65ec,
            linkAddress: 0x1AC2EE68b8d038C982C1E1f73F596927dd70De59, // LINK on HyperEVM
            wrappedNativeAddress: address(0), // fill if HyperEVM has a WETH-equivalent
            ccipBnMAddress: address(0),
            ccipLnMAddress: address(0),
            rmnProxyAddress: 0x07f15e9813FBd007d38CF534133C0838f449ecFA,
            registryModuleOwnerCustomAddress: 0xbAb3aBB5F29275065F2814F1f4B10Ffc1284fFEf,
            tokenAdminRegistryAddress: 0xcE44363496ABc3a9e53B3F404a740F992D977bDF
        });

        sim.setNetworkDetails(999, hypDetails);
        tokenHYP = new MockCCT("MockCCT", "MCCT");

        routerHYP = IRouterClient(HYPER_ROUTER);
        address rmnHYP = sim.getNetworkDetails(HYPER_EVM).rmnProxyAddress;
        poolHYP = new BurnMintTokenPool(
            IBurnMintERC20(address(tokenHYP)),
            18,
            new address[](0),
            rmnHYP,
            address(routerHYP)
        );

        tokenHYP.grantRole(tokenHYP.MINTER_ROLE(), address(poolHYP));
        tokenHYP.grantRole(tokenHYP.BURNER_ROLE(), address(poolHYP));

        // ========= Link pools / register token for CCIP =========
        // In a live env you would call TokenAdminRegistry + RegistryModuleOwnerCustom to:
        // - setPool(token, pool)
        // - configure per-destination chain pool addresses / limits
        // The CCIP Local Fork tutorial walks through those exact calls.
        // For this example test, we mint some supply and use the simulator to route.

        // Fund sender on ETH with native for fees (no real ETH needed on a fork)
        vm.selectFork(ethFork);
        vm.deal(alice, 10 ether);

        // Mint sender test tokens on ETH
        tokenETH.mint(alice, 1_000e18);

        _registerTokens();
        _wirePools();
    }

    function _registerTokens() internal {
        // --- Ethereum fork ---
        vm.selectFork(ethFork);

        address tarEth = sim
            .getNetworkDetails(ETHEREUM)
            .tokenAdminRegistryAddress;
        address rmoEth = sim
            .getNetworkDetails(ETHEREUM)
            .registryModuleOwnerCustomAddress;

        // 1. Register admin (based on token.getCCIPAdmin())
        RegistryModuleOwnerCustom(rmoEth).registerAdminViaGetCCIPAdmin(
            address(tokenETH)
        );
        // 2. Accept admin role
        TokenAdminRegistry(tarEth).acceptAdminRole(address(tokenETH));
        // 3. Set pool
        TokenAdminRegistry(tarEth).setPool(address(tokenETH), address(poolETH));

        // --- HyperEVM fork ---
        vm.selectFork(hyperFork);

        address tarHyp = sim
            .getNetworkDetails(HYPER_EVM)
            .tokenAdminRegistryAddress;
        address rmoHyp = sim
            .getNetworkDetails(HYPER_EVM)
            .registryModuleOwnerCustomAddress;

        RegistryModuleOwnerCustom(rmoHyp).registerAdminViaGetCCIPAdmin(
            address(tokenHYP)
        );
        TokenAdminRegistry(tarHyp).acceptAdminRole(address(tokenHYP));
        TokenAdminRegistry(tarHyp).setPool(address(tokenHYP), address(poolHYP));
    }

    function _wirePools() internal {
        vm.selectFork(ethFork);
        // --- Ethereum pool config to HyperEVM ---
        TokenPool.ChainUpdate[] memory updatesEth = new TokenPool.ChainUpdate[](
            1
        );

        bytes[] memory remotePoolsHyp = new bytes[](1);
        remotePoolsHyp[0] = abi.encode(address(poolHYP));

        updatesEth[0] = TokenPool.ChainUpdate({
            remoteChainSelector: HYPER_SELECTOR,
            remotePoolAddresses: remotePoolsHyp,
            remoteTokenAddress: abi.encode(address(tokenHYP)),
            outboundRateLimiterConfig: RateLimiter.Config(false, 0, 0),
            inboundRateLimiterConfig: RateLimiter.Config(false, 0, 0)
        });

        poolETH.applyChainUpdates(new uint64[](0), updatesEth);

        vm.selectFork(hyperFork);

        // --- HyperEVM pool config to Ethereum ---
        TokenPool.ChainUpdate[] memory updatesHyp = new TokenPool.ChainUpdate[](
            1
        );

        bytes[] memory remotePoolsEth = new bytes[](1);
        remotePoolsEth[0] = abi.encode(address(poolETH));

        updatesHyp[0] = TokenPool.ChainUpdate({
            remoteChainSelector: ETH_SELECTOR,
            remotePoolAddresses: remotePoolsEth,
            remoteTokenAddress: abi.encode(address(tokenETH)),
            outboundRateLimiterConfig: RateLimiter.Config(false, 0, 0),
            inboundRateLimiterConfig: RateLimiter.Config(false, 0, 0)
        });

        poolHYP.applyChainUpdates(new uint64[](0), updatesHyp);
    }

    function test_EthToHyper_tokenTransfer() public {
        vm.selectFork(ethFork);
        // Approve Router to pull tokens from alice (simulate pool workflow)
        vm.startPrank(alice);
        tokenETH.approve(address(routerETH), 100e18);
        // Build CCIP message: send 100 MCCT to bob on HyperEVM
        Client.EVMTokenAmount[]
            memory tokenAmounts = new Client.EVMTokenAmount[](1);
        tokenAmounts[0] = Client.EVMTokenAmount({
            token: address(tokenETH),
            amount: 100e18
        });

        // // Fails with 0xee433e99 (i.e., ExtraArgOutOfOrderExecutionMustBeTrue()) error
        // Client.EVM2AnyMessage memory msgOut = Client.EVM2AnyMessage({
        //     receiver: abi.encode(bob), // EOA dest is fine; only tokens are delivered
        //     data: hex"", // no extra data
        //     tokenAmounts: tokenAmounts,
        //     extraArgs: Client._argsToBytes(
        //         Client.EVMExtraArgsV1({
        //             gasLimit: 500_000
        //         })
        //     ),
        //     feeToken: address(0) // pay fees in native (ETH)
        // });

        Client.EVM2AnyMessage memory msgOut = Client.EVM2AnyMessage({
            receiver: abi.encode(bob), // EOA dest is fine; only tokens are delivered
            data: hex"", // no extra data
            tokenAmounts: tokenAmounts,
            extraArgs: Client._argsToBytes(
                Client.GenericExtraArgsV2({
                    gasLimit: 500_000,
                    allowOutOfOrderExecution: true
                })
            ),
            feeToken: address(0) // pay fees in native (ETH)
        });
        // Send from ETH to HyperEVM
        routerETH.ccipSend{value: 0.05 ether}(HYPER_SELECTOR, msgOut);
        vm.stopPrank();
        // Now execute the message on the HyperEVM fork
        sim.switchChainAndRouteMessage(hyperFork);
        // Balance should appear on HyperEVM for bob (burn on src, mint on dst)
        vm.selectFork(hyperFork);
        assertEq(tokenHYP.balanceOf(bob), 100e18, "dest token not minted");
    }
}
