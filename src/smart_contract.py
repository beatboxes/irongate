#!/usr/bin/env python3
"""
Irongate Device Registry Smart Contract for Algorand

This script can:
1. Compile the PyTeal contract to TEAL (default)
2. Deploy the contract on-chain with 'onchain' argument

Usage:
    python3 smart_contract.py           # Compile only
    python3 smart_contract.py onchain   # Compile and deploy to blockchain

Requirements: pip install py-algorand-sdk pyteal
"""

import sys
import os
import base64
import time
import yaml

# ═══════════════════════════════════════════════════════════════════════════
# SMART CONTRACT (PyTeal)
# ═══════════════════════════════════════════════════════════════════════════

def get_approval_teal():
    """Generate approval program TEAL code"""
    try:
        from pyteal import (
            App, Approve, Assert, Bytes, Cond, Global, Int, Mode,
            OnComplete, Return, Seq, Txn, And, compileTeal
        )
    except ImportError:
        print("ERROR: PyTeal not installed")
        print("Install with: pip install pyteal --break-system-packages")
        sys.exit(1)
    
    admin_key = Bytes("admin")
    device_count_key = Bytes("device_count")
    is_admin = Txn.sender() == App.globalGet(admin_key)
    
    basic_checks = And(
        Txn.rekey_to() == Global.zero_address(),
        Txn.close_remainder_to() == Global.zero_address(),
        Txn.asset_close_to() == Global.zero_address()
    )
    
    on_creation = Seq([
        Assert(basic_checks),
        App.globalPut(admin_key, Txn.sender()),
        App.globalPut(device_count_key, Int(0)),
        Approve()
    ])
    
    on_register = Seq([
        Assert(basic_checks),
        Assert(is_admin),
        Assert(Txn.application_args.length() == Int(3)),
        Assert(App.globalGet(Txn.application_args[1]) == Bytes("")),
        App.globalPut(Txn.application_args[1], Txn.application_args[2]),
        App.globalPut(device_count_key, App.globalGet(device_count_key) + Int(1)),
        Approve()
    ])
    
    on_update = Seq([
        Assert(basic_checks),
        Assert(is_admin),
        Assert(Txn.application_args.length() == Int(3)),
        Assert(App.globalGet(Txn.application_args[1]) != Bytes("")),
        App.globalPut(Txn.application_args[1], Txn.application_args[2]),
        Approve()
    ])
    
    on_revoke = Seq([
        Assert(basic_checks),
        Assert(is_admin),
        Assert(Txn.application_args.length() == Int(2)),
        Assert(App.globalGet(Txn.application_args[1]) != Bytes("")),
        App.globalDel(Txn.application_args[1]),
        App.globalPut(device_count_key, App.globalGet(device_count_key) - Int(1)),
        Approve()
    ])
    
    on_transfer = Seq([
        Assert(basic_checks),
        Assert(is_admin),
        Assert(Txn.application_args.length() == Int(2)),
        App.globalPut(admin_key, Txn.application_args[1]),
        Approve()
    ])
    
    program = Cond(
        [Txn.application_id() == Int(0), on_creation],
        [Txn.on_complete() == OnComplete.DeleteApplication, Return(is_admin)],
        [Txn.on_complete() == OnComplete.UpdateApplication, Return(is_admin)],
        [Txn.on_complete() == OnComplete.CloseOut, Approve()],
        [Txn.on_complete() == OnComplete.OptIn, Approve()],
        [Txn.application_args[0] == Bytes("register"), on_register],
        [Txn.application_args[0] == Bytes("update"), on_update],
        [Txn.application_args[0] == Bytes("revoke"), on_revoke],
        [Txn.application_args[0] == Bytes("transfer_admin"), on_transfer],
    )
    
    return compileTeal(program, mode=Mode.Application, version=8)


def get_clear_teal():
    """Generate clear program TEAL code"""
    from pyteal import Approve, Mode, compileTeal
    return compileTeal(Approve(), mode=Mode.Application, version=8)


def compile_contracts():
    """Compile and save TEAL files"""
    print("=" * 60)
    print("IRONGATE DEVICE REGISTRY - SMART CONTRACT COMPILER")
    print("=" * 60)
    
    approval_teal = get_approval_teal()
    clear_teal = get_clear_teal()
    
    os.makedirs("/opt/irongate", exist_ok=True)
    
    with open("/opt/irongate/approval.teal", "w") as f:
        f.write(approval_teal)
    print(f"\n✓ Approval program: /opt/irongate/approval.teal ({len(approval_teal)} bytes)")
    
    with open("/opt/irongate/clear.teal", "w") as f:
        f.write(clear_teal)
    print(f"✓ Clear program: /opt/irongate/clear.teal ({len(clear_teal)} bytes)")
    
    return approval_teal, clear_teal


# ═══════════════════════════════════════════════════════════════════════════
# ON-CHAIN DEPLOYMENT
# ═══════════════════════════════════════════════════════════════════════════

def deploy_onchain():
    """Deploy the smart contract directly to Algorand blockchain"""
    
    print("=" * 60)
    print("IRONGATE DEVICE REGISTRY - ON-CHAIN DEPLOYMENT")
    print("=" * 60)
    
    # Check for Algorand SDK
    try:
        from algosdk import account, mnemonic, transaction
        from algosdk.v2client import algod
    except ImportError:
        print("\nERROR: Algorand SDK not installed")
        print("Install with: pip install py-algorand-sdk --break-system-packages")
        sys.exit(1)
    
    # Load config or prompt for mnemonic
    config_path = "/etc/irongate/config.yaml"
    admin_mnemonic = None
    network = "mainnet"
    
    if os.path.exists(config_path):
        try:
            with open(config_path) as f:
                config = yaml.safe_load(f) or {}
            blockchain_cfg = config.get('blockchain', {})
            admin_mnemonic = blockchain_cfg.get('admin_mnemonic')
            network = blockchain_cfg.get('network', 'mainnet')
        except Exception as e:
            print(f"Warning: Could not read config: {e}")
    
    # Prompt for mnemonic if not in config
    if not admin_mnemonic:
        print("\nNo admin_mnemonic found in /etc/irongate/config.yaml")
        print("Enter your 25-word Algorand wallet mnemonic:")
        print("(This wallet will be the admin and needs ~0.5 ALGO for deployment)")
        print()
        admin_mnemonic = input("Mnemonic: ").strip()
    
    if not admin_mnemonic or len(admin_mnemonic.split()) != 25:
        print("ERROR: Invalid mnemonic. Must be 25 words.")
        sys.exit(1)
    
    # Get private key from mnemonic
    try:
        private_key = mnemonic.to_private_key(admin_mnemonic)
        sender_address = account.address_from_private_key(private_key)
    except Exception as e:
        print(f"ERROR: Invalid mnemonic - {e}")
        sys.exit(1)
    
    print(f"\n✓ Wallet address: {sender_address}")
    
    # Select network
    print(f"\nNetwork: {network.upper()}")
    if network == "testnet":
        algod_address = "https://testnet-api.algonode.cloud"
    else:
        algod_address = "https://mainnet-api.algonode.cloud"
    
    print(f"Node: {algod_address}")
    
    # Connect to Algorand node
    try:
        client = algod.AlgodClient("", algod_address)
        params = client.suggested_params()
        print(f"✓ Connected to Algorand {network}")
    except Exception as e:
        print(f"ERROR: Could not connect to Algorand node - {e}")
        sys.exit(1)
    
    # Check balance
    try:
        account_info = client.account_info(sender_address)
        balance = account_info.get('amount', 0) / 1_000_000
        print(f"✓ Wallet balance: {balance:.6f} ALGO")
        
        if balance < 0.5:
            print(f"\nERROR: Insufficient balance. Need at least 0.5 ALGO, have {balance:.6f}")
            print("Fund your wallet and try again.")
            sys.exit(1)
    except Exception as e:
        print(f"ERROR: Could not check balance - {e}")
        sys.exit(1)
    
    # Compile contracts
    print("\n" + "-" * 60)
    print("Compiling smart contract...")
    approval_teal, clear_teal = compile_contracts()
    
    # Compile TEAL to bytecode
    print("\nCompiling TEAL to bytecode...")
    try:
        approval_compiled = client.compile(approval_teal)
        approval_bytes = base64.b64decode(approval_compiled['result'])
        
        clear_compiled = client.compile(clear_teal)
        clear_bytes = base64.b64decode(clear_compiled['result'])
        
        print(f"✓ Approval bytecode: {len(approval_bytes)} bytes")
        print(f"✓ Clear bytecode: {len(clear_bytes)} bytes")
    except Exception as e:
        print(f"ERROR: Could not compile TEAL - {e}")
        sys.exit(1)
    
    # Create application
    print("\n" + "-" * 60)
    print("Deploying to blockchain...")
    
    # Global schema: 62 byte slices (for MAC addresses), 2 ints
    global_schema = transaction.StateSchema(num_uints=2, num_byte_slices=62)
    local_schema = transaction.StateSchema(num_uints=0, num_byte_slices=0)
    
    try:
        txn = transaction.ApplicationCreateTxn(
            sender=sender_address,
            sp=params,
            on_complete=transaction.OnComplete.NoOpOC,
            approval_program=approval_bytes,
            clear_program=clear_bytes,
            global_schema=global_schema,
            local_schema=local_schema
        )
        
        # Sign transaction
        signed_txn = txn.sign(private_key)
        
        # Submit transaction
        tx_id = client.send_transaction(signed_txn)
        print(f"✓ Transaction submitted: {tx_id}")
        
        # Wait for confirmation
        print("Waiting for confirmation...")
        confirmed_txn = None
        for _ in range(30):
            try:
                confirmed_txn = client.pending_transaction_info(tx_id)
                if confirmed_txn.get('confirmed-round', 0) > 0:
                    break
            except:
                pass
            time.sleep(1)
        
        if not confirmed_txn or confirmed_txn.get('confirmed-round', 0) == 0:
            print("ERROR: Transaction not confirmed after 30 seconds")
            sys.exit(1)
        
        app_id = confirmed_txn.get('application-index')
        
        print("\n" + "=" * 60)
        print("SUCCESS! SMART CONTRACT DEPLOYED")
        print("=" * 60)
        print(f"\n  App ID: {app_id}")
        print(f"  Transaction: {tx_id}")
        print(f"  Network: {network}")
        print(f"  Admin: {sender_address}")
        
        # Update config file
        print("\n" + "-" * 60)
        print("Updating /etc/irongate/config.yaml...")
        
        try:
            if os.path.exists(config_path):
                with open(config_path) as f:
                    config = yaml.safe_load(f) or {}
            else:
                config = {}
            
            if 'blockchain' not in config:
                config['blockchain'] = {}
            
            config['blockchain']['enabled'] = True
            config['blockchain']['network'] = network
            config['blockchain']['app_id'] = app_id
            config['blockchain']['admin_mnemonic'] = admin_mnemonic
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            
            with open(config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
            
            print(f"✓ Config updated with App ID: {app_id}")
            print("\n✓ Restart Irongate to activate Layer 8:")
            print("  sudo systemctl restart irongate")
            
        except Exception as e:
            print(f"\nWarning: Could not update config - {e}")
            print(f"\nManually add to {config_path}:")
            print(f"""
blockchain:
  enabled: true
  network: {network}
  app_id: {app_id}
  admin_mnemonic: "{admin_mnemonic}"
""")
        
        # Save app_id to a separate file for easy reference
        with open("/opt/irongate/app_id.txt", "w") as f:
            f.write(str(app_id))
        
        print("\n" + "=" * 60)
        print("NEXT STEPS:")
        print("=" * 60)
        print("""
1. Restart Irongate:
   sudo systemctl restart irongate

2. Register your devices:
   irongate-blockchain sync

3. Verify registration:
   irongate-blockchain list
""")
        
        return app_id
        
    except Exception as e:
        print(f"ERROR: Deployment failed - {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].lower() == "onchain":
        deploy_onchain()
    else:
        compile_contracts()
        print("""
═══════════════════════════════════════════════════════════════
TO DEPLOY ON-CHAIN:
═══════════════════════════════════════════════════════════════

Run: python3 /opt/irongate/smart_contract.py onchain

This will:
1. Compile the contract
2. Deploy to Algorand blockchain
3. Update /etc/irongate/config.yaml with the App ID

Requirements:
- Algorand wallet with ~0.5 ALGO
- 25-word mnemonic phrase
═══════════════════════════════════════════════════════════════
""")
