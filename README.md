# Algorand Wallet written in Python (CLI only)

Algorand wallet written in Python, to allow for signing of transactions and interacting with the Algorand blockchain. This wallet does not contain a graphical user interfaces, but the included functions make it easy to manage an account as well as send various transaction. _More functionality will be added in the future._

## Contents

The two files `algorandWallet.py` and `AlgoExplorerAPI.py` provide the functionality you need manage a simple account, encrypt and decrypt priavte keys, add and remove contacts as well as make simple transaction on the blockchain without having to set up and maintain a personal Algorand node.

## Example of making account, adding contact, making a transaction, going online for consensus and posting the transactions to the blockchain using AlgoExplorer API.

```python
import AlgoExplorerAPI as ae
import algorandWallet as aw


# Creates wallet object
wallet = aw.algoWallet("algorandWallet")

# Creates a connection to the AlgoExplorer API
node = ae.node("mainnet")

# Fetch suggested parameters from either API or node
params = node.suggested_params()

# Generates an account and encrypts it using a password
wallet.genAccount("primary_account","myPassword1234!")

# Adds a contact and gives it easy to type name
wallet.addContact("Algorand8","APDO5T76FB57LNURPHTLAGLQOHUQZXYHH2ZKR4DPQRKK76FB4IAOBVBXHQ")

# Exports wallet to a file (in this case to "algorandWallet")
wallet.exportWallet()

# Sends 0.1337 Algos to Algorand8 on testnet, and decrypts the wallet for signing
txA = wallet.makeSendAlgoTx("primary_account","Algorand8",0.1337,params,"myPassword1234!")

# https://developer.algorand.org/docs/run-a-node/participate/generate_keys/
partkeyinfo = {'!! Your partkey dictionary should go here !!'}

# Registers as online for participation in consensus
txB = wallet.participateConsensus("primary_account",params,partkeyinfo,"myPassword1234!")

# Sends transaction and catches transaction ID
txnoteA = node.send_transaction(txA) # Posts money transfer transaction to blockchain
txnoteB = node.send_transaction(txB) # Posts consensus participation transaction to blockchain

# Prints links to AlgoExplorer transaction page 
# !!This will only work for the AlgoExplorerAPI node!!
print( node.explorer_tx(txA) ) 
print( node.explorer_tx(txB) )
```
