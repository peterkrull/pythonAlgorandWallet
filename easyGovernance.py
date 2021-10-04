"""

This file 'governance.py' makes it easy to interact with algorand Governance while being
completely open source. The most important functionalities
are governance.commit() and governance.voting(), but if this file is run directly
the user is asked to commit or vote in governance, and is guided through the process.

"""
import algorandWallet as aw
import AlgoExplorerAPI as ae

# end-to-end commit script
class commit():

    """
    Automated wizard that makes it easier to sign up and commit Algos for governance.
    
    Args:
        wallet_name (str) : Name of wallet to find account in
        account_name (str) : Name of account to use to sign up for governance
    """

    def __init__(self,wallet_name,account_name):

        # Setup
        print("Setting up wallet and node, fetching params.")
        wallet = aw.algoWallet(wallet_name)
        node = ae.node()
        params = node.suggested_params()

        # Select period
        print("Checking if next period is active..")
        if aw.govAPI.nextPeriodOpen():
            print("Next period is active, type 'yes' use address:")
            govner = aw.govAPI.getNextGovAddress()
            print(govner)
            if input().lower() != "yes":
                del govner
                print("Type 'yes' use current periods address instead:")
                govner = aw.govAPI.getActiveGovAddress()
                print(govner)
                if input().lower() != "yes":
                    del govner
                    exit()
        else:
            print("Next period is NOT active, type 'yes' use current periods address:")
            govner = aw.govAPI.getActiveGovAddress()
            print(govner)
            if input().lower() != "yes":
                del govner
                exit()

        # Fetch amount of Algos of account
        algos = node.account_algo_amount(wallet.getPublic(account_name))

        # Get user unput on amount to commit
        print("Please enter amount of Algos to commit for '{}', maximum of {} Algos:".format(account_name,algos))
        while 1:
            try:
                amount = float(input())
                if amount >= algos:
                    print("Can't commit more Algos than account holds, try again.")
                else:
                    break
            except ValueError:
                print("Invalid input, please enter a number (can have decimals)")
                pass

        # Create transaction
        tx = wallet.governanceCommit(account_name,params,amount,governance_account=govner)

        # Get final user confirmation before posting
        print ( wallet.txDetails(tx) )
        print("Please verify the transaction. Type 'yes' to post to blockchain.")
        answer = input().lower()
        if answer == "yes":
            txID = node.send_transaction(tx)
            print ( node.explorer_tx(txID) )
        else:
            print("Transaction canceled.")

# end-to-end voting script
class voting():
    """
    Automated wizard that makes it easier to read the proposals and cast votes.
    
    Args:
        wallet_name (str) : Name of wallet to find account in
        account_name (str) : Name of account to use for voting in governance
    """

    def __init__(self,wallet_name,account_name):

        # Setup
        print("Setting up wallet and node, fetching params.")
        wallet = aw.algoWallet(wallet_name)
        sessions = aw.govAPI.getActiveVotingSessions()
        xround, votes = aw.voting.wizard(sessions)
        node = ae.node()
        params = node.suggested_params()

        # Fetch governance address
        govner = aw.govAPI.getActiveGovAddress()

        # Create transaction
        tx = wallet.governanceVote(account_name,params,xround,votes,governance_account=govner)

        # Get final user confirmation before posting
        print ( wallet.txDetails(tx) )
        print("Please verify the transaction. Type 'yes' to post to blockchain.")
        answer = input().lower()
        if answer == "yes":
            txID = node.send_transaction(tx)
            print ( node.explorer_tx(txID) )
        else:
            print("Transaction canceled.")

    # voting wizard to guide through a vote
    def wizard(sessions) -> tuple[int,tuple[str]]:
        

        session = voting.__selectSession(sessions)
        
        id = session["id"]

        votes = []
        for topic in session["topics"]:
            votes.append( voting.__selectOption(topic) )
            
        print("==============================================")
        print("\n========= For the following session: =========\n")
        print(">>> {} <<<".format(session["title"]))
        print("\n========= You are casting votes for: =========\n")

        index = []
        for vote in votes:
            print(">>> {} <<<".format(vote["title"]))
            index.append(vote["indicator"])
        
        print("\n==============================================")
        print("If this is your choice, please type 'yes' now.")
        print("==============================================")
        
        if input().lower() == "yes":
            return id, index

    # From a list of active sessions, select one
    def __selectSession(sessions):
        title = []
        for i in sessions:
            title.append(i["title"])
        print("\n==============================================")
        print("You are about to select a voting session.")
        print("Please enter the number in front of the title.")
        print("==============================================")
        for i in range(len(title)):
            print("{} : {}".format(i,title[i]))

        choice_raw = input()

        choice = int(choice_raw)
  
        if choice < len(title) and choice >= 0:
            print(">>> {} <<<".format(sessions[choice]["title"]))
            print("==============================================\n")
            return sessions[choice]
        else:
            raise ValueError

    # In a given session, take available votes
    def __selectOption(options):
        title = []
        for i in options["topic_options"]:
            title.append(i["title"])

        print("Description of the current proposal:")
        print("==============================================\n")
        print(aw.govAPI.cleanhtml( options["description_html"]))
        print("\n==============================================")
        print("You are about to select an option to vote for.")
        print("Please enter the number in front of the title.")
        print("NOTE: You can review your choices afterwards.")
        print("==============================================")        

        for i in range(len(title)):
            print("{} : {}".format(i,title[i]))

        choice_raw = input()

        choice = int(choice_raw)

        if choice < len(title) and choice >= 0:
            print(">>> {} <<<".format(options["topic_options"][choice]["title"]))
            print("==============================================\n\n")
            return options["topic_options"][choice]  
        else:
            raise ValueError

# get wallet and account to use
def get_wallet_account(extension):
    print("Please type the name of the wallet file you wish to use.")
    wallet_name = input()

    try:
        open(wallet_name)
    except:
        FileNotFoundError
        print("This file does not exist, exiting..")
        exit()

    print("Please type the name of the account you wish to {}".format(extension))
    account_name = input()

    if not account_name in aw.algoWallet(wallet_name).internalWallet:
        print("This account does not exist in the chosen file, exiting..")
        exit()
    
    return wallet_name,account_name

# if run directly, run easy-script
if __name__ == '__main__':
    print("Do you want to commit Algos or vote in governance?")
    print("Type 'commit' or 'vote' to continue.")

    while 1:
        entered = input().lower()
        if entered == 'commit':
            wal,acc = get_wallet_account("commit to governance.")
            commit(wal,acc)
            break
        elif entered == 'vote':
            wal,acc = get_wallet_account("vote with.")
            voting(wal,acc)
            break
        else:
            print("Invalid choice, try again-")
