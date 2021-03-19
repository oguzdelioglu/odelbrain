# odelbrain


This project is a brute force application written in GO scripting language using BrainWallet wallets mnemonic.


It was inspired by a similar project BrainFlayer and adapted to the GO language.

Of course it is not similar in every sense.

The project needs to be optimized.


Sqlite was used instead of BloomFilter.
Wallet addresses are converted to RIPEM160 and stored in the database.

The reason I didn't use BloomFilter was that it was not accurate enough in brute force tests for 25 million wallets.
If there are friends who know how to code, they can solve this problem in GO language and use BloomFilter for this project again.
Perhaps there is another quicker method of interrogation that I do not know about.

Required modules
go get "github.com/gosuri/uilive"
go get "github.com/haltingstate/secp256k1-go"
go get "github.com/jbenet/go-base58"
go get "golang.org/x/crypto/ripemd160"
go get "github.com/mattn/go-sqlite3"


Build process
go build


Parameters
wallet  (Default:wallets.txt)
walletinsert (Default:false)
phrasecount (Default:12)
input (Default:phrases.txt)
output (Default:bingo.txt)

Example command: .\odelbrain.exe -wallet="wallets.txt" -walletinsert=true  -phrasecount=12 input="phrases.txt" output="bingo.txt"



