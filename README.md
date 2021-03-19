# ODELBrain


This project is a brute force application written in GO scripting language using BrainWallet wallets mnemonic.<br>
It was inspired by a similar project BrainFlayer and adapted to the GO language.<br>
Of course it is not similar in every sense.<br>
The project needs to be optimized.<br>
Sqlite was used instead of BloomFilter.<br>
Wallet addresses are converted to RIPEM160 and stored in the database.<br>
The reason I didn't use BloomFilter was that it was not accurate enough in brute force tests for 25 million wallets.<br>
If there are friends who know how to code, they can solve this problem in GO language and use BloomFilter for this project again.<br>
Perhaps there is another quicker method of interrogation that I do not know about.<br>

Required modules<br>
go get "github.com/gosuri/uilive"<br>
go get "github.com/haltingstate/secp256k1-go"<br>
go get "github.com/jbenet/go-base58"<br>
go get "golang.org/x/crypto/ripemd160"<br>
go get "github.com/mattn/go-sqlite3"<br>


Build process<br>
go build<br>


Parameters<br>
wallet  (Default:wallets.txt)<br>
walletinsert (Default:false)<br>
phrasecount (Default:12)<br>
input (Default:phrases.txt)<br>
output (Default:bingo.txt)<br>

Usage<br>
.\odelbrain.exe -wallet="wallets.txt" -walletinsert=true  -phrasecount=12 -input="phrases.txt" -output="bingo.txt" -thread=4



