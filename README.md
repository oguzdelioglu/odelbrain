# ODELBrain


This project is a brute force application written in GO scripting language using BrainWallet wallets mnemonic.<br>
It was inspired by a similar project BrainFlayer and adapted to the GO language.<br>
Of course it is not similar in every sense.<br>
The project needs to be optimized.<br>
Added BloomFilter.<br>
Check Address balance (Because bloom filter giving false positive address sometimes.We need recheck address.)

Required modules<br>
go get "github.com/gosuri/uilive"<br>
go get "github.com/haltingstate/secp256k1-go"<br>
go get "github.com/jbenet/go-base58"<br>
go get "golang.org/x/crypto/ripemd160"<br>
go get "github.com/mattn/go-sqlite3"<br>
go get "github.com/bits-and-blooms/bloom/v3"<br>


Build process<br>
go build<br>


Parameters<br>
wallet  (Default:wallets.txt)<br>
walletinsert (Default:false)<br>
phrasecount (Default:12)<br>
input (Default:phrases.txt)<br>
output (Default:bingo.txt)<br>

Usage<br>
odelbrain.exe -i="phrases.txt" -w="wallets.txt" -t=24 -pc=3 -u=true -s=true -v=false

