package main

import (
    "bitbucket.org/kevalin-p2p/subtlecrypto"
    )

func main() {
    println("Generate AES Key")
    key, err := subtlecrypto.GenerateKey()
    println(key, err)
    
    
    println("Generate RSA KeyPair")
    keypair, err := subtlecrypto.GenerateKeyPair()
    println(keypair, err)
}
