package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

func main() {

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil{
		fmt.Println("Erro: ", err)
	}

	publicKey := privateKey.PublicKey
	
	clientValue := encrypt("O Morte, torne-se minha lamina mais uma vez")
	fmt.Println("Seu valor encriptado em base64: ",clientValue)
	
	encryptedValue, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &publicKey, []byte(clientValue), nil)
	if err != nil{
		fmt.Println("Erro: ", err)
	}

	fmt.Println("Seu valor encriptado: ", string(encryptedValue))

	descrypedValue, err := privateKey.Decrypt(nil, encryptedValue, &rsa.OAEPOptions{Hash: crypto.SHA256})
	
	if err != nil{
		fmt.Println("Erro: ", err)
	}

	fmt.Println("Seu valor em base64: ", string(descrypedValue))
	fmt.Println("Seu valor descriptografado: ", decrypt(string(descrypedValue)))
}

func encrypt(value string) string{
	return base64.RawStdEncoding.EncodeToString([]byte(value))
}

func decrypt(base64Encoded string) string{

	valueDecoted, err := base64.StdEncoding.DecodeString(base64Encoded)
	if err != nil {
		fmt.Println("Erro: ", err)
	}
	return string(valueDecoted)
}

func testes(){

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		println("Erro retornado: ", err)
	}

	publicKey := privateKey.PublicKey

	multBytes := base64.StdEncoding.EncodeToString(privateKey.N.Bytes())
	privateExponentBytes := base64.StdEncoding.EncodeToString(privateKey.D.Bytes())

	meuTexto := "Vou testar se criptografa isso aqui"
	teste := base64.StdEncoding.EncodeToString([]byte(meuTexto))
	teste2, err := base64.StdEncoding.DecodeString(teste)
	if err != nil {
		println("Erro retornado: ", err)
	}

	_ = teste2
	_ = multBytes
	_ = privateExponentBytes

	/*fmt.Println("Private key base64: ")
	fmt.Println(multBytes)
	fmt.Println("Peivate key base64 privateExponentBytes: ")
	fmt.Println(privateExponentBytes)
	fmt.Println("Public key base64: ")
	fmt.Println(publicKey.E)
	fmt.Println("meu texto em base64: ")
	fmt.Println(teste)
	fmt.Println("meu texto em base64 decoded: ")
	fmt.Println(string(teste2))*/

	encryptedBytes, err := rsa.EncryptOAEP(sha256.New(),
		rand.Reader,
		&publicKey,
		[]byte(teste),
		nil)

	if err != nil {
		fmt.Println(err)
	}	

	//fmt.Println("Bytes encriptados: ", string(encryptedBytes))

	descrypedBytes, err := privateKey.Decrypt(nil, encryptedBytes, &rsa.OAEPOptions{Hash: crypto.SHA256})
	_ = descrypedBytes

	if err != nil {
		fmt.Println(err) 
	}	

	//fmt.Println("descrypted message: ", string(descrypedBytes))	


	msg := []byte("O Morte, torne-se minha lamina mais uma vez")

	msgHash := sha256.New()
	_, err = msgHash.Write(msg)
	if err != nil {
		panic(err)
	}

	msgHashSum := msgHash.Sum(nil)


	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, msgHashSum, nil)
	if err != nil {
		panic(err)
	}

	err = rsa.VerifyPSS(&publicKey,crypto.SHA256, msgHashSum, signature, nil)
	if err != nil {
		fmt.Println("Não foi possive verificar assinatura:  ", err)
		return
	}

	fmt.Println("Assinatura verificada")
}
