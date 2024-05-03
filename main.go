package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"github.com/labstack/echo/v4"
)

type MeuIp struct{
	HeaderEscondido 	 	string 	`json:"headerEscondido"`
	StatusCodeRespondido 	string 	`json:"statusCode"`
	Ip 					 	string 	`json:"ip"`
}

func main() {

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	
	

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

	routes()
	//enviarMsg()
}



func routes(){
	e := echo.New()
	e.GET("/", func(c echo.Context) error{
		mensagem := c.QueryParam("msg")
		return c.String(http.StatusOK, mensagem)
		//return c.String(http.StatusOK, "Aloooo")
	})

	e.GET("/meu-ip", func(c echo.Context) error {
		r, err := getIp()
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError)
		}
		return c.JSON(http.StatusOK, r)
	})
	e.Logger.Fatal(e.Start(":7801"))
}

func enviarMsg(c echo.Context) error{
	mensagem := c.QueryParam("msg")
	return c.String(http.StatusOK, mensagem)
}

func getIp() (MeuIp, error){

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	
	resp, err := client.Get("https://distopia.savi2w.workers.dev/")
	if err != nil {
		return MeuIp{}, err
	}

	resp2, err := http.Get("https://distopia.savi2w.workers.dev/")
	if err != nil {
		return MeuIp{}, err
	}

	body, err := io.ReadAll(resp2.Body)
	if err != nil{
		return MeuIp{}, err
	}
	
	resp.Body.Close()

	return MeuIp{
		HeaderEscondido: resp.Header.Get("Distopia"),
		StatusCodeRespondido: resp.Status,
		Ip: string(body),
	}, nil
}

func encrypt(value string) string{
	return base64.StdEncoding.EncodeToString([]byte(value))
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
