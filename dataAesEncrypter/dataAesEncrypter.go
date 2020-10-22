package dataAesEncrypter

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
)

type dataEncrypter struct {
	key           []byte // Une clé de la taille d'un bloc AES
	data          []byte
	encryptedData []byte
	decryptedData []byte
}

const (
	SizePerRoutine            = aes.BlockSize * 64
	MaxSimultaneousGoroutines = 4
)

/*
   Fonction effectuant le padding du tableau de bytes passé en paramètres pour l'aligner sur la
   taille d'un bloc AES
*/
func pad(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

/*
   Fonction supprimant le padding du tableau de bytes passé en paramètres
   Renvoie une erreur si l'unpadding échoue (lorsque la clé de décodage est incorrecte)
*/
func unpad(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > length {
		return nil, errors.New("unpad error. This could happen when incorrect encryption key is used")
	}
	return src[:(length - unpadding)], nil
}

/*
Prend en paramètre une clé et un tableau de bytes et retourne un tableau de bytes chiffré par AES
avec la clé donnée.
*/
func encrypt(key []byte, iv []byte, data []byte, output []byte, blockIndex int, lastBlock bool) {
	fmt.Printf("Encrypting block %d\n", blockIndex)
	block, _ := aes.NewCipher(key)

	var dataToEncrypt []byte

	cfb := cipher.NewCFBEncrypter(block, iv)
	if lastBlock {
		dataToEncrypt = data[blockIndex*SizePerRoutine:]
		cfb.XORKeyStream(output[aes.BlockSize+blockIndex*SizePerRoutine:], dataToEncrypt)
	} else {
		dataToEncrypt = data[blockIndex*SizePerRoutine : (blockIndex+1)*SizePerRoutine]
		cfb.XORKeyStream(output[aes.BlockSize+blockIndex*SizePerRoutine:aes.BlockSize+(blockIndex+1)*SizePerRoutine], dataToEncrypt)
	}

}

/*
Prend en paramètre une clé et un tableau de bytes et retourne un tableau de bytes déchiffré par AES
avec la clé donnée.
*/
func decrypt(key []byte, iv []byte, data []byte, output []byte, blockIndex int, lastBlock bool) {
	fmt.Printf("Decrypting block %d\n", blockIndex)
	block, _ := aes.NewCipher(key)

	var dataToDecrypt []byte

	cfb := cipher.NewCFBDecrypter(block, iv)
	if lastBlock {
		dataToDecrypt = data[blockIndex*SizePerRoutine:]
		cfb.XORKeyStream(output[blockIndex*SizePerRoutine:], dataToDecrypt)
	} else {
		dataToDecrypt = data[blockIndex*SizePerRoutine : (blockIndex+1)*SizePerRoutine]
		cfb.XORKeyStream(output[blockIndex*SizePerRoutine:(blockIndex+1)*SizePerRoutine], dataToDecrypt)
	}

}

func (encrypter *dataEncrypter) SetKey(key []byte) {
	encrypter.key = key
}

func (encrypter *dataEncrypter) SetStringKey(key string) {
	h := sha256.New()
	h.Write([]byte(key))

	encrypter.key = h.Sum(nil)[:aes.BlockSize]
}

func (encrypter *dataEncrypter) SetData(data []byte) {
	encrypter.data = data
}

func (encrypter *dataEncrypter) Encrypt() error {
	encrypter.decryptedData = encrypter.data
	encrypter.data = nil

	data := pad(encrypter.decryptedData)
	result := make([]byte, aes.BlockSize+len(data))

	iv := result[:aes.BlockSize] // Génération du vecteur d'initialisation
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	totalRoutinesNeeded := int(math.Ceil(float64(len(data))/SizePerRoutine)) - 1 // number of routines needed (excepted for the last one)

	indexChan := make(chan int, totalRoutinesNeeded)
	var wg sync.WaitGroup

	wg.Add(MaxSimultaneousGoroutines + 1)
	// On chiffre le dernier bloc d'abord : special encoding for last block since it needs extra care for slices
	go func() {
		encrypt(encrypter.key, iv, data, result, totalRoutinesNeeded, true)
		wg.Done()
	}()

	// starts MaMaxSimultaneousGoroutinesx at the same time stopping when every job is done
	for i := 0; i < MaxSimultaneousGoroutines; i++ {
		go func() {
			for {
				blocIndex, elementsLeft := <-indexChan

				if !elementsLeft {
					wg.Done()
					return
				}

				encrypt(encrypter.key, iv, data, result, blocIndex, false)
			}
		}()
	}

	// add indicies to the queue (channel)
	for i := 0; i < totalRoutinesNeeded; i++ {
		indexChan <- i
	}

	close(indexChan)
	wg.Wait()

	encrypter.encryptedData = result
	fmt.Println("Done encrypting")

	return nil
}

func (encrypter *dataEncrypter) Decrypt() error {
	encrypter.encryptedData = encrypter.data
	encrypter.data = nil

	var err error

	if len(encrypter.encryptedData)%aes.BlockSize != 0 {
		return errors.New("blocksize must be multipe of decoded message length")
	}

	iv := encrypter.encryptedData[:aes.BlockSize]
	data := encrypter.encryptedData[aes.BlockSize:]

	result := make([]byte, len(data))

	totalRoutinesNeeded := int(math.Ceil(float64(len(data))/SizePerRoutine)) - 1

	indexChan := make(chan int, totalRoutinesNeeded)
	var wg sync.WaitGroup

	wg.Add(MaxSimultaneousGoroutines + 1)

	// On déchiffre d'abord le dernier bloc
	go func() {
		decrypt(encrypter.key, iv, data, result, totalRoutinesNeeded, true)
		wg.Done()
	}()

	for i := 0; i < MaxSimultaneousGoroutines; i++ {
		go func() {
			for {
				blocIndex, elementsLeft := <-indexChan

				if !elementsLeft {
					wg.Done()
					return
				}

				decrypt(encrypter.key, iv, data, result, blocIndex, false)
			}
		}()
	}

	for i := 0; i < totalRoutinesNeeded; i++ {
		indexChan <- i
	}

	close(indexChan)
	wg.Wait()

	encrypter.decryptedData, err = unpad(result)
	fmt.Println("Done decrypting")

	return err
}

func (encrypter dataEncrypter) GetEncryptedData() []byte {
	return encrypter.encryptedData
}

func (encrypter dataEncrypter) GetDecryptedData() []byte {
	return encrypter.decryptedData
}

func New() *dataEncrypter {
	return &dataEncrypter{}
}

func (encrypter dataEncrypter) String() string {
	return fmt.Sprintf("Key: %x\nData: %x\nData (string): %s\nEncrypted data: %x\nDecrypted data: %x\n",
		encrypter.key, encrypter.data, encrypter.data, encrypter.encryptedData, encrypter.decryptedData)
}
