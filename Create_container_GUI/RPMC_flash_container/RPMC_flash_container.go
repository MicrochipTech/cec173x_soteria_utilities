package main

import (
	"bufio"
//	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
//	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"log"
//	"time"
	"gopkg.in/gcfg.v1"

	//    "strconv"
	"hash/crc32"
	"mchp/crc8"
)

/* Called before main() use it to set default values */

const program_version string = "Version 5.0 2021-09-17"

var MCHP_Signature_string string = "CREATE_CONTAINER_REQUEST"
var chipstr string
var cfgFileName string
var outFileName string
var mergeFileName string
var outFileNameTagx string
var DebugPrint string

const SHA384size uint = 48
const P384SIGNSZE uint = 96
const P384KEYSZE uint = 48

// SPI configuration is in gcfg format
// Data structure models gcfg format we are using
type OwnerCfg struct {
	PvtKeyFile string
	PvtKeyPass string
	PubKeyFile string
}
type KeyCfg struct {
	ECDSAPvtKeyFile string
	ECDSAPvtKeyPass string
	ECDSAPubKeyFile string
}

type Config struct {
	Spi struct {
		SPISizeMegabits    uint
		KeyHashLoc         uint
		RPMCFlashContainer uint
	}

	Key map[string]*KeyCfg

	UpdtKey struct {
		UpdatePvtKeyFile string
		UpdatePvtKeyPass string
		UpdatePubKeyFile string
	}

	ECFWentry struct {
		EcfwEntryData string
	}
	OutPutDirectory struct {
		OutPutDirectory                      string
	}
	RPMCContainerHeader struct {
		RPMCValue                      uint
		ActiveContainerVersion         uint
		ContainerType                  uint8
		SecureContainerContentLength   uint
		DeviceSerialNumber063032       uint
		DeviceSerialNumber031000       uint
		ContainerCommandKeySHA384Hash0 string
		ContainerCommandKeySHA384Hash1 string
		ContainerCommandKeySHA384Hash2 string
		ContainerCommandKeySHA384Hash3 string
	}
	RPMCContainerContent struct {
		OwnerConfiguration            uint8
		ActiveContainerVersion        uint
		OwnerID                       string
		OwnerTransferAuthorizationKey string
		KeyRevocation                 uint8
		RollbackProtection            uint16
		TAG0ImageHeaderBaseAddress    uint
		TAG1ImageHeaderBaseAddress    uint
		ECDHprivatekey                string
		ECDHPublicKey2                string
		SHA384KHB                     string
		OwnerDebugOptions             uint8
		OwnerPlatformID               uint16
		SecurityFeatures              uint8
		SHA384Platk                   string
		OwnerPUFAC                    string
	}
	RPMCCommand struct {
		CreateContainerCommandRegister        uint8
		IncrementRPMCRequestCommand           uint8
		UpdateContainerRequestCommand         uint8
		RepairFallbackContainerRequestCommand uint8
	}
	CreateContainerRequest struct {
		ContainerNumber             uint8
		ContainerType               uint8
		SecureContainerContentLen   uint
		ContainerCommandKey0        string
		ContainerCommandKey1        string
		ContainerCommandKey2        string
		ContainerCommandKey3        string
		OwnerConfiguration          uint8
		OwnerID                     string
		KeyRevocation               uint8
		RollbackProtection          string
		TAG0ImageHeaderBaseAddress  uint
		TAG1ImageHeaderBaseAddress  uint
		ECDHprivatekey              string
		ECDHPublicKey2              string
		SHA384KHB                   string
		OwnerDebugOptions           uint8
		OwnerPlatformID             uint16
		SecurityFeatures            uint8
		SHA384Platk                 string
		OwnerCreationPubKey         string
		OwnerCreationPrivateKey     string
		OwnerCreationPrivateKeyPass string
	}
	IncrementRPMCContainerRequest struct {
		ContainerNumber              uint8
		ContainerType                uint8
		SignaturePubKeySelect        uint8
		ContainerCommandsPub         string
		ContainerCommandsPrivate     string
		ContainerCommandsPrivatePass string
		SHA384PrimaryContainer string
	}
	UpdateContainerRequest struct {
		ContainerNumber            uint8
		ContainerType              uint8
		SubCommand                 uint8
		KeyRevocationReq           uint
		ImageRevisionRollbackProt  string
		SecureContainerContentLen  uint
		ContainerCommandKey0       string
		ContainerCommandKey1       string
		ContainerCommandKey2       string
		ContainerCommandKey3       string
		OwnerConfiguration         uint8
		OwnerID                    string
		KeyRevocation              uint8
		RollbackProtection         string
		TAG0ImageHeaderBaseAddress uint
		TAG1ImageHeaderBaseAddress uint
		ECDHprivatekey             string
		ECDHPublicKey2             string
		SHA384KHB                  string
		OwnerDebugOptions          uint8
		OwnerPlatformID            uint16
		SecurityFeatures           uint8
		SHA384Platk                string
		SignaturePublicKeySelect   uint8
		PubKey                     string
		PrivateKey                 string
		PrivateKeyPass             string
		SHA384PrimaryContainer string
	}
	UpdateContainerRequestTransfer struct {
		ContainerNumber            uint8
		ContainerType              uint8
		SubCommand                 uint8
		KeyRevocationReq           uint
		ImageRevisionRollbackProt  string
		SecureContainerContentLen  uint
		ContainerCommandKey0       string
		ContainerCommandKey1       string
		ContainerCommandKey2       string
		ContainerCommandKey3       string
		OwnerConfiguration         uint8
		OwnerID                    string
		KeyRevocation              uint8
		RollbackProtection         string
		TAG0ImageHeaderBaseAddress uint
		TAG1ImageHeaderBaseAddress uint
		ECDHprivatekey             string
		ECDHPublicKey2             string
		SHA384KHB                  string
		OwnerDebugOptions          uint8
		OwnerPlatformID            uint16
		SecurityFeatures           uint8
		SHA384Platk                string
		SignaturePublicKeySelect   uint8
		PubKey                     string
		PrivateKey                 string
		PrivateKeyPass             string
		SHA384PrimaryContainer string
	}
	RepairFallbackContainerRequest struct {
		ContainerNumber          uint8
		ContainerType            uint8
		SubCommand               uint8
		SignaturePublicKeySelect uint8
		PubKey                   string
		PrivateKey               string
		PrivateKeyPass           string
		SHA384PrimaryContainer string
	}
	EnableUnrestrictedTransfers struct{
		ContainerNumber          uint8
		ContainerType            uint8
		OwnerConfiguration		 uint8	
		OTAPub 					 string	
		SignaturePublicKeySelect uint8
		PubKey                   string
		PrivateKey               string
		PrivateKeyPass           string
		SHA384PrimaryContainer string
	}
		UpdateOTAKey struct{
		ContainerNumber          uint8
		ContainerType            uint8
		OwnerConfiguration		 uint8	
		OTAPub 					 string	
		SignaturePublicKeySelect uint8
		PubKey                   string
		PrivateKey               string
		PrivateKeyPass           string
		SHA384PrimaryContainer string
	}
	ModifyTagxBaseAddress struct {
		ContainerNumber          uint8
		ContainerType            uint8
		TAG0ImageHeaderBaseAddress uint
		TAG1ImageHeaderBaseAddress uint
	}
	ContainerSignature struct {
		ContainerSignatureKeyFile     string
		ContainerSignatureKeyFilePass string
	}
}

type Aes256ECDHInfo struct {
	Key []byte
	Iv  []byte
	Rx  *big.Int
	Ry  *big.Int
}

// Copied from Go x509 module as its not public
type ecdsaSignature struct {
	R, S *big.Int
}

// ErrMessageTooLong is returned when attempting to encrypt a message which is
// too large for the size of the public key.
var errMessageTooLong = errors.New("crypto/rsa: message too long for RSA public key size")

var bigZero = big.NewInt(0)
var bigOne = big.NewInt(1)
var flashMap8 = make([]byte, 4)
var falshmap bool

const ECFWEntrysize uint = 256
const KEY384size uint = 48
const PUBKEYSZE uint = KEY384size * 2
const HASHsize uint = 48 //SHA384
const ToTAUTHKeys uint = 8
const ToTKEYS uint = 9 //8keys  + 1 update key
// For performance, we don't use the generic ASN1 encoder. Rather, we
// precompute a prefix of the digest value that makes a valid ASN1 DER string
// with the correct contents.
var mechashPrefixes = map[crypto.Hash][]byte{
	crypto.MD5:       {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:      {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:    {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:    {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:    {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:    {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.MD5SHA1:   {}, // A special TLS case which doesn't use an ASN1 prefix.
	crypto.RIPEMD160: {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
}

func readAndReturnBinaryFile(file_name string) ([]byte, error) {
	f, err := os.Open(file_name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	flen := fi.Size()

	size := uint(flen)

	filebytes := make([]byte, size)
	buffer := bufio.NewReader(f)
	_, err = buffer.Read(filebytes)
	if err != nil {
		return nil, err
	}
	return filebytes, nil
}

func mcopyWithLeftPad(dest, src []byte) {
	numPaddingBytes := len(dest) - len(src)
	for i := 0; i < numPaddingBytes; i++ {
		dest[i] = 0
	}
	copy(dest[numPaddingBytes:], src)
}

func print_bytes_as_hex(ba []byte, title string) {
	DebugPrint ="t"
	if (DebugPrint == "t") || (DebugPrint == "T") {
		fmt.Printf("\n")
		if title != "" {
			fmt.Println(title)
		}
		for i, b := range ba {
			if (i != 0) && ((i % 16) == 0) {
				fmt.Printf("\n")
			}
			fmt.Printf("0x%02X ", b)
		}
		fmt.Printf("\n")
	}
}

func ByteLenFromBitLen(bitLen int) uint {
	byteLen := uint(bitLen) >> 3

	if (bitLen % 8) != 0 {
		byteLen = byteLen + 1
	}

	return byteLen
}

func fillword(start_index int, ba []byte, w uint) {
	for i := 0; i < 4; i++ {
		ba[i+start_index] = byte(w & 0xFF)
		w >>= 8
	}
}
func byte_or(ba []byte, w uint8, d uint8) {
	for i := 0; i < 1; i++ {
		ba[i] = byte(w | d)
		w >>= 8
	}
}

/* From RFC5480 Elliptic Curve Cryptograph Subject Public Key Information
 * ecdsa-with-SHA256 OBJECT IDENTIFIER ::= {
 *    iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
 *    ecdsa-with-SHA2(3) 2 }
 *
 * ECDSA-Sig-Value :: SEQUENCE {
 *   r  INTEGER,
 *   s  INTEGER
 * }
 *
 * An OpenSSL ECDSAwithSHA256 signature looks like (from asn1parse)
 *    0:d=0  hl=2 l=  69 cons: SEQUENCE
 *    2:d=1  hl=2 l=  32 prim: INTEGER           :3697F6BFD2C4A6F81C5B69F2FDDCF8A1A2EA778032206E8F4CA7C153A81F0EA8
 *   36:d=1  hl=2 l=  33 prim: INTEGER           :F703077F00C11C93FC53C61C4CF057EB9151D1A2103876075C809D014D4B0FB9
 *
 * OpenSSL binary signature is 71 or 72 bytes (ASN.1 )
 * 30 45 02 20 36 97 ... 0E A8
 * 02 21 00 F7 03 07 ... 0F B9
 *
 * 30 45 -> 30 is the Universal Tag sequence,  45 is the number of bytes after 45
 * 02 = Tag number for INTEGER
 * Next byte is the length
 * First INTEGER is positive and length 32(0x20) -> 02 20
 * Second INTEGER is negative (MSB is set) and a leading zero byte was added
 * making the length 33(0x21) -> 02 21
 */
func encodeECDSAsig(r, s *big.Int) ([]byte, error) {
	// from x509.CreateCertificate
	signature, err := asn1.Marshal(ecdsaSignature{r, s})
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func decodeECDSAsig(encodedSig []byte) (*ecdsaSignature, error) {
	ecdsaSig := new(ecdsaSignature)
	_, err := asn1.Unmarshal(encodedSig, ecdsaSig)
	if err != nil {
		return nil, err
	}
	return ecdsaSig, nil
}

func readEncryptedECPrivateKey(filename string, password string) (*ecdsa.PrivateKey, error) {

	pemBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	pemBlock, _ := pem.Decode(pemBytes)

	ecPrivKeyBytes, err := x509.DecryptPEMBlock(pemBlock, []byte(password))
	if err != nil {
		return nil, err
	}

	return x509.ParseECPrivateKey(ecPrivKeyBytes)
}

func readPlainECPrivateKey(filename string) (*ecdsa.PrivateKey, error) {

	pembytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	ecPrivKeyBytes, _ := pem.Decode([]byte(pembytes))

	return x509.ParseECPrivateKey(ecPrivKeyBytes.Bytes)
}

func readECPublicKeyFromCert(filename string) (*ecdsa.PublicKey, error) {

	pemBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	pemBlock, _ := pem.Decode(pemBytes)

	if pemBlock.Type == "PUBLIC KEY" {
		pub, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}
		return pub.(*ecdsa.PublicKey), nil
	} else {
		cert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}

		if cert.PublicKeyAlgorithm != x509.ECDSA {
			return nil, errors.New("mchp/Glacier/readECPublicKeyFromCert: Public Key Algorithm is not ECDSA!")
		}

		return cert.PublicKey.(*ecdsa.PublicKey), nil
	}
}

func getRandomBigInt(max *big.Int) (*big.Int, error) {

	for {
		// returns a value in [0, max), we want [1, max-1]
		r, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, err
		}
		if r != bigZero {
			return r, nil
		}
	}
}

func getImagebuffer(flashLen uint, flashFileName string) ([]byte, error) {
	if flashFileName == "" {
		fimg := make([]byte, flashLen)
		for index, _ := range fimg {
			fimg[index] = byte(0xFF)
		}
		return fimg, nil
	} else {
		return ioutil.ReadFile(flashFileName)
	}
}

func calculate_crc32(message []byte) uint32 {
	crc32 := crc32.ChecksumIEEE(message)
	return crc32
}

func init() {
	const (
		defaultChip       = "GLACIER_RPMC_Flash_Container"
		defaultCfgFile    = "rpmc_cfg.ini"
		usageCfg          = "SPI image configuration file is text based Go gcfg format"
		defaultOutFile    = "KeyHashSpiImage.bin"
		usageOut          = "File name of generated SPI flash binary"
		defaultMergeFile  = ""
		usageMerge        = "SPI flash image to merge Firmware images into"
		defaultDebugPrint = ""
		usageDebugPrint   = "Print the output if enabled"
	)
	flag.StringVar(&cfgFileName, "i", defaultCfgFile, usageCfg)
	flag.StringVar(&outFileName, "o", defaultOutFile, usageOut)
	flag.StringVar(&mergeFileName, "m", defaultMergeFile, usageMerge)
	flag.StringVar(&DebugPrint, "d", defaultDebugPrint, usageDebugPrint)
}

// Fill the 32bit data in lsb order
func fillDword(start_index int, ba []byte, w uint) {
	for i := 0; i < 4; i++ {
		ba[i+start_index] = byte(w & 0xFF)
		w >>= 8
	}
}

// Fill the 32bit data in lsb order
func fillSword(start_index int, ba []byte, w uint8) {
	for i := 0; i < 1; i++ {
		ba[i+start_index] = byte(w & 0xFF)
		w >>= 8
	}
}

// Fill the 16bit data in lsb order
func fill16word(start_index int, ba []byte, w uint16) {
	for i := 0; i < 2; i++ {
		ba[i+start_index] = byte(w & 0xFF)
		w >>= 8
	}
}
func buildTag(hdrLocation uint) []byte {
	tag := make([]byte, 4)

	tag[0] = byte((hdrLocation >> 8) & 0xFF)
	tag[1] = byte((hdrLocation >> 16) & 0xFF)
	tag[2] = byte((hdrLocation >> 24) & 0xFF)

	crch := crc8.New(crc8.Poly07Table, 0x55)
	tcrc8 := crch.Checksum(tag[0:3])
	tag[3] = tcrc8

	return tag
}
func readECPrivateKey(filename string, password string) (*ecdsa.PrivateKey, error) {

	privateKeyFile, err := os.Open(filename)

	if err != nil {
		fmt.Printf("File is not exist %s \n ", filename)
		fmt.Println("Fatal error ", err.Error())
		os.Exit(1)
	}

	pemfileinfo, _ := privateKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pembytes)

	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(1)
	}
	data, _ := pem.Decode([]byte(pembytes))

	privateKeyFile.Close()

	//	pemBytes, err := ioutil.ReadFile(filename)
	//if err != nil {
	//	return nil, err
	//}

	//pemBlock, _ := pem.Decode(pemBytes)
	//fmt.Printf("pemBlock %x",pemBlock)
	//ecPrivKeyBytes, err := x509.DecryptPEMBlock(pemBlock, []byte(password))
	//if err != nil {
	//	return nil, err
	//}
	pkey, err := x509.ParseECPrivateKey(data.Bytes)
	if err != nil {
		fmt.Printf("got unexpected key type: %x", pkey)
	}

	return pkey, err
	//return x509.ParseECPrivateKey(ecPrivKeyBytes)
}
var verify_flag_status uint
/*
 * Public methods
 */
// Function to allocate the ECDSA table siging for teh AP_CFG_MEMORY_MAP includes the
// AP_FW_IMAGE table
func APTablesigningImage(fname string, password string, data []byte) (*big.Int, *big.Int, error) {

	rh := new(big.Int)
	sh := new(big.Int)
	// ECDSA sign
	hasher := sha512.New384() //sha256.New()
	hasher.Write(data)
	hash_ecdsa := hasher.Sum(nil)
	var err error
	_ = hash_ecdsa

	ECDSAPrivKeyFile := fname
	ECDSAPrivKeyFilePass := password
	if ECDSAPrivKeyFilePass == "None" || ECDSAPrivKeyFilePass == "" {
		authEC, err := readECPrivateKey(ECDSAPrivKeyFile, ECDSAPrivKeyFilePass)
		//fmt.Printf("APCFG without password \n")
		if err != nil {
			fmt.Printf("FW readECPrivateKey from file %v returned error %v \n", ECDSAPrivKeyFile, err)
			//return
		}
		rh, sh, err = ecdsa.Sign(rand.Reader, authEC, hash_ecdsa)
		if err != nil {
			fmt.Printf("Header ecdsa.Sign returned error %v \n", err)
			//return
		}
		// Verify
		var pubkey ecdsa.PublicKey
		pubkey = authEC.PublicKey
		verifystatus := ecdsa.Verify(&pubkey, hash_ecdsa, rh, sh)
		if verifystatus == true {
			//fmt.Printf(" Generated Signature is verified \n")
			verify_flag_status =1
		} else {
			fmt.Printf(" Generated Signature is incorrect \n")
			verify_flag_status =0
		}
	} else {
		authEC, err := readEncryptedECPrivateKey(ECDSAPrivKeyFile, ECDSAPrivKeyFilePass)
		if err != nil {
			fmt.Printf("FW readEncryptedECPrivateKey from file %v returned error %v \n", ECDSAPrivKeyFile, err)
			//return
		}
		rh, sh, err = ecdsa.Sign(rand.Reader, authEC, hash_ecdsa)
		if err != nil {
			fmt.Printf("Header ecdsa.Sign returned error %v \n", err)
			//return
		}
		// Verify
		var pubkey ecdsa.PublicKey
		pubkey = authEC.PublicKey
		verifystatus := ecdsa.Verify(&pubkey, hash_ecdsa, rh, sh)
		if verifystatus == true {
			//fmt.Printf(" Generated Signature is verified \n")
			verify_flag_status =1
		} else {
			fmt.Printf(" Generated Signature is incorrect \n")
			verify_flag_status =0
		}
	}

	//fmt.Printf("rh.Bytes() %x \n",rh.Bytes())
	//fmt.Printf("sh.Bytes() %x \n",sh.Bytes())

	return rh, sh, err
}
func rpmc_container(){
	var cfg Config
	err := gcfg.ReadFileInto(&cfg, cfgFileName)
	if err != nil {
		fmt.Printf("gcfg.ReadFileInto for config file %v returned error %v\n", cfgFileName, err)
		return
	}	
	fmt.Printf(" Enter rpmc_container \n")
	he := make([]byte, 0x5F4+(96))
	Authpubkey := make([]byte, KEY384size*2)
	_ = Authpubkey
	fillDword(0x00, he, cfg.RPMCContainerHeader.RPMCValue)
	fillDword(0x04, he, cfg.RPMCContainerHeader.ActiveContainerVersion)
	he[8] = cfg.RPMCContainerHeader.ContainerType
	fillDword(0x09, he, cfg.RPMCContainerHeader.SecureContainerContentLength)
	fillDword(0x0C, he, cfg.RPMCContainerHeader.DeviceSerialNumber063032)
	fillDword(0x10, he, cfg.RPMCContainerHeader.DeviceSerialNumber031000)
		if cfg.RPMCContainerHeader.ContainerCommandKeySHA384Hash0 != "" {
			AuthECPubKey, err := readECPublicKeyFromCert(cfg.RPMCContainerHeader.ContainerCommandKeySHA384Hash0)
			if err != nil {
				fmt.Printf("FW readECPublicKeyFromCert from file %v returned error %v \n", cfg.RPMCContainerHeader.ContainerCommandKeySHA384Hash0, err)
				return
			}
			mcopyWithLeftPad(Authpubkey[0:KEY384size], AuthECPubKey.X.Bytes())
			mcopyWithLeftPad(Authpubkey[KEY384size:KEY384size*2], AuthECPubKey.Y.Bytes())
			//print_bytes_as_hex(Authpubkey, "--------------------------- P U B K E Y . B Y T E S ---------------------------")
			hasher := sha512.New384()
			hasher.Write(Authpubkey)
			keyhash := hasher.Sum(nil)
			//copy(Keyhashblob[0:HASHsize], keyhash[0:HASHsize])
			copy(he[0x14:], keyhash)
			//print_bytes_as_hex(keyhash, "---------------------- P U B K E Y . B Y T E S . H A S H ----------------------")
		}
		if cfg.RPMCContainerHeader.ContainerCommandKeySHA384Hash1 != "" {
			AuthECPubKey, err := readECPublicKeyFromCert(cfg.RPMCContainerHeader.ContainerCommandKeySHA384Hash1)
			if err != nil {
				fmt.Printf("FW readECPublicKeyFromCert from file %v returned error %v \n", cfg.RPMCContainerHeader.ContainerCommandKeySHA384Hash1, err)
				return
			}
			mcopyWithLeftPad(Authpubkey[0:KEY384size], AuthECPubKey.X.Bytes())
			mcopyWithLeftPad(Authpubkey[KEY384size:KEY384size*2], AuthECPubKey.Y.Bytes())
			print_bytes_as_hex(Authpubkey, "--------------------------- P U B K E Y . B Y T E S ---------------------------")
			hasher := sha512.New384()
			hasher.Write(Authpubkey)
			keyhash := hasher.Sum(nil)
			//copy(Keyhashblob[0:HASHsize], keyhash[0:HASHsize])
			copy(he[0x14+0x30:], keyhash)
			//print_bytes_as_hex(keyhash, "---------------------- P U B K E Y . B Y T E S . H A S H ----------------------")
		}
		if cfg.RPMCContainerHeader.ContainerCommandKeySHA384Hash2 != "" {
			AuthECPubKey, err := readECPublicKeyFromCert(cfg.RPMCContainerHeader.ContainerCommandKeySHA384Hash2)
			if err != nil {
				fmt.Printf("FW readECPublicKeyFromCert from file %v returned error %v \n", cfg.RPMCContainerHeader.ContainerCommandKeySHA384Hash2, err)
				return
			}
			mcopyWithLeftPad(Authpubkey[0:KEY384size], AuthECPubKey.X.Bytes())
			mcopyWithLeftPad(Authpubkey[KEY384size:KEY384size*2], AuthECPubKey.Y.Bytes())
			print_bytes_as_hex(Authpubkey, "--------------------------- P U B K E Y . B Y T E S ---------------------------")
			hasher := sha512.New384()
			hasher.Write(Authpubkey)
			keyhash := hasher.Sum(nil)
			//copy(Keyhashblob[0:HASHsize], keyhash[0:HASHsize])
			copy(he[0x14+(0x30*2):], keyhash)
			//print_bytes_as_hex(keyhash, "---------------------- P U B K E Y . B Y T E S . H A S H ----------------------")
		}
		if cfg.RPMCContainerHeader.ContainerCommandKeySHA384Hash3 != "" {
			AuthECPubKey, err := readECPublicKeyFromCert(cfg.RPMCContainerHeader.ContainerCommandKeySHA384Hash3)
			if err != nil {
				fmt.Printf("FW readECPublicKeyFromCert from file %v returned error %v \n", cfg.RPMCContainerHeader.ContainerCommandKeySHA384Hash3, err)
				return
			}
			mcopyWithLeftPad(Authpubkey[0:KEY384size], AuthECPubKey.X.Bytes())
			mcopyWithLeftPad(Authpubkey[KEY384size:KEY384size*2], AuthECPubKey.Y.Bytes())
			print_bytes_as_hex(Authpubkey, "--------------------------- P U B K E Y . B Y T E S ---------------------------")
			hasher := sha512.New384()
			hasher.Write(Authpubkey)
			keyhash := hasher.Sum(nil)
			//copy(Keyhashblob[0:HASHsize], keyhash[0:HASHsize])
			copy(he[0x14+(0x30*3):], keyhash)
			//print_bytes_as_hex(keyhash, "---------------------- P U B K E Y . B Y T E S . H A S H ----------------------")
		}
		he[0xD4] = cfg.RPMCContainerContent.OwnerConfiguration
		fill16word(0x150, he, cfg.RPMCContainerContent.RollbackProtection)
				aesTestR := new(big.Int)
		aesTestR.SetString(cfg.RPMCContainerContent.OwnerID, 0)
		kxb := aesTestR.Bytes()
		copy(he[0xD8:], kxb)
		if cfg.RPMCContainerContent.OwnerTransferAuthorizationKey != "" {
			AuthECPubKey, err := readECPublicKeyFromCert(cfg.RPMCContainerContent.OwnerTransferAuthorizationKey)
			if err != nil {
				fmt.Printf("FW readECPublicKeyFromCert from file %v returned error %v \n", cfg.RPMCContainerContent.OwnerTransferAuthorizationKey, err)
				return
			}
			mcopyWithLeftPad(Authpubkey[0:KEY384size], AuthECPubKey.X.Bytes())
			mcopyWithLeftPad(Authpubkey[KEY384size:KEY384size*2], AuthECPubKey.Y.Bytes())
			copy(he[0xEC:], Authpubkey)
		}
		he[0x14C] = cfg.RPMCContainerContent.KeyRevocation

		tag := buildTag(cfg.RPMCContainerContent.TAG0ImageHeaderBaseAddress)
		copy(he[0x160:], tag[0:])

		tag = buildTag(cfg.RPMCContainerContent.TAG1ImageHeaderBaseAddress)
		copy(he[0x164:], tag[0:])
		if "" != cfg.RPMCContainerContent.ECDHprivatekey {
			//ECfwEntryidx := (uint)(ToTKEYS * HASHsize)
			ReadRawBytes, err := readAndReturnBinaryFile(cfg.RPMCContainerContent.ECDHprivatekey)
			if err != nil {
				fmt.Printf("FW readAndReturnBinaryFile(%v) returned error %v \n", cfg.RPMCContainerContent.ECDHprivatekey, err)
				return
			}
			copy(he[0x168:], ReadRawBytes)
		}
		if "" != cfg.RPMCContainerContent.ECDHPublicKey2 {
			//ECfwEntryidx := (uint)(ToTKEYS * HASHsize)
			ReadRawBytes, err := readAndReturnBinaryFile(cfg.RPMCContainerContent.ECDHPublicKey2)
			if err != nil {
				fmt.Printf("FW readAndReturnBinaryFile(%v) returned error %v \n", cfg.RPMCContainerContent.ECDHPublicKey2, err)
				return
			}
			copy(he[0x198:], ReadRawBytes)
		}
		if "" != cfg.RPMCContainerContent.SHA384KHB {
			//ECfwEntryidx := (uint)(ToTKEYS * HASHsize)
			ReadRawBytes, err := readAndReturnBinaryFile(cfg.RPMCContainerContent.SHA384KHB)
			if err != nil {
				fmt.Printf("FW readAndReturnBinaryFile(%v) returned error %v \n", cfg.RPMCContainerContent.SHA384KHB, err)
				return
			}
			copy(he[0x1C8:], ReadRawBytes)
		}

		he[0x1F8] = cfg.RPMCContainerContent.OwnerDebugOptions
		fill16word(0x1f9, he, cfg.RPMCContainerContent.OwnerPlatformID)
		he[0x1FB] = cfg.RPMCContainerContent.SecurityFeatures
		if "" != cfg.RPMCContainerContent.SHA384Platk {
			//ECfwEntryidx := (uint)(ToTKEYS * HASHsize)
			ReadRawBytes, err := readAndReturnBinaryFile(cfg.RPMCContainerContent.SHA384Platk)
			if err != nil {
				fmt.Printf("FW readAndReturnBinaryFile(%v) returned error %v \n", cfg.RPMCContainerContent.SHA384Platk, err)
				return
			}
			copy(he[0x1FC:], ReadRawBytes)
		}
		f1 := cfg.ContainerSignature.ContainerSignatureKeyFile
		f2 := cfg.ContainerSignature.ContainerSignatureKeyFilePass
		//f2 :="None"
		//mchp_sign_data = keyimg[cfg.Spi.RPMCFlashContainer:cfg.Spi.RPMCFlashContainer+0x22C+0x3C8]
		rh, sh, res := APTablesigningImage(f1, f2, he[0:0x5CF])
		_ = res
		//Hashtable0AP0F0 = make([]byte, 96)

		mcopyWithLeftPad(he[uint32(0x5CF):uint32(0x5CF)+48], rh.Bytes())
		mcopyWithLeftPad(he[uint32(0x5CF)+48:uint32(0x5CF)+96], sh.Bytes())
		outFileName := "rmpc_raw.bin"
		err = ioutil.WriteFile(formatted+"\\"+outFileName,  he[0:0x5CF], 0644)
		if err != nil {
			fmt.Printf("Error write Output file  to file %v return error %v \n", outFileName, err)
			return
		}
		outFileName = "rmpc_signature.bin"
		err = ioutil.WriteFile(formatted+"\\"+outFileName, he, 0644)
		if err != nil {
			fmt.Printf("Error write Output file  to file %v return error %v \n", outFileName, err)
			return
		}
		if verify_flag_status ==1{
			fmt.Printf(" Generated Create Container rpmc_raw.bin and rpmc_signature.bin \n")
			fmt.Printf(" Signature and verification is success \n")
		}
	fmt.Printf(" Exit rpmc_container \n")
}
func update_rpmc_container(){
	var cfg Config
	err := gcfg.ReadFileInto(&cfg, cfgFileName)
	if err != nil {
		fmt.Printf("gcfg.ReadFileInto for config file %v returned error %v\n", cfgFileName, err)
		return
	}	
	fmt.Printf(" Enter update_rpmc_container \n")
	//fmt.Printf("Value %x ",cfg.UpdateContainerRequest.SubCommand)
	he := make([]byte, 0)
	Authpubkey := make([]byte, KEY384size*2)
	_ = Authpubkey
	//if cfg.UpdateContainerRequest.SubCommand ==0{
		he = make([]byte, 0x4+20+1+(96*2))
		he[0x0] = cfg.UpdateContainerRequest.ContainerNumber
		he[0x1] = cfg.UpdateContainerRequest.ContainerType
		he[0x2] = cfg.UpdateContainerRequest.SubCommand
		fillDword(0x04, he, cfg.UpdateContainerRequest.KeyRevocationReq)
		aesTestR := new(big.Int)
		aesTestR.SetString(cfg.UpdateContainerRequest.ImageRevisionRollbackProt, 0)
		kxb := aesTestR.Bytes()
		copy(he[0x8:], kxb)

		he[0x18] = cfg.UpdateContainerRequest.SignaturePublicKeySelect
		if cfg.UpdateContainerRequest.PubKey != "" {
			AuthECPubKey, err := readECPublicKeyFromCert(cfg.UpdateContainerRequest.PubKey)
			if err != nil {
				fmt.Printf("FW cfg.UpdateContainerRequest.PubKey from file %v returned error %v \n", cfg.UpdateContainerRequest.PubKey, err)
				return
			}
			mcopyWithLeftPad(Authpubkey[0:KEY384size], AuthECPubKey.X.Bytes())
			mcopyWithLeftPad(Authpubkey[KEY384size:KEY384size*2], AuthECPubKey.Y.Bytes())
			//print_bytes_as_hex(Authpubkey, "--------------------------- P U B K E Y . B Y T E S ---------------------------")
			//hasher := sha512.New384()
			//hasher.Write(Authpubkey)
			//keyhash := hasher.Sum(nil)
			//copy(Keyhashblob[0:HASHsize], keyhash[0:HASHsize])
			copy(he[0x19:], Authpubkey)
			//print_bytes_as_hex(keyhash, "---------------------- P U B K E Y . B Y T E S . H A S H ----------------------")
		}
		var I_MCHP_Signature_string string ="UPDATE_CONTAINER_REQUEST"
		r1 := make([]byte, len(I_MCHP_Signature_string))
		//var a byte
		copy(r1[0:],I_MCHP_Signature_string)
		//len :=0
		//if "" != cfg.IncrementRPMCContainerRequest.SHA384PrimaryContainer {
				//ECfwEntryidx := (uint)(ToTKEYS * HASHsize)
				ReadRawBytes, err := readAndReturnBinaryFile(cfg.UpdateContainerRequest.SHA384PrimaryContainer)
				if err != nil {
					fmt.Printf("FW readAndReturnBinaryFile(%v) returned error %v \n", cfg.UpdateContainerRequest.SHA384PrimaryContainer, err)
					return
				}
				//copy(he[0xEf:], ReadRawBytes)

		//}
		//fmt.Printf("R1 len(MCHP_Signature_string) " ,r1,len(MCHP_Signature_string))
		s := make([]byte, len(I_MCHP_Signature_string)+0x4+20+1+(96)+len(ReadRawBytes)+96)
		copy(s[0:],I_MCHP_Signature_string)
		copy(s[len(I_MCHP_Signature_string):],he[0x00:0x4+20+1+(96)])
		copy(s[len(I_MCHP_Signature_string)+0x4+20+1+(96):],ReadRawBytes)

		outFileName := "contatenate_update_container_subcommand_0_raw_to_sign.bin"
		err = ioutil.WriteFile(formatted+"\\"+outFileName, s[0:len(I_MCHP_Signature_string)+0x4+20+1+(96)+len(ReadRawBytes)], 0644)
		if err != nil {
			fmt.Printf("Error write Output file  to file %v return error %v \n", outFileName, err)
			return
		}		
		f1 := cfg.UpdateContainerRequest.PrivateKey
		f2 := cfg.UpdateContainerRequest.PrivateKeyPass
		//f2 :="None"
		//mchp_sign_data = keyimg[cfg.Spi.RPMCFlashContainer:cfg.Spi.RPMCFlashContainer+0x22C+0x3C8]
		rh, sh, res := APTablesigningImage(f1, f2, s[0:len(I_MCHP_Signature_string)+0x4+20+1+(96)+len(ReadRawBytes)])
		_ = res
		len1 :=len(I_MCHP_Signature_string)+0x4+20+1+(96)//+len(ReadRawBytes) 			
		mcopyWithLeftPad(s[len1:len1+48], rh.Bytes())
		mcopyWithLeftPad(s[len1+48:len1+96], sh.Bytes())
		len2 :=len1+96
		outFileName_1 := "contatenate_update_container_subcommand_0_signature.bin"
		err = ioutil.WriteFile(formatted+"\\"+outFileName_1, s[len(I_MCHP_Signature_string):len2], 0644)
		if err != nil {
			fmt.Printf("Error write Output file  to file %v return error %v \n", outFileName_1, err)
			return
		}	
		if verify_flag_status ==1{
			fmt.Printf(" Generated %s %s \n",outFileName,outFileName_1)
			fmt.Printf(" Signature and verification is success \n")
		}
/*
		rh, sh, res = APTablesigningImage(f1, f2, he[0x0:0x4+20+1+(96*1)])
		_ = res
		//Hashtable0AP0F0 = make([]byte, 96)
		err = ioutil.WriteFile(formatted+"\\"+"update_container_raw.bin", he[0x0:0x4+20+1+(96*1)], 0644)
		if err != nil {
			fmt.Printf("Error write Output file  to file %v return error %v \n", "update_container_raw.bin", err)
			return
		}			
		mcopyWithLeftPad(he[uint32(0x4+20+1+(96*1)):uint32(0x4+20+1+(96*1))+48], rh.Bytes())
		mcopyWithLeftPad(he[uint32(0x4+20+1+(96*1))+48:uint32(0x4+20+1+(96*1))+96], sh.Bytes())
		//outFileName := "update_container_signature.bin"
		err = ioutil.WriteFile(formatted+"\\"+"update_container_signature.bin", he, 0644)
		if err != nil {
			fmt.Printf("Error write Output file  to file %v return error %v \n", "update_container_signature.bin", err)
			return
		}	
		if verify_flag_status ==1{
			fmt.Printf(" Generated Create Container update_container_raw.bin and update_container_signature.bin \n")
			fmt.Printf(" Signature and verification is success \n")
		}



		//fmt.Printf(" Exit update_rpmc_container ")
	//	fmt.Printf(" Exit update_rpmc_container ")

*/	
		return
}
func update_rpmc_container_subcommand_transfer(){
	var cfg Config
	err := gcfg.ReadFileInto(&cfg, cfgFileName)
	if err != nil {
		fmt.Printf("gcfg.ReadFileInto for config file %v returned error %v\n", cfgFileName, err)
		return
	}	
	fmt.Printf(" Enter update_rpmc_container ")
	fmt.Printf("Value %x ",cfg.UpdateContainerRequestTransfer.SubCommand)
	he := make([]byte, 0)
	Authpubkey := make([]byte, KEY384size*2)
	_ = Authpubkey

		he = make([]byte, 0x185+1+48+(96*2))
		he[0x0] = cfg.UpdateContainerRequestTransfer.ContainerNumber
		he[0x1] = cfg.UpdateContainerRequestTransfer.ContainerType
		he[0x2] = cfg.UpdateContainerRequestTransfer.SubCommand		
		fillDword(0x04, he, cfg.UpdateContainerRequestTransfer.SecureContainerContentLen)
	if cfg.UpdateContainerRequestTransfer.ContainerCommandKey0 != "" {
			AuthECPubKey, err := readECPublicKeyFromCert(cfg.UpdateContainerRequestTransfer.ContainerCommandKey0)
			if err != nil {
				fmt.Printf("FW cfg.UpdateContainerRequestTransfer.ContainerCommandKey0 from file %v returned error %v \n", cfg.UpdateContainerRequest.ContainerCommandKey0, err)
				return
			}
			mcopyWithLeftPad(Authpubkey[0:KEY384size], AuthECPubKey.X.Bytes())
			mcopyWithLeftPad(Authpubkey[KEY384size:KEY384size*2], AuthECPubKey.Y.Bytes())
			//print_bytes_as_hex(Authpubkey, "--------------------------- P U B K E Y . B Y T E S ---------------------------")
			hasher := sha512.New384()
			hasher.Write(Authpubkey)
			keyhash := hasher.Sum(nil)
			//copy(Keyhashblob[0:HASHsize], keyhash[0:HASHsize])
			copy(he[0x7:], keyhash[0:HASHsize])
			//print_bytes_as_hex(keyhash, "---------------------- P U B K E Y . B Y T E S . H A S H ----------------------")
	}
	if cfg.UpdateContainerRequestTransfer.ContainerCommandKey1 != "" {
			AuthECPubKey, err := readECPublicKeyFromCert(cfg.UpdateContainerRequestTransfer.ContainerCommandKey1)
			if err != nil {
				fmt.Printf("FW cfg.UpdateContainerRequestTransfer.ContainerCommandKey1 from file %v returned error %v \n", cfg.UpdateContainerRequest.ContainerCommandKey1, err)
				return
			}
			mcopyWithLeftPad(Authpubkey[0:KEY384size], AuthECPubKey.X.Bytes())
			mcopyWithLeftPad(Authpubkey[KEY384size:KEY384size*2], AuthECPubKey.Y.Bytes())
			//print_bytes_as_hex(Authpubkey, "--------------------------- P U B K E Y . B Y T E S ---------------------------")
			hasher := sha512.New384()
			hasher.Write(Authpubkey)
			keyhash := hasher.Sum(nil)
			//copy(Keyhashblob[0:HASHsize], keyhash[0:HASHsize])
			copy(he[0x37:], keyhash[0:HASHsize])
			//print_bytes_as_hex(keyhash, "---------------------- P U B K E Y . B Y T E S . H A S H ----------------------")
	}
	if cfg.UpdateContainerRequestTransfer.ContainerCommandKey2 != "" {
			AuthECPubKey, err := readECPublicKeyFromCert(cfg.UpdateContainerRequestTransfer.ContainerCommandKey2)
			if err != nil {
				fmt.Printf("FW cfg.UpdateContainerRequestTransfer.ContainerCommandKey2 from file %v returned error %v \n", cfg.UpdateContainerRequest.ContainerCommandKey2, err)
				return
			}
			mcopyWithLeftPad(Authpubkey[0:KEY384size], AuthECPubKey.X.Bytes())
			mcopyWithLeftPad(Authpubkey[KEY384size:KEY384size*2], AuthECPubKey.Y.Bytes())
			//print_bytes_as_hex(Authpubkey, "--------------------------- P U B K E Y . B Y T E S ---------------------------")
			hasher := sha512.New384()
			hasher.Write(Authpubkey)
			keyhash := hasher.Sum(nil)
			//copy(Keyhashblob[0:HASHsize], keyhash[0:HASHsize])
			copy(he[0x67:], keyhash[0:HASHsize])
			//print_bytes_as_hex(keyhash, "---------------------- P U B K E Y . B Y T E S . H A S H ----------------------")
	}
	if cfg.UpdateContainerRequestTransfer.ContainerCommandKey3 != "" {
			AuthECPubKey, err := readECPublicKeyFromCert(cfg.UpdateContainerRequestTransfer.ContainerCommandKey3)
			if err != nil {
				fmt.Printf("FW cfg.UpdateContainerRequestTransfer.ContainerCommandKey3 from file %v returned error %v \n", cfg.UpdateContainerRequest.ContainerCommandKey3, err)
				return
			}
			mcopyWithLeftPad(Authpubkey[0:KEY384size], AuthECPubKey.X.Bytes())
			mcopyWithLeftPad(Authpubkey[KEY384size:KEY384size*2], AuthECPubKey.Y.Bytes())
			//print_bytes_as_hex(Authpubkey, "--------------------------- P U B K E Y . B Y T E S ---------------------------")
			hasher := sha512.New384()
			hasher.Write(Authpubkey)
			keyhash := hasher.Sum(nil)
			//copy(Keyhashblob[0:HASHsize], keyhash[0:HASHsize])
			copy(he[0x97:], keyhash[0:HASHsize])
			//print_bytes_as_hex(keyhash, "---------------------- P U B K E Y . B Y T E S . H A S H ----------------------")
	}
	he[0xC7] = cfg.UpdateContainerRequestTransfer.OwnerConfiguration
	aesTestR := new(big.Int)
	aesTestR.SetString(cfg.UpdateContainerRequestTransfer.OwnerID, 0)
	kxb := aesTestR.Bytes()
	copy(he[0xC8:], kxb)
	he[0xD8] = cfg.UpdateContainerRequestTransfer.KeyRevocation

	aesTestR = new(big.Int)
	aesTestR.SetString(cfg.UpdateContainerRequestTransfer.RollbackProtection, 0)
	kxb = aesTestR.Bytes()
	copy(he[0xD9:], kxb)

	fillDword(0xE9, he, cfg.UpdateContainerRequestTransfer.TAG0ImageHeaderBaseAddress)
	fillDword(0xED, he, cfg.UpdateContainerRequestTransfer.TAG1ImageHeaderBaseAddress)

	if "" != cfg.UpdateContainerRequestTransfer.ECDHprivatekey {
			//ECfwEntryidx := (uint)(ToTKEYS * HASHsize)
			ReadRawBytes, err := readAndReturnBinaryFile(cfg.UpdateContainerRequestTransfer.ECDHprivatekey)
			if err != nil {
				fmt.Printf("FW readAndReturnBinaryFile(%v) returned error %v \n", cfg.UpdateContainerRequestTransfer.ECDHprivatekey, err)
				return
			}
			copy(he[0xF1:], ReadRawBytes)
	}
	if "" != cfg.UpdateContainerRequestTransfer.ECDHPublicKey2 {
			//ECfwEntryidx := (uint)(ToTKEYS * HASHsize)
			ReadRawBytes, err := readAndReturnBinaryFile(cfg.UpdateContainerRequestTransfer.ECDHPublicKey2)
			if err != nil {
				fmt.Printf("FW readAndReturnBinaryFile(%v) returned error %v \n", cfg.UpdateContainerRequestTransfer.ECDHPublicKey2, err)
				return
			}
			copy(he[0x121:], ReadRawBytes)
	}
	if "" != cfg.UpdateContainerRequestTransfer.SHA384KHB {
			//ECfwEntryidx := (uint)(ToTKEYS * HASHsize)
			ReadRawBytes, err := readAndReturnBinaryFile(cfg.UpdateContainerRequestTransfer.SHA384KHB)
			if err != nil {
				fmt.Printf("FW readAndReturnBinaryFile(%v) returned error %v \n", cfg.UpdateContainerRequestTransfer.SHA384KHB, err)
				return
			}
			copy(he[0x151:], ReadRawBytes)
	}
	he[0x181] = cfg.UpdateContainerRequestTransfer.OwnerDebugOptions
	fill16word(0x182, he, cfg.UpdateContainerRequestTransfer.OwnerPlatformID)
	he[0x184] = cfg.UpdateContainerRequestTransfer.SecurityFeatures
	if "" != cfg.UpdateContainerRequestTransfer.SHA384Platk {
			//ECfwEntryidx := (uint)(ToTKEYS * HASHsize)
			ReadRawBytes, err := readAndReturnBinaryFile(cfg.UpdateContainerRequestTransfer.SHA384Platk)
			if err != nil {
				fmt.Printf("FW cfg.UpdateContainerRequestTransfer.SHA384Platk(%v) returned error %v \n", cfg.UpdateContainerRequestTransfer.SHA384Platk, err)
				return
			}
			copy(he[0x185:], ReadRawBytes)
	}
	he[0x185+48] = cfg.UpdateContainerRequestTransfer.SignaturePublicKeySelect
	if cfg.UpdateContainerRequestTransfer.PubKey != "" {
			AuthECPubKey, err := readECPublicKeyFromCert(cfg.UpdateContainerRequestTransfer.PubKey)
			if err != nil {
				fmt.Printf("FW cfg.UpdateContainerRequestTransfer.PubKey from file %v returned error %v \n", cfg.UpdateContainerRequestTransfer.PubKey, err)
				return
			}
			mcopyWithLeftPad(Authpubkey[0:KEY384size], AuthECPubKey.X.Bytes())
			mcopyWithLeftPad(Authpubkey[KEY384size:KEY384size*2], AuthECPubKey.Y.Bytes())
			//print_bytes_as_hex(Authpubkey, "--------------------------- P U B K E Y . B Y T E S ---------------------------")
			//hasher := sha512.New384()
			//hasher.Write(Authpubkey)
			//keyhash := hasher.Sum(nil)
			//copy(Keyhashblob[0:HASHsize], keyhash[0:HASHsize])
			copy(he[0x185+49:], Authpubkey)
			//print_bytes_as_hex(keyhash, "---------------------- P U B K E Y . B Y T E S . H A S H ----------------------")
	}
		var I_MCHP_Signature_string string ="UPDATE_CONTAINER_REQUEST"
		r1 := make([]byte, len(I_MCHP_Signature_string))
		//var a byte
		copy(r1[0:],I_MCHP_Signature_string)
		//len :=0
		//if "" != cfg.IncrementRPMCContainerRequest.SHA384PrimaryContainer {
				//ECfwEntryidx := (uint)(ToTKEYS * HASHsize)
				ReadRawBytes, err := readAndReturnBinaryFile(cfg.UpdateContainerRequestTransfer.SHA384PrimaryContainer)
				if err != nil {
					fmt.Printf("FW readAndReturnBinaryFile(%v) returned error %v \n", cfg.UpdateContainerRequestTransfer.SHA384PrimaryContainer, err)
					return
				}
				//copy(he[0xEf:], ReadRawBytes)

		//}
		//fmt.Printf("R1 len(MCHP_Signature_string) " ,r1,len(MCHP_Signature_string))
		s := make([]byte, len(I_MCHP_Signature_string)+0x185+48+1+(96*1)+len(ReadRawBytes)+96)
		copy(s[0:],I_MCHP_Signature_string)
		copy(s[len(I_MCHP_Signature_string):],he[0x00:0x185+48+1+(96*1)])
		copy(s[len(I_MCHP_Signature_string)+0x185+48+1+(96*1):],ReadRawBytes)

		outFileName := "contatenate_update_container_subcommand_1_raw_to_sign.bin"
		err = ioutil.WriteFile(formatted+"\\"+outFileName, s[0:len(I_MCHP_Signature_string)+0x185+48+1+(96*1)+len(ReadRawBytes)], 0644)
		if err != nil {
			fmt.Printf("Error write Output file  to file %v return error %v \n", outFileName, err)
			return
		}	

		f1 := cfg.UpdateContainerRequestTransfer.PrivateKey
		f2 := cfg.UpdateContainerRequestTransfer.PrivateKeyPass
		//f2 :="None"
		//mchp_sign_data = keyimg[cfg.Spi.RPMCFlashContainer:cfg.Spi.RPMCFlashContainer+0x22C+0x3C8]
		rh, sh, res := APTablesigningImage(f1, f2, s[0:len(I_MCHP_Signature_string)+0x185+48+1+(96*1)+len(ReadRawBytes)])//he[0x0:0x185+48+1+(96*1)])
		_ = res
		len1 :=len(I_MCHP_Signature_string)+0x185+48+1+(96*1)//+len(ReadRawBytes)		
		mcopyWithLeftPad(s[len1:len1+48], rh.Bytes())
		mcopyWithLeftPad(s[len1+48:len1+96], sh.Bytes())
		len2 := len1 +96
		outFileName_1 := "contatenate_update_container_subcommand_1_signature.bin"
		err = ioutil.WriteFile(formatted+"\\"+outFileName_1, s[len(I_MCHP_Signature_string):len2], 0644)
		if err != nil {
			fmt.Printf("Error write Output file  to file %v return error %v \n", outFileName, err)
			return
		}	
		if verify_flag_status ==1{
			fmt.Printf("\n Generated %s %s \n",outFileName,outFileName_1)
			fmt.Printf("\n Signature and verification is success \n")
		}
/*
		rh, sh, res = APTablesigningImage(f1, f2, he[0x0:0x185+48+1+(96*1)])//he[0x0:0x185+48+1+(96*1)])
		_ = res
		//Hashtable0AP0F0 = make([]byte, 96)
		err = ioutil.WriteFile(formatted+"\\"+"update_container_raw.bin", he[0x0:0x185+48+1+(96*1)], 0644)
		if err != nil {
			fmt.Printf("Error write Output file  to file %v return error %v \n", "update_container_raw.bin", err)
			return
		}			
		mcopyWithLeftPad(he[uint32(0x185+48+1+(96*1)):uint32(0x185+48+1+(96*1))+48], rh.Bytes())
		mcopyWithLeftPad(he[uint32(0x185+48+1+(96*1))+48:uint32(0x185+48+1+(96*1))+96], sh.Bytes())
		outFileName = "update_container_signature.bin"
		err = ioutil.WriteFile(formatted+"\\"+"update_container_signature.bin", he, 0644)
		if err != nil {
			fmt.Printf("Error write Output file  to file %v return error %v \n", outFileName, err)
			return
		}	
		if verify_flag_status ==1{
			fmt.Printf("\n Generated Create Container update_container_raw.bin and update_container_signature.bin \n")
			fmt.Printf("\n Signature and verification is success \n")
		}
		fmt.Printf(" Exit update_rpmc_container ")
*/
		return

	
}
func modify_rpmc_container(){
		var cfg Config
	err := gcfg.ReadFileInto(&cfg, cfgFileName)
	if err != nil {
		fmt.Printf("gcfg.ReadFileInto for config file %v returned error %v\n", cfgFileName, err)
		return
	}
	//fmt.Printf("Enter repair_rpmc_container ")
	he := make([]byte, 0xa)
	_ =he
	//Authpubkey := make([]byte, KEY384size*2)
	//_ = Authpubkey
	he[0x0] = cfg.ModifyTagxBaseAddress.ContainerNumber
	he[0x1] = cfg.ModifyTagxBaseAddress.ContainerType

	fillDword(0x2, he, cfg.ModifyTagxBaseAddress.TAG0ImageHeaderBaseAddress)
	fillDword(0x6, he, cfg.ModifyTagxBaseAddress.TAG1ImageHeaderBaseAddress)
		outFileName := "modify_tagx_baseaddress_container.bin"
		err = ioutil.WriteFile(formatted+"\\"+"modify_tagx_baseaddress_container.bin", he, 0644)
		if err != nil {
			fmt.Printf("Error write Output file  to file %v return error %v \n", outFileName, err)
			return
		}
}

func ota_pub_rpmc_container(){
		var cfg Config
	err := gcfg.ReadFileInto(&cfg, cfgFileName)
	if err != nil {
		fmt.Printf("gcfg.ReadFileInto for config file %v returned error %v\n", cfgFileName, err)
		return
	}
	//fmt.Printf("Enter repair_rpmc_container ")
	he := make([]byte, 0xC3+(96))
	_ =he
	Authpubkey := make([]byte, KEY384size*2)
	_ = Authpubkey
	he[0x0] = cfg.UpdateOTAKey.ContainerNumber
	he[0x1] = cfg.UpdateOTAKey.ContainerType
	//he[0x2] = cfg.EnableUnrestrictedTransfers.OwnerConfiguration
	if cfg.UpdateOTAKey.OTAPub != "" {
			AuthECPubKey, err := readECPublicKeyFromCert(cfg.UpdateOTAKey.OTAPub)
			if err != nil {
				fmt.Printf("FW cfg.UpdateOTAKey.OTAPub from file %v returned error %v \n", cfg.UpdateOTAKey.OTAPub, err)
				return
			}
			mcopyWithLeftPad(Authpubkey[0:KEY384size], AuthECPubKey.X.Bytes())
			mcopyWithLeftPad(Authpubkey[KEY384size:KEY384size*2], AuthECPubKey.Y.Bytes())
			//print_bytes_as_hex(Authpubkey, "--------------------------- P U B K E Y . B Y T E S ---------------------------")
			//hasher := sha512.New384()
			//hasher.Write(Authpubkey)
			//keyhash := hasher.Sum(nil)
			//copy(Keyhashblob[0:HASHsize], keyhash[0:HASHsize])
			copy(he[0x2:], Authpubkey)
			//print_bytes_as_hex(keyhash, "---------------------- P U B K E Y . B Y T E S . H A S H ----------------------")
	}
	he[0x62] = cfg.UpdateOTAKey.SignaturePublicKeySelect
	if cfg.UpdateOTAKey.PubKey != "" {
			AuthECPubKey, err := readECPublicKeyFromCert(cfg.UpdateOTAKey.PubKey)
			if err != nil {
				fmt.Printf("FW cfg.UpdateOTAKey.PubKey from file %v returned error %v \n", cfg.UpdateOTAKey.PubKey, err)
				return
			}
			mcopyWithLeftPad(Authpubkey[0:KEY384size], AuthECPubKey.X.Bytes())
			mcopyWithLeftPad(Authpubkey[KEY384size:KEY384size*2], AuthECPubKey.Y.Bytes())
			//print_bytes_as_hex(Authpubkey, "--------------------------- P U B K E Y . B Y T E S ---------------------------")
			//hasher := sha512.New384()
			//hasher.Write(Authpubkey)
			//keyhash := hasher.Sum(nil)
			//copy(Keyhashblob[0:HASHsize], keyhash[0:HASHsize])
			copy(he[0x63:], Authpubkey)
			//print_bytes_as_hex(keyhash, "---------------------- P U B K E Y . B Y T E S . H A S H ----------------------")
	}
		var I_MCHP_Signature_string string ="UPDATE_OTAK_KEY"
		r1 := make([]byte, len(I_MCHP_Signature_string))
		//var a byte
		copy(r1[0:],I_MCHP_Signature_string)
		//len :=0
		//if "" != cfg.IncrementRPMCContainerRequest.SHA384PrimaryContainer {
				//ECfwEntryidx := (uint)(ToTKEYS * HASHsize)
				ReadRawBytes, err := readAndReturnBinaryFile(cfg.UpdateOTAKey.SHA384PrimaryContainer)
				if err != nil {
					fmt.Printf("FW readAndReturnBinaryFile(%v) returned error %v \n", cfg.UpdateOTAKey.SHA384PrimaryContainer, err)
					return
				}
				//copy(he[0xEf:], ReadRawBytes)

		//}
		//fmt.Printf("R1 len(MCHP_Signature_string) " ,r1,len(MCHP_Signature_string))
		s := make([]byte, len(I_MCHP_Signature_string)+0xC3+len(ReadRawBytes)+96)
		copy(s[0:],I_MCHP_Signature_string)
		copy(s[len(I_MCHP_Signature_string):],he[0x00:0xC3])
		copy(s[len(I_MCHP_Signature_string)+0xC3:],ReadRawBytes)

		outFileName = "contatenate_update_OTAAPub_container_raw_to_sign.bin"
		err = ioutil.WriteFile(formatted+"\\"+outFileName, s[0:len(I_MCHP_Signature_string)+0xC3+len(ReadRawBytes)], 0644)
		if err != nil {
			fmt.Printf("Error write Output file  to file %v return error %v \n", outFileName, err)
			return
		}	
		f1 := cfg.UpdateOTAKey.PrivateKey
		f2 := cfg.UpdateOTAKey.PrivateKeyPass
		//f2 :="None"
		//mchp_sign_data = keyimg[cfg.Spi.RPMCFlashContainer:cfg.Spi.RPMCFlashContainer+0x22C+0x3C8]
		rh, sh, res := APTablesigningImage(f1, f2, s[0:len(I_MCHP_Signature_string)+0xC3+len(ReadRawBytes)])//he[0x0:0xC3])
		_ = res
		//Hashtable0AP0F0 = make([]byte, 96)
		len1 :=len(I_MCHP_Signature_string)+0xC3//len(ReadRawBytes)		
		mcopyWithLeftPad(s[len1:len1+48], rh.Bytes())
		mcopyWithLeftPad(s[len1+48:len1+96], sh.Bytes())
	//outFileName := "create_container_signature.bin"
		len2 :=len1-len(I_MCHP_Signature_string)+96
		fmt.Printf("len2 in the otp pub len2 %x  len1 %x ",len2,len1)
	outFileName_1 := "contatenate_update_OTAAPub_container_signature.bin"
	err = ioutil.WriteFile(formatted+"\\"+outFileName_1, s[len(I_MCHP_Signature_string):len(I_MCHP_Signature_string)+len2], 0644)
	if err != nil {
		fmt.Printf("Error write Output file  to file %v return error %v \n", outFileName_1, err)
		return
	}	
	if verify_flag_status ==1{
		fmt.Printf(" Generated Create %s %s  \n",outFileName,outFileName_1)
		fmt.Printf(" Signature and verification is success \n")
	}
	return
/*	
		rh, sh, res = APTablesigningImage(f1, f2, s)//he[0x0:0xC3])
		_ = res
		//Hashtable0AP0F0 = make([]byte, 96)
		err = ioutil.WriteFile(formatted+"\\"+"update_OTAAPub_container_raw.bin", he[0x0:0xC3], 0644)
		if err != nil {
			fmt.Printf("Error write Output file  to file %v return error %v \n", outFileName, err)
			return
		}			
		mcopyWithLeftPad(he[uint32(0xC3):uint32(0xC3)+48], rh.Bytes())
		mcopyWithLeftPad(he[uint32(0xC3)+48:uint32(0xC3)+96], sh.Bytes())
	//outFileName := "create_container_signature.bin"
	err = ioutil.WriteFile(formatted+"\\"+"update_OTAAPub_container_signature.bin", he, 0644)
	if err != nil {
		fmt.Printf("Error write Output file  to file %v return error %v \n", "update_OTAAPub_container_signature.bin", err)
		return
	}	
	if verify_flag_status ==1{
		fmt.Printf(" Generated Create Container update_OTAAPub_container_raw.bin and update_OTAAPub_container_signature.bin \n")
		fmt.Printf(" Signature and verification is success \n")
	}	
*/
}
func enable_unrestricted_rpmc_container(){
		var cfg Config
	err := gcfg.ReadFileInto(&cfg, cfgFileName)
	if err != nil {
		fmt.Printf("gcfg.ReadFileInto for config file %v returned error %v\n", cfgFileName, err)
		return
	}
	//fmt.Printf("Enter repair_rpmc_container ")
	he := make([]byte, 0xC4+(96))
	_ =he
	Authpubkey := make([]byte, KEY384size*2)
	_ = Authpubkey
	he[0x0] = cfg.EnableUnrestrictedTransfers.ContainerNumber
	he[0x1] = cfg.EnableUnrestrictedTransfers.ContainerType
	he[0x2] = cfg.EnableUnrestrictedTransfers.OwnerConfiguration
	if cfg.EnableUnrestrictedTransfers.OTAPub != "" {
			AuthECPubKey, err := readECPublicKeyFromCert(cfg.EnableUnrestrictedTransfers.OTAPub)
			if err != nil {
				fmt.Printf("FW cfg.EnableUnrestrictedTransfers.OTAPub from file %v returned error %v \n", cfg.EnableUnrestrictedTransfers.OTAPub, err)
				return
			}
			mcopyWithLeftPad(Authpubkey[0:KEY384size], AuthECPubKey.X.Bytes())
			mcopyWithLeftPad(Authpubkey[KEY384size:KEY384size*2], AuthECPubKey.Y.Bytes())
			//print_bytes_as_hex(Authpubkey, "--------------------------- P U B K E Y . B Y T E S ---------------------------")
			//hasher := sha512.New384()
			//hasher.Write(Authpubkey)
			//keyhash := hasher.Sum(nil)
			//copy(Keyhashblob[0:HASHsize], keyhash[0:HASHsize])
			copy(he[0x3:], Authpubkey)
			//print_bytes_as_hex(keyhash, "---------------------- P U B K E Y . B Y T E S . H A S H ----------------------")
	}
	he[0x63] = cfg.EnableUnrestrictedTransfers.SignaturePublicKeySelect
	if cfg.EnableUnrestrictedTransfers.PubKey != "" {
			AuthECPubKey, err := readECPublicKeyFromCert(cfg.EnableUnrestrictedTransfers.PubKey)
			if err != nil {
				fmt.Printf("FW cfg.EnableUnrestrictedTransfers.PubKey from file %v returned error %v \n", cfg.EnableUnrestrictedTransfers.PubKey, err)
				return
			}
			mcopyWithLeftPad(Authpubkey[0:KEY384size], AuthECPubKey.X.Bytes())
			mcopyWithLeftPad(Authpubkey[KEY384size:KEY384size*2], AuthECPubKey.Y.Bytes())
			//print_bytes_as_hex(Authpubkey, "--------------------------- P U B K E Y . B Y T E S ---------------------------")
			//hasher := sha512.New384()
			//hasher.Write(Authpubkey)
			//keyhash := hasher.Sum(nil)
			//copy(Keyhashblob[0:HASHsize], keyhash[0:HASHsize])
			copy(he[0x64:], Authpubkey)
			//print_bytes_as_hex(keyhash, "---------------------- P U B K E Y . B Y T E S . H A S H ----------------------")
	}
		var I_MCHP_Signature_string string ="ENABLE_UNRESTRICTED_TRANSFERS"
		r1 := make([]byte, len(I_MCHP_Signature_string))
		//var a byte
		copy(r1[0:],I_MCHP_Signature_string)
		//len :=0
		//if "" != cfg.IncrementRPMCContainerRequest.SHA384PrimaryContainer {
				//ECfwEntryidx := (uint)(ToTKEYS * HASHsize)
				ReadRawBytes, err := readAndReturnBinaryFile(cfg.EnableUnrestrictedTransfers.SHA384PrimaryContainer)
				if err != nil {
					fmt.Printf("FW readAndReturnBinaryFile(%v) returned error %v \n", cfg.EnableUnrestrictedTransfers.SHA384PrimaryContainer, err)
					return
				}
				//copy(he[0xEf:], ReadRawBytes)

		//}
		//fmt.Printf("R1 len(MCHP_Signature_string) " ,r1,len(MCHP_Signature_string))
		s := make([]byte, len(I_MCHP_Signature_string)+0xC4+96+len(ReadRawBytes))
		copy(s[0:],I_MCHP_Signature_string)
		copy(s[len(I_MCHP_Signature_string):],he[0x00:0xC4])
		copy(s[len(I_MCHP_Signature_string)+0xC4:],ReadRawBytes)

		outFileName = "contatenate_enable_unrestricted_container_raw_to_sign.bin"
		err = ioutil.WriteFile(formatted+"\\"+outFileName, s[0:len(I_MCHP_Signature_string)+0xC4+len(ReadRawBytes)], 0644)
		if err != nil {
			fmt.Printf("Error write Output file  to file %v return error %v \n", outFileName, err)
			return
		}	
		f1 := cfg.EnableUnrestrictedTransfers.PrivateKey
		f2 := cfg.EnableUnrestrictedTransfers.PrivateKeyPass
		//f2 :="None"
		//mchp_sign_data = keyimg[cfg.Spi.RPMCFlashContainer:cfg.Spi.RPMCFlashContainer+0x22C+0x3C8]
		rh, sh, res := APTablesigningImage(f1, f2, s[0:len(I_MCHP_Signature_string)+0xC4+len(ReadRawBytes)])//he[0x0:0xC4])
		_ = res
		//Hashtable0AP0F0 = make([]byte, 96)
		len1 := len(I_MCHP_Signature_string)+0xC4//+len(ReadRawBytes)			
		mcopyWithLeftPad(s[len1:len1+48], rh.Bytes())
		mcopyWithLeftPad(s[len1+48:len1+96], sh.Bytes())
		len2 :=0xC4+96
	outFileName_1 := "contatenate_enable_unrestricted_container_signature.bin"
	err = ioutil.WriteFile(formatted+"\\"+outFileName_1, s[len(I_MCHP_Signature_string):len(I_MCHP_Signature_string)+len2], 0644)
	if err != nil {
		fmt.Printf("Error write Output file  to file %v return error %v \n", outFileName_1, err)
		return
	}	
	if verify_flag_status ==1{
		fmt.Printf(" Generated Create %s %s  \n",outFileName,outFileName_1)
		fmt.Printf(" Signature and verification is success \n")
	}
	return
	/*
		rh, sh, res = APTablesigningImage(f1, f2, s)//he[0x0:0xC4])
		_ = res
		//Hashtable0AP0F0 = make([]byte, 96)
		err = ioutil.WriteFile(formatted+"\\"+"enable_unrestricted_container_raw.bin", he[0x0:0xC4], 0644)
		if err != nil {
			fmt.Printf("Error write Output file  to file %v return error %v \n", outFileName, err)
			return
		}			
		mcopyWithLeftPad(he[uint32(0xC4):uint32(0xC4)+48], rh.Bytes())
		mcopyWithLeftPad(he[uint32(0xC4)+48:uint32(0xC4)+96], sh.Bytes())
	//outFileName := "create_container_signature.bin"
	err = ioutil.WriteFile(formatted+"\\"+"enable_unrestricted_container_signature.bin", he, 0644)
	if err != nil {
		fmt.Printf("Error write Output file  to file %v return error %v \n", "enable_unrestricted_container_signature.bin", err)
		return
	}	
	if verify_flag_status ==1{
		fmt.Printf(" Generated Create Container enable_unrestricted_container_raw.bin and enable_unrestricted_container_signature.bin \n")
		fmt.Printf(" Signature and verification is success \n")
	}
	*/
}
func repair_rpmc_container(){
	var cfg Config
	err := gcfg.ReadFileInto(&cfg, cfgFileName)
	if err != nil {
		fmt.Printf("gcfg.ReadFileInto for config file %v returned error %v\n", cfgFileName, err)
		return
	}
	//fmt.Printf("Enter repair_rpmc_container ")
	he := make([]byte, 0x3+(96*2))
	_ =he
	Authpubkey := make([]byte, KEY384size*2)
	_ = Authpubkey
	he[0x0] = cfg.RepairFallbackContainerRequest.ContainerNumber
	he[0x1] = cfg.RepairFallbackContainerRequest.ContainerType
	he[0x2] = cfg.RepairFallbackContainerRequest.SignaturePublicKeySelect
	if cfg.RepairFallbackContainerRequest.PubKey != "" {
			AuthECPubKey, err := readECPublicKeyFromCert(cfg.RepairFallbackContainerRequest.PubKey)
			if err != nil {
				fmt.Printf("FW cfg.RepairFallbackContainerRequest.PubKey from file %v returned error %v \n", cfg.RepairFallbackContainerRequest.PubKey, err)
				return
			}
			mcopyWithLeftPad(Authpubkey[0:KEY384size], AuthECPubKey.X.Bytes())
			mcopyWithLeftPad(Authpubkey[KEY384size:KEY384size*2], AuthECPubKey.Y.Bytes())
			//print_bytes_as_hex(Authpubkey, "--------------------------- P U B K E Y . B Y T E S ---------------------------")
			//hasher := sha512.New384()
			//hasher.Write(Authpubkey)
			//keyhash := hasher.Sum(nil)
			//copy(Keyhashblob[0:HASHsize], keyhash[0:HASHsize])
			copy(he[0x3:], Authpubkey)
			//print_bytes_as_hex(keyhash, "---------------------- P U B K E Y . B Y T E S . H A S H ----------------------")
	}
		var I_MCHP_Signature_string string ="REPAIR_FALLBACK_CONTAINER_REQUEST"
		r1 := make([]byte, len(I_MCHP_Signature_string))
		//var a byte
		copy(r1[0:],I_MCHP_Signature_string)
		//len :=0
		//if "" != cfg.IncrementRPMCContainerRequest.SHA384PrimaryContainer {
				//ECfwEntryidx := (uint)(ToTKEYS * HASHsize)
				ReadRawBytes, err := readAndReturnBinaryFile(cfg.RepairFallbackContainerRequest.SHA384PrimaryContainer)
				if err != nil {
					fmt.Printf("FW readAndReturnBinaryFile(%v) returned error %v \n", cfg.RepairFallbackContainerRequest.SHA384PrimaryContainer, err)
					return
				}
				//copy(he[0xEf:], ReadRawBytes)

		//}
		//fmt.Printf("R1 len(MCHP_Signature_string) " ,r1,len(MCHP_Signature_string))
		s := make([]byte, len(I_MCHP_Signature_string)+0x03+96+len(ReadRawBytes)+96)
		copy(s[0:],I_MCHP_Signature_string)
		copy(s[len(I_MCHP_Signature_string):],he[0x00:0x03+96])
		copy(s[len(I_MCHP_Signature_string)+0x03+96:],ReadRawBytes)

		outFileName = "contatenate_repair_container_raw_to_sign.bin"
		err = ioutil.WriteFile(formatted+"\\"+outFileName, s[0:len(I_MCHP_Signature_string)+0x03+96+len(ReadRawBytes)], 0644)
		if err != nil {
			fmt.Printf("Error write Output file  to file %v return error %v \n", outFileName, err)
			return
		}	
		f1 := cfg.RepairFallbackContainerRequest.PrivateKey
		f2 := cfg.RepairFallbackContainerRequest.PrivateKeyPass
		//f2 :="None"
		//mchp_sign_data = keyimg[cfg.Spi.RPMCFlashContainer:cfg.Spi.RPMCFlashContainer+0x22C+0x3C8]
		rh, sh, res := APTablesigningImage(f1, f2, s[0:len(I_MCHP_Signature_string)+0x03+96+len(ReadRawBytes)])//he[0x0:0x3+96])
		_ = res
		//Hashtable0AP0F0 = make([]byte, 96)
		len1 := len(I_MCHP_Signature_string)+0x03+96//+len(ReadRawBytes)
		mcopyWithLeftPad(s[len1:len1+48], rh.Bytes())
		mcopyWithLeftPad(s[len1+48:len1+96], sh.Bytes())
		len2 :=0x03+(96*2)
	outFileName_1 := "contatenate_repair_container_signature.bin"
	err = ioutil.WriteFile(formatted+"\\"+outFileName_1, s[len(I_MCHP_Signature_string):len(I_MCHP_Signature_string)+len2], 0644)
	if err != nil {
		fmt.Printf("Error write Output file  to file %v return error %v \n", outFileName_1, err)
		return
	}	
	if verify_flag_status ==1{
		fmt.Printf(" Generated Create  %s %s \n",outFileName,outFileName_1)
		fmt.Printf(" Signature and verification is success \n")
	}
/*
		rh, sh, res = APTablesigningImage(f1, f2, he[0x0:0x3+96])//he[0x0:0x3+96])
		_ = res
		//Hashtable0AP0F0 = make([]byte, 96)
		err = ioutil.WriteFile(formatted+"\\"+"repair_container_raw.bin", he[0x0:0x3+96], 0644)
		if err != nil {
			fmt.Printf("Error write Output file  to file %v return error %v \n", outFileName, err)
			return
		}			
		mcopyWithLeftPad(he[uint32(0x3+96):uint32(0x3+96)+48], rh.Bytes())
		mcopyWithLeftPad(he[uint32(0x3+96)+48:uint32(0x3+96)+96], sh.Bytes())
	//outFileName := "create_container_signature.bin"
	err = ioutil.WriteFile(formatted+"\\"+"repair_container_signature.bin", he, 0644)
	if err != nil {
		fmt.Printf("Error write Output file  to file %v return error %v \n", "increment_container_signature.bin", err)
		return
	}	
	if verify_flag_status ==1{
		fmt.Printf(" Generated Create Container repair_container_raw.bin and repair_container_signature.bin \n")
		fmt.Printf(" Signature and verification is success \n")
	}
	//fmt.Printf("Exit repair_rpmc_container ")	
*/
	return
}
func increment_rpmc_container() {
	var cfg Config
	err := gcfg.ReadFileInto(&cfg, cfgFileName)
	if err != nil {
		fmt.Printf("gcfg.ReadFileInto for config file %v returned error %v\n", cfgFileName, err)
		return
	}
	//fmt.Printf("Enter increment_rpmc_container ")
	he := make([]byte, 0x3+(96*2))
	_ =he
	Authpubkey := make([]byte, KEY384size*2)
	_ = Authpubkey
	he[0x0] = cfg.IncrementRPMCContainerRequest.ContainerNumber
	he[0x1] = cfg.IncrementRPMCContainerRequest.ContainerType
	he[0x2] = cfg.IncrementRPMCContainerRequest.SignaturePubKeySelect
	if cfg.IncrementRPMCContainerRequest.ContainerCommandsPub != "" {
			AuthECPubKey, err := readECPublicKeyFromCert(cfg.IncrementRPMCContainerRequest.ContainerCommandsPub)
			if err != nil {
				fmt.Printf("FW cfg.IncrementRPMCContainerRequest.ContainerCommandsPub from file %v returned error %v \n", cfg.IncrementRPMCContainerRequest.ContainerCommandsPub, err)
				return
			}
			mcopyWithLeftPad(Authpubkey[0:KEY384size], AuthECPubKey.X.Bytes())
			mcopyWithLeftPad(Authpubkey[KEY384size:KEY384size*2], AuthECPubKey.Y.Bytes())
			//print_bytes_as_hex(Authpubkey, "--------------------------- P U B K E Y . B Y T E S ---------------------------")
			//hasher := sha512.New384()
			//hasher.Write(Authpubkey)
			//keyhash := hasher.Sum(nil)
			//copy(Keyhashblob[0:HASHsize], keyhash[0:HASHsize])
			copy(he[0x3:], Authpubkey)
			//print_bytes_as_hex(keyhash, "---------------------- P U B K E Y . B Y T E S . H A S H ----------------------")
	}
	var I_MCHP_Signature_string string ="INCREMENT_RPMC_REQUEST"
	r1 := make([]byte, len(I_MCHP_Signature_string))
	//var a byte
	copy(r1[0:],I_MCHP_Signature_string)
	//len :=0
	//if "" != cfg.IncrementRPMCContainerRequest.SHA384PrimaryContainer {
			//ECfwEntryidx := (uint)(ToTKEYS * HASHsize)
			ReadRawBytes, err := readAndReturnBinaryFile(cfg.IncrementRPMCContainerRequest.SHA384PrimaryContainer)
			if err != nil {
				fmt.Printf("FW readAndReturnBinaryFile(%v) returned error %v \n", cfg.IncrementRPMCContainerRequest.SHA384PrimaryContainer, err)
				return
			}
			//copy(he[0xEf:], ReadRawBytes)

	//}
	//fmt.Printf("R1 len(MCHP_Signature_string) " ,r1,len(MCHP_Signature_string))
	s := make([]byte, len(I_MCHP_Signature_string)+0x03+96+len(ReadRawBytes)+96)
	copy(s[0:],I_MCHP_Signature_string)
	copy(s[len(I_MCHP_Signature_string):],he[0x00:0x03+96])
	copy(s[len(I_MCHP_Signature_string)+0x03+96:],ReadRawBytes)

	outFileName = "contatenate_increment_container_raw_to_sign.bin"
	err = ioutil.WriteFile(formatted+"\\"+outFileName, s[0:len(I_MCHP_Signature_string)+0x03+96+len(ReadRawBytes)], 0644)
	if err != nil {
		fmt.Printf("Error write Output file  to file %v return error %v \n", outFileName, err)
		return
	}
		f1 := cfg.IncrementRPMCContainerRequest.ContainerCommandsPrivate
		f2 := cfg.IncrementRPMCContainerRequest.ContainerCommandsPrivatePass
		//f2 :="None"
		//mchp_sign_data = keyimg[cfg.Spi.RPMCFlashContainer:cfg.Spi.RPMCFlashContainer+0x22C+0x3C8]
		rh, sh, res := APTablesigningImage(f1, f2, s[0:len(I_MCHP_Signature_string)+0x03+96+len(ReadRawBytes)])//he[0x0:0x3+96])
		_ = res
		//Hashtable0AP0F0 = make([]byte, 96)
		len_1 := len(I_MCHP_Signature_string)+0x03+96 //+ len(ReadRawBytes)
		mcopyWithLeftPad(s[len_1:len_1+48], rh.Bytes())
		mcopyWithLeftPad(s[len_1+48:len_1+96], sh.Bytes())
		len_2 := 0x03+(96*2) 
		//outFileName := "contatenate_increment_container_signature.bin"
		err = ioutil.WriteFile(formatted+"\\"+"contatenate_increment_container_signature.bin", s[len(I_MCHP_Signature_string):len(I_MCHP_Signature_string)+len_2], 0644)
		if err != nil {
			fmt.Printf("Error write Output file  to file %v return error %v \n", outFileName, err)
			return
		}	
		if verify_flag_status ==1{
			fmt.Printf(" Generated Create Container contatenate_increment_container_raw_to_sign.bin and contatenate_increment_container_signature.bin \n")
			fmt.Printf(" Signature and verification is success \n")
		}
		/*
		rh, sh, res = APTablesigningImage(f1, f2, he)//he[0x0:0x3+96])
		_ = res
		//Hashtable0AP0F0 = make([]byte, 96)
		err = ioutil.WriteFile(formatted+"\\"+"increment_container_raw.bin", he[0x0:0x3+96], 0644)
		if err != nil {
			fmt.Printf("Error write Output file  to file %v return error %v \n", outFileName, err)
			return
		}			
		mcopyWithLeftPad(he[uint32(0x3+96):uint32(0x3+96)+48], rh.Bytes())
		mcopyWithLeftPad(he[uint32(0x3+96)+48:uint32(0x3+96)+96], sh.Bytes())
		outFileName = "create_container_signature.bin"
		err = ioutil.WriteFile(formatted+"\\"+"increment_container_signature.bin", he, 0644)
		if err != nil {
			fmt.Printf("Error write Output file  to file %v return error %v \n", outFileName, err)
			return
		}	
		if verify_flag_status ==1{
			fmt.Printf(" Generated Create Container increment_container_raw.bin and increment_container_signature.bin \n")
			fmt.Printf(" Signature and verification is success \n")
		}
		*/
	//fmt.Printf("Exit increment_rpmc_container ")
}
func create_container() {
	var cfg Config
	err := gcfg.ReadFileInto(&cfg, cfgFileName)
	if err != nil {
		fmt.Printf("gcfg.ReadFileInto for config file %v returned error %v\n", cfgFileName, err)
		return
	}
	//fmt.Printf("Enter create_container ")
	he := make([]byte, 0x183+48+(96*2))
	_ =he
	//cfg.Spi.SPISizeMegabits 
	var SPISizeMegabits    uint
	SPISizeMegabits =16
	spiSizeBytes := SPISizeMegabits * (1024 * 1024) / 8
	_ = spiSizeBytes
	keyimg, err := getImagebuffer(spiSizeBytes, mergeFileName)
	_ = keyimg

	Authpubkey := make([]byte, KEY384size*2)
	_ = Authpubkey
	//cfg.CreateContainerRequest.ContainerNumber
	//copy(keyimg[0:], cfg.CreateContainerRequest.ContainerNumber)
	he[0x0] = cfg.CreateContainerRequest.ContainerNumber
	he[0x1] = cfg.CreateContainerRequest.ContainerType
	//ap_ba_ptr_0 := make([]byte, 4)
	//value := (cfg.CreateContainerRequest.SecureContainerContentLen)
	fillDword(0x02, he, cfg.CreateContainerRequest.SecureContainerContentLen)
	if cfg.CreateContainerRequest.ContainerCommandKey0 != "" {
			AuthECPubKey, err := readECPublicKeyFromCert(cfg.CreateContainerRequest.ContainerCommandKey0)
			if err != nil {
				fmt.Printf("FW cfg.CreateContainerRequest.ContainerCommandKey0 from file %v returned error %v \n", cfg.CreateContainerRequest.ContainerCommandKey0, err)
				return
			}
			mcopyWithLeftPad(Authpubkey[0:KEY384size], AuthECPubKey.X.Bytes())
			mcopyWithLeftPad(Authpubkey[KEY384size:KEY384size*2], AuthECPubKey.Y.Bytes())
			//print_bytes_as_hex(Authpubkey, "--------------------------- P U B K E Y . B Y T E S ---------------------------")
			hasher := sha512.New384()
			hasher.Write(Authpubkey)
			keyhash := hasher.Sum(nil)
			//copy(Keyhashblob[0:HASHsize], keyhash[0:HASHsize])
			copy(he[0x5:], keyhash[0:HASHsize])
			//print_bytes_as_hex(keyhash, "---------------------- P U B K E Y . B Y T E S . H A S H ----------------------")
	}
	if cfg.CreateContainerRequest.ContainerCommandKey1 != "" {
			AuthECPubKey, err := readECPublicKeyFromCert(cfg.CreateContainerRequest.ContainerCommandKey1)
			if err != nil {
				fmt.Printf("FW cfg.CreateContainerRequest.ContainerCommandKey1 from file %v returned error %v \n", cfg.CreateContainerRequest.ContainerCommandKey1, err)
				return
			}
			mcopyWithLeftPad(Authpubkey[0:KEY384size], AuthECPubKey.X.Bytes())
			mcopyWithLeftPad(Authpubkey[KEY384size:KEY384size*2], AuthECPubKey.Y.Bytes())
			//print_bytes_as_hex(Authpubkey, "--------------------------- P U B K E Y . B Y T E S ---------------------------")
			hasher := sha512.New384()
			hasher.Write(Authpubkey)
			keyhash := hasher.Sum(nil)
			//copy(Keyhashblob[0:HASHsize], keyhash[0:HASHsize])
			copy(he[0x35:], keyhash[0:HASHsize])
			//print_bytes_as_hex(keyhash, "---------------------- P U B K E Y . B Y T E S . H A S H ----------------------")
	}
	if cfg.CreateContainerRequest.ContainerCommandKey2 != "" {
			AuthECPubKey, err := readECPublicKeyFromCert(cfg.CreateContainerRequest.ContainerCommandKey2)
			if err != nil {
				fmt.Printf("FW cfg.CreateContainerRequest.ContainerCommandKey2 from file %v returned error %v \n", cfg.CreateContainerRequest.ContainerCommandKey2, err)
				return
			}
			mcopyWithLeftPad(Authpubkey[0:KEY384size], AuthECPubKey.X.Bytes())
			mcopyWithLeftPad(Authpubkey[KEY384size:KEY384size*2], AuthECPubKey.Y.Bytes())
			//print_bytes_as_hex(Authpubkey, "--------------------------- P U B K E Y . B Y T E S ---------------------------")
			hasher := sha512.New384()
			hasher.Write(Authpubkey)
			keyhash := hasher.Sum(nil)
			//copy(Keyhashblob[0:HASHsize], keyhash[0:HASHsize])
			copy(he[0x65:], keyhash[0:HASHsize])
			//print_bytes_as_hex(keyhash, "---------------------- P U B K E Y . B Y T E S . H A S H ----------------------")
	}
	if cfg.CreateContainerRequest.ContainerCommandKey3 != "" {
			AuthECPubKey, err := readECPublicKeyFromCert(cfg.CreateContainerRequest.ContainerCommandKey3)
			if err != nil {
				fmt.Printf("FW cfg.CreateContainerRequest.ContainerCommandKey3 from file %v returned error %v \n", cfg.CreateContainerRequest.ContainerCommandKey3, err)
				return
			}
			mcopyWithLeftPad(Authpubkey[0:KEY384size], AuthECPubKey.X.Bytes())
			mcopyWithLeftPad(Authpubkey[KEY384size:KEY384size*2], AuthECPubKey.Y.Bytes())
			//print_bytes_as_hex(Authpubkey, "--------------------------- P U B K E Y . B Y T E S ---------------------------")
			hasher := sha512.New384()
			hasher.Write(Authpubkey)
			keyhash := hasher.Sum(nil)
			//copy(Keyhashblob[0:HASHsize], keyhash[0:HASHsize])
			copy(he[0x95:], keyhash[0:HASHsize])
			//print_bytes_as_hex(keyhash, "---------------------- P U B K E Y . B Y T E S . H A S H ----------------------")
	}
	he[0xC5] = cfg.CreateContainerRequest.OwnerConfiguration
	aesTestR := new(big.Int)
	aesTestR.SetString(cfg.CreateContainerRequest.OwnerID, 0)
	kxb := aesTestR.Bytes()
	copy(he[0xC6:], kxb)
	he[0xD6] = cfg.CreateContainerRequest.KeyRevocation

	//fill16word(0xD7, he, cfg.RPMCContainerContent.RollbackProtection)
	aesTestR = new(big.Int)
	aesTestR.SetString(cfg.CreateContainerRequest.RollbackProtection, 0)
	kxb = aesTestR.Bytes()
	copy(he[0xD7:], kxb)

	fillDword(0xE7, he, cfg.CreateContainerRequest.TAG0ImageHeaderBaseAddress)
	fillDword(0xEB, he, cfg.CreateContainerRequest.TAG1ImageHeaderBaseAddress)

	if "" != cfg.CreateContainerRequest.ECDHprivatekey {
			//ECfwEntryidx := (uint)(ToTKEYS * HASHsize)
			ReadRawBytes, err := readAndReturnBinaryFile(cfg.CreateContainerRequest.ECDHprivatekey)
			if err != nil {
				fmt.Printf("FW readAndReturnBinaryFile(%v) returned error %v \n", cfg.RPMCContainerContent.ECDHprivatekey, err)
				return
			}
			copy(he[0xEf:], ReadRawBytes)
	}
	if "" != cfg.CreateContainerRequest.ECDHPublicKey2 {
			//ECfwEntryidx := (uint)(ToTKEYS * HASHsize)
			ReadRawBytes, err := readAndReturnBinaryFile(cfg.CreateContainerRequest.ECDHPublicKey2)
			if err != nil {
				fmt.Printf("FW readAndReturnBinaryFile(%v) returned error %v \n", cfg.RPMCContainerContent.ECDHPublicKey2, err)
				return
			}
			copy(he[0x11F:], ReadRawBytes)
	}
	if "" != cfg.CreateContainerRequest.SHA384KHB {
			//ECfwEntryidx := (uint)(ToTKEYS * HASHsize)
			ReadRawBytes, err := readAndReturnBinaryFile(cfg.CreateContainerRequest.SHA384KHB)
			if err != nil {
				fmt.Printf("FW readAndReturnBinaryFile(%v) returned error %v \n", cfg.RPMCContainerContent.SHA384KHB, err)
				return
			}
			copy(he[0x14F:], ReadRawBytes)
	}
	he[0x17F] = cfg.CreateContainerRequest.OwnerDebugOptions
	fill16word(0x180, he, cfg.CreateContainerRequest.OwnerPlatformID)
	he[0x182] = cfg.CreateContainerRequest.SecurityFeatures
	if "" != cfg.CreateContainerRequest.SHA384Platk {
			//ECfwEntryidx := (uint)(ToTKEYS * HASHsize)
			ReadRawBytes, err := readAndReturnBinaryFile(cfg.CreateContainerRequest.SHA384Platk)
			if err != nil {
				fmt.Printf("FW cfg.CreateContainerRequest.SHA384Platk(%v) returned error %v \n", cfg.CreateContainerRequest.SHA384Platk, err)
				return
			}
			copy(he[0x183:], ReadRawBytes)
	}
	if cfg.CreateContainerRequest.OwnerCreationPubKey != "" {
			AuthECPubKey, err := readECPublicKeyFromCert(cfg.CreateContainerRequest.OwnerCreationPubKey)
			if err != nil {
				fmt.Printf("FW cfg.CreateContainerRequest.OwnerCreationPubKey from file %v returned error %v \n", cfg.CreateContainerRequest.OwnerCreationPubKey, err)
				return
			}
			mcopyWithLeftPad(Authpubkey[0:KEY384size], AuthECPubKey.X.Bytes())
			mcopyWithLeftPad(Authpubkey[KEY384size:KEY384size*2], AuthECPubKey.Y.Bytes())
			//print_bytes_as_hex(Authpubkey, "--------------------------- P U B K E Y . B Y T E S ---------------------------")
			//hasher := sha512.New384()
			//hasher.Write(Authpubkey)
			//keyhash := hasher.Sum(nil)
			//copy(Keyhashblob[0:HASHsize], keyhash[0:HASHsize])
			copy(he[0x183+48:], Authpubkey)
			//print_bytes_as_hex(keyhash, "---------------------- P U B K E Y . B Y T E S . H A S H ----------------------")
	}
	r1 := make([]byte, len(MCHP_Signature_string))
	//var a byte
	copy(r1[0:],MCHP_Signature_string)
	//fmt.Printf("R1 len(MCHP_Signature_string) " ,r1,len(MCHP_Signature_string))
	s := make([]byte, len(MCHP_Signature_string)+0x183+48+(96*2))
	copy(s[0:],MCHP_Signature_string)
	copy(s[len(MCHP_Signature_string):],he[0x00:0x0+0x183+48+(96)])
	outFileName = "contatenate_create_container_raw_to_sign.bin"
	err = ioutil.WriteFile(formatted+"\\"+outFileName,  s[0:len(MCHP_Signature_string)+0x183+48+(96*1)], 0644)
	if err != nil {
		fmt.Printf("Error write Output file  to file %v return error %v \n", outFileName, err)
		return
	}	
		f1 := cfg.CreateContainerRequest.OwnerCreationPrivateKey
		f2 := cfg.CreateContainerRequest.OwnerCreationPrivateKeyPass
		rh, sh, res := APTablesigningImage(f1, f2,  s[0:len(MCHP_Signature_string)+0x183+48+96])//he[0x00:0x0+0x183+48+96])
		_ = res
		len_1 := len(MCHP_Signature_string)+0x183+48+(96*1)
		mcopyWithLeftPad(s[len_1:len_1+48], rh.Bytes())
		mcopyWithLeftPad(s[len_1+48:len_1+96], sh.Bytes())
		len_2 :=0x183+48+(96*2)
		fmt.Printf("len_1 %x len_2 %x %x ",len_1,len_2,len(MCHP_Signature_string)+len_2)
		outFileName := "contatenate_create_container_signature.bin"
		err = ioutil.WriteFile(formatted+"\\"+outFileName, s[len(MCHP_Signature_string):len(MCHP_Signature_string)+len_2], 0644)
		if err != nil {
			fmt.Printf("Error write Output file  to file %v return error %v \n", outFileName, err)
			return
		}	
		if verify_flag_status ==1{
			fmt.Printf(" Generated Create Container contatenate_create_container_raw_to_sign.bin and contatenate_create_container_signature.bin \n")
			fmt.Printf(" Signature and verification is success \n")
		}
		//f2 :="None"
		//mchp_sign_data = keyimg[cfg.Spi.RPMCFlashContainer:cfg.Spi.RPMCFlashContainer+0x22C+0x3C8]


}

var formatted string
var abc = []byte{byte(0x61), byte(0x62), byte(0x63)}
var abc_sha256 = []byte{byte(0xba), byte(0x78), byte(0x16), byte(0xbf),
	byte(0x8f), byte(0x01), byte(0xcf), byte(0xea), byte(0x41), byte(0x41), byte(0x40), byte(0xde),
	byte(0x5d), byte(0xae), byte(0x22), byte(0x23), byte(0xb0), byte(0x03), byte(0x61), byte(0xa3),
	byte(0x96), byte(0x17), byte(0x7a), byte(0x9c), byte(0xb4), byte(0x10), byte(0xff), byte(0x61),
	byte(0xf2), byte(0x00), byte(0x15), byte(0xad)}

/* !!!! Go libraries do not support parsing PKCS#12 format files !!!!
 * Go PEM module can handle OpenSSL SSLeay encrypted PEM files.
 * Go x509 module can handle OpenSSL certificate PEM files.
 * Private EC Key pair will be in OpenSSL SSLeay AES-256-CBC encrypted PEM files
 * Corresponding Public Key will be a PEM encoded certificate (no encryption)
 *
 */
func main() {

	//flag.Parse()
	fmt.Printf("\n*******************************************************************************************\n")
	fmt.Printf(" Enter into  the RPMC Flash Container Generatation tool \n")
	fmt.Printf(" \n GLACIER_RPMC_Flash_Container tool version  %v\n ==================================================\n", program_version)
	//chipstr = "GLACIER_KEY_HASH_REVB"
	//fmt.Printf(" Chip String        = %v\n", chipstr)
	fmt.Printf(" Config File Name   = %v\n", cfgFileName)


    //argsWithProg := os.Args
    //_ =argsWithProg
    //argsWithoutProg := os.Args[1:]
	/*
	t := time.Now()
	time_val := fmt.Sprintf("%04d_%02d%02d%02d%02d",
        t.Year(), t.Month(), t.Day(),
        t.Hour(), t.Minute())
	formatted = "rpmc_"+time_val 
	_, err := os.Stat(formatted)
 
	if os.IsNotExist(err) {
		errDir := os.MkdirAll(formatted, 0755)
		if errDir != nil {
			log.Fatal(err)
		}
 
	}
	*/
	
    var command_reg string
    _ =command_reg
    var cfg Config
    if len(os.Args) > 1{
	    if os.Args[1]== "-i"{
				cfgFileName = os.Args[2] 
				
				err := gcfg.ReadFileInto(&cfg, cfgFileName)
				if err != nil {
					fmt.Printf("gcfg.ReadFileInto for config file %v returned error %v\n", cfgFileName, err)
					return
					}
			}
			formatted = cfg.OutPutDirectory.OutPutDirectory
			_, err := os.Stat(formatted)
			fmt.Printf(" Generated the RPMC binaries directory=%v\n",formatted)
			if os.IsNotExist(err) {
			errDir := os.MkdirAll(formatted, 0755)
			if errDir != nil {
				log.Fatal(err)
			}
	 
		}
	    if os.Args[3]== "-c"{
				command_reg = (os.Args[4])
				if command_reg =="1"{
					create_container()
				}
				if command_reg =="5"{
					increment_rpmc_container()
					}
				if command_reg =="7"{
					update_rpmc_container()
					update_rpmc_container_subcommand_transfer()
					}
				if command_reg =="3"{
					repair_rpmc_container()
					}
				if command_reg =="F" || command_reg =="f"{
					enable_unrestricted_rpmc_container()
					}
				if command_reg =="1F" || command_reg =="1f"{
					ota_pub_rpmc_container()
					}
				if command_reg =="2F" || command_reg =="2f"{
					modify_rpmc_container()
					}
				rpmc_container()
			}
	}else{
		//fmt.Printf("else")
		//var cfg Config
		err := gcfg.ReadFileInto(&cfg, cfgFileName)
		if err != nil {
			fmt.Printf("gcfg.ReadFileInto for config file %v returned error =%v\n", cfgFileName, err)
			return
		}
			formatted = cfg.OutPutDirectory.OutPutDirectory
			fmt.Printf(" Generated the RPMC binaries directory =%v\n",formatted)
			if os.IsNotExist(err) {
			errDir := os.MkdirAll(formatted, 0755)
			if errDir != nil {
				log.Fatal(err)
			}
	 
		}	
		create_container()
		increment_rpmc_container()
		repair_rpmc_container()
		update_rpmc_container()
		update_rpmc_container_subcommand_transfer()
		rpmc_container()
		enable_unrestricted_rpmc_container()
		ota_pub_rpmc_container()
		modify_rpmc_container()	
	}
    //arg := os.Args[3]
	fmt.Printf("\n Exit the RPMC Flash Container tool \n")
	fmt.Printf("\n*******************************************************************************************\n")
	return

	
//commented by me	
/*
	increment_rpmc_container()
	repair_rpmc_container()
	update_rpmc_container()
	rpmc_container()
	enable_unrestricted_rpmc_container()
	ota_pub_rpmc_container()
	modify_rpmc_container()
*/
///

//	fmt.Printf("Length of string %d \n",len(MCHP_Signature_string))
	//byte_or(r1, v1, uint8(r))
	//r1 := make([]byte, len(MCHP_Signature_string))
	//var a byte
	//copy(r1[0:],MCHP_Signature_string)
	//fmt.Printf("R1 " ,r1)
	//outFileName := "r.bin"
	//err = ioutil.WriteFile(formatted+"\\"+outFileName, r1, 0644)
	//if err != nil {
//		fmt.Printf("Error write Output file  to file %v return error %v \n", outFileName, err)
		//return
//	}	
//	err = binary.Read(bytes.NewReader(r1[0:], binary.BigEndian, &a)
//	r := int(a)
//	_ =r
//	fmt.Printf("r valie %x ", r1,r)



	
}
