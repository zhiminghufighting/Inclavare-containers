package config

import (

)

type SigStruct struct {
	Header         [16]byte  `struct:"[16]byte"`
	Vendor         uint32    `struct:"uint32,little"`
	BuildYear      uint16    `struct:"uint16,little"`
	BuildMonth     uint8     `struct:"uint8"`
	BuildDay       uint8     `struct:"uint8"`
	Header2        [16]byte  `struct:"[16]byte"`
	SwDefined      uint32    `struct:"uint32,little"`
	_              [84]byte  `struct:"[84]byte"`
	Modulus        [384]byte `struct:"[384]byte"`
	Exponent       uint32    `struct:"uint32,little"`
	Signature      [384]byte `struct:"[384]byte"`
	MiscSelect     uint32    `struct:"uint32,little"`
	MiscMask       uint32    `struct:"uint32,little"`
	_              [4]byte   `struct:"[4]byte"`
	ISVFamilyId    [16]byte  `struct:"[16]byte"`
	Attributes     [16]byte  `struct:"[16]byte"`
	AttributesMask [16]byte  `struct:"[16]byte"`
	EnclaveHash    [32]byte  `struct:"[32]byte"`
	_              [16]byte  `struct:"[16]byte"`
	ISVExtProdId   [16]byte  `struct:"[16]byte"`
	ISVProdId      uint16    `struct:"uint16,little"`
	ISVSvn         uint16    `struct:"uint16,little"`
	_              [12]byte  `struct:"[12]byte"`
	Q1             [384]byte `struct:"[384]byte"`
	Q2             [384]byte `struct:"[384]byte"`
}



type Einittoken struct {
	Valid              uint32   `struct:"uint32,little"`
	_                  [44]byte `struct:"[44]byte"`
	Attributes         [16]byte `struct:"[16]byte"`
	MrEnclave          [32]byte `struct:"[32]byte"`
	_                  [32]byte `struct:"[32]byte"`
	MrSigner           [32]byte `struct:"[32]byte"`
	_                  [32]byte `struct:"[32]byte"`
	CpuSvnLe           [16]byte `struct:"[16]byte"`
	ISVProdIdLe        uint16   `struct:"uint16"`
	ISVSvnLe           uint16   `struct:"uint16"`
	_                  [24]byte `struct:"[24]byte"`
	MaskedMiscSelectLe uint32   `struct:"uint32"`
	MaskedAttributesLe [16]byte `struct:"[16]byte"`
	KeyId              [32]byte `struct:"[32]byte"`
	Mac                [16]byte `struct:"[16]byte"`
}



type Targetinfo struct {
	Measurement   [32]byte  `struct:"[32]byte"`
	Attributes    [16]byte  `struct:"[16]byte"`
	CetAttributes uint8     `struct:"uint8"`
	_             uint8     `struct:"uint8"`
	ConfigSvn     uint16    `struct:"uint16"`
	MiscSelect    uint32    `struct:"uint32"`
	_             [8]byte   `struct:"[8]byte"`
	ConfigId      [64]byte  `struct:"[64]byte"`
	_             [384]byte `struct:"[384]byte"`
}


type QuoteBody struct {
	Version       uint16   `struct:"uint16"`
	SignatureType uint16   `struct:"uint16"`
	Gid           uint32   `struct:"uint32"`
	ISVSvnQe      uint16   `struct:"uint16"`
	ISVSvnPce     uint16   `struct:"uint16"`
	_             [4]byte  `struct:"[4]byte"`
	Basename      [32]byte `struct:"[32]byte"`
}

type Report struct {
	ReportBody
	Keyid [32]byte `struct:"[32]byte"`
	Mac   [16]byte `struct:"[16]byte"`
}



type ReportBody struct {
	CpuSvn       [16]byte `struct:"[16]byte"`
	MiscSelect   uint32   `struct:"uint32"`
	_            [12]byte `struct:"[12]byte"`
	IsvExtProdId [16]byte `struct:"[16]byte"`
	Attributes   [16]byte `struct:"[16]byte"`
	MrEnclave    [32]byte `struct:"[32]byte"`
	_            [32]byte `struct:"[32]byte"`
	MrSigner     [32]byte `struct:"[32]byte"`
	_            [32]byte `struct:"[32]byte"`
	ConfigId     [64]byte `struct:"[64]byte"`
	IsvProdId    uint16   `struct:"uint16"`
	IsvSvn       uint16   `struct:"uint16"`
	ConfigSvn    uint16   `struct:"uint16"`
	_            [42]byte `struct:"[42]byte"`
	IsvFamilyId  [16]byte `struct:"[16]byte"`
	ReportData   [64]byte `struct:"[64]byte"`
}


type Quote struct {
	QuoteBody
	ReportBody
	SigLen uint32 `struct:"uint32"`
}

type PodInfo struct{
    podid                   string 
    apiVersion              string 
}

type ContainerInfo struct{
    containerid             string 
}

type PoolInfo struct{
    poolid                  string 
    pooltype                string 
    enclaveinfo             EnclaveInfo 
    enclavetype             string 
}

type EnclaveInfo map[string]interface{}

type SgxEncalve struct{
    encalvegid              string 
    sigstruct               SigStruct 
    targetInfo              Targetinfo 
    einittoken              Einittoken 
    report                  Report 
    libos                   LibOS                   
}

type LibOS struct{
    ostype                  string 
    version                 string 
    githuburl               string 
    branch                  string 
    commitid                string 
    buildconfig             string 
}

type ShelterConfig struct{
    version                 string 
    podInfo                 PodInfo 
    containerinfo           ContainerInfo 
    poolinfo                PoolInfo 
    enclaveinfo             EnclaveInfo 
}