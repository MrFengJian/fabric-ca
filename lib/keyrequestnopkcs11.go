// +build !pkcs11

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import (
	"github.com/hyperledger/fabric-ca/api"
	"strings"
)

// GetKeyRequest constructs and returns api.BasicKeyRequest object based on the bccsp
// configuration options
func GetKeyRequest(cfg *CAConfig) *api.BasicKeyRequest {
	if cfg.CSP.SwOpts != nil {
		// 按设置，选择默认私钥请求算法
		if strings.ToUpper(cfg.CSP.ProviderName) == "GM" {
			return &api.BasicKeyRequest{Algo: "sm2", Size: cfg.CSP.SwOpts.SecLevel}
		}
		return &api.BasicKeyRequest{Algo: "ecdsa", Size: cfg.CSP.SwOpts.SecLevel}
	}
	return api.NewBasicKeyRequest()
}
