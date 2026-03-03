package envio

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

type Authorization struct {
	ChainId         string
	ContractAddress string
	Nonce           string
	Authority       string
}

// rawAuthorization holds the intermediate parsed values from the binary format
// before crypto recovery is performed.
type rawAuthorization struct {
	chainIdStr   string
	chainId      uint64
	addressStr   string
	addressBytes []byte
	nonceStr     string
	nonce        uint64
	yParityStr   string
	v            []byte
	rStr         string
	r            []byte
	sStr         string
	s            []byte
}

// readLengthPrefixedField reads an 8-byte little-endian length prefix followed
// by that many bytes of payload from data starting at *offset. It returns the
// raw payload bytes and advances *offset past them. Returns an error if the
// data is too short at any point.
func readLengthPrefixedField(data []byte, offset *uint64, fieldName string) ([]byte, error) {
	if uint64(len(data)) < *offset+8 {
		return nil, fmt.Errorf("truncated %s: need 8 bytes for length at offset %d, have %d", fieldName, *offset, len(data))
	}
	fieldLen := binary.LittleEndian.Uint64(data[*offset : *offset+8])
	*offset += 8

	if uint64(len(data)) < *offset+fieldLen {
		return nil, fmt.Errorf("truncated %s: need %d bytes at offset %d, have %d", fieldName, fieldLen, *offset, len(data))
	}
	value := data[*offset : *offset+fieldLen]
	*offset += fieldLen
	return value, nil
}

// decodeHexField strips an optional "0x" prefix from a hex string, left-pads
// to even length, and decodes the result. fieldName is used in error messages.
func decodeHexField(raw string, fieldName string) ([]byte, error) {
	h := strings.TrimPrefix(raw, "0x")
	if len(h)%2 != 0 {
		h = "0" + h
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("invalid %s hex: %v", fieldName, err)
	}
	return b, nil
}

// parseRawAuthorization reads one authorization entry from the binary-encoded
// data starting at *offset. It performs only binary parsing / hex decoding —
// no cryptographic operations.
func parseRawAuthorization(data []byte, offset *uint64) (rawAuthorization, error) {
	var raw rawAuthorization

	// --- chain ID ---
	chainIdBytes, err := readLengthPrefixedField(data, offset, "chainId")
	if err != nil {
		return raw, err
	}
	raw.chainIdStr = string(chainIdBytes)
	raw.chainId, err = strconv.ParseUint(strings.TrimPrefix(raw.chainIdStr, "0x"), 16, 64)
	if err != nil {
		return raw, fmt.Errorf("invalid chain ID %q: %v", raw.chainIdStr, err)
	}

	// --- contract address ---
	addrBytes, err := readLengthPrefixedField(data, offset, "contractAddress")
	if err != nil {
		return raw, err
	}
	raw.addressStr = string(addrBytes)
	raw.addressBytes, err = hex.DecodeString(strings.TrimPrefix(raw.addressStr, "0x"))
	if err != nil {
		return raw, fmt.Errorf("invalid contract address %q: %v", raw.addressStr, err)
	}

	// --- nonce ---
	nonceBytes, err := readLengthPrefixedField(data, offset, "nonce")
	if err != nil {
		return raw, err
	}
	raw.nonceStr = string(nonceBytes)
	raw.nonce, err = strconv.ParseUint(strings.TrimPrefix(raw.nonceStr, "0x"), 16, 64)
	if err != nil {
		return raw, fmt.Errorf("invalid nonce %q: %v", raw.nonceStr, err)
	}

	// --- yParity (v) ---
	yParityBytes, err := readLengthPrefixedField(data, offset, "yParity")
	if err != nil {
		return raw, err
	}
	raw.yParityStr = string(yParityBytes)
	raw.v, err = decodeHexField(raw.yParityStr, "yParity")
	if err != nil {
		return raw, err
	}

	// --- r ---
	rBytes, err := readLengthPrefixedField(data, offset, "r")
	if err != nil {
		return raw, err
	}
	raw.rStr = string(rBytes)
	raw.r, err = decodeHexField(raw.rStr, "r")
	if err != nil {
		return raw, err
	}

	// --- s ---
	sBytes, err := readLengthPrefixedField(data, offset, "s")
	if err != nil {
		return raw, err
	}
	raw.sStr = string(sBytes)
	raw.s, err = decodeHexField(raw.sStr, "s")
	if err != nil {
		return raw, err
	}

	return raw, nil
}

// recoverAuthority RLP-encodes the authorization fields, hashes them with the
// EIP-7702 magic byte (0x05), recovers the signer's public key from the
// signature, and returns (hash, authority address, error).
func recoverAuthority(logger *slog.Logger, chainId uint64, addr []byte, nonce uint64, v, r, s []byte) (string, string, error) {
	encoded, err := rlp.EncodeToBytes(struct {
		ChainId         uint64
		ContractAddress []byte
		Nonce           uint64
	}{
		ChainId:         chainId,
		ContractAddress: addr,
		Nonce:           nonce,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to RLP-encode authorization: %v", err)
	}

	hash := crypto.Keccak256Hash(append([]byte{0x05}, encoded...))

	// Build the 65-byte [R || S || V] signature expected by Ecrecover.
	if len(r) > 32 || len(s) > 32 || len(v) == 0 {
		return "", "", fmt.Errorf("invalid signature component lengths: r=%d s=%d v=%d", len(r), len(s), len(v))
	}
	sig := make([]byte, 65)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = v[len(v)-1]

	recoveredPubKey, err := crypto.Ecrecover(hash.Bytes(), sig)
	if err != nil {
		logger.Error("failed to recover public key for authorization",
			"hash", hash.Hex(),
			"r", "0x"+hex.EncodeToString(r),
			"s", "0x"+hex.EncodeToString(s),
			"v", "0x"+hex.EncodeToString(v),
			"signature", hex.EncodeToString(sig),
		)
		return "", "", fmt.Errorf("failed to recover public key: %v", err)
	}

	pubKey, err := crypto.UnmarshalPubkey(recoveredPubKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to unmarshal public key: %v", err)
	}

	authority := "0x" + hex.EncodeToString(crypto.PubkeyToAddress(*pubKey).Bytes())
	return hash.Hex(), authority, nil
}

// DecodeAuthorizationList decodes the binary-encoded authorization list
// produced by the Envio indexer (which has a non-standard format).
func DecodeAuthorizationList(logger *slog.Logger, authList string) ([]Authorization, error) {
	authList = strings.TrimPrefix(authList, "0x")

	decodedBytes, err := hex.DecodeString(authList)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %v", err)
	}
	if len(decodedBytes) < 8 {
		return nil, fmt.Errorf("invalid authorization list: expected at least 8 bytes, got %d", len(decodedBytes))
	}

	listLength := binary.LittleEndian.Uint64(decodedBytes[:8])
	result := make([]Authorization, 0, listLength)

	offset := uint64(8)
	for i := uint64(0); i < listLength; i++ {
		raw, err := parseRawAuthorization(decodedBytes, &offset)
		if err != nil {
			return nil, fmt.Errorf("authorization %d: %w", i, err)
		}

		_, authority, err := recoverAuthority(logger, raw.chainId, raw.addressBytes, raw.nonce, raw.v, raw.r, raw.s)
		if err != nil {
			return nil, fmt.Errorf("authorization %d: %w", i, err)
		}

		result = append(result, Authorization{
			ChainId:         raw.chainIdStr,
			ContractAddress: raw.addressStr,
			Nonce:           raw.nonceStr,
			Authority:       authority,
		})
	}

	return result, nil
}
