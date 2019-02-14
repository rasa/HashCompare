/*
 * Minio Cloud Storage, (C) 2018 Minio, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main_test

/*
test with:
$ go test -bench=.
*/

import (
	// https://en.wikipedia.org/wiki/List_of_hash_functions#Cyclic_redundancy_checks
	"hash/crc32"
	"hash/crc64"
	// https://en.wikipedia.org/wiki/List_of_hash_functions#Checksums
	"hash/adler32"
	// https://en.wikipedia.org/wiki/List_of_hash_functions#Non-cryptographic_hash_functions
	"hash/fnv"
	cespare_xxhash "github.com/cespare/xxhash"
	shivakar_xxhash "github.com/shivakar/xxhash"
	// https://en.wikipedia.org/wiki/List_of_hash_functions#Keyed_cryptographic_hash_functions
	"github.com/minio/blake2b-simd"
	// "github.com/aead/poly1305" // doesn't implement BlockSize()
	"github.com/aead/siphash"
	// "github.com/minio/highwayhash"
	// https://en.wikipedia.org/wiki/List_of_hash_functions#Unkeyed_cryptographic_hash_functions

	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"github.com/minio/highwayhash"
	sha256Avx512 "github.com/minio/sha256-simd"
	/* on windows:
	golang.org/x/crypto/blake2b.supportsAVX2: relocation target runtime.support_avx2 not defined
	golang.org/x/crypto/blake2b.supportsAVX: relocation target runtime.support_avx not defined
	"golang.org/x/crypto/blake2b"
	*/
	"hash"
	"testing"
)

const size = 5 * 1024 * 1024

func benchmarkHashWithKey(b *testing.B, hash func(key []byte) (hash.Hash, error)) {
	var key [32]byte
	data := make([]byte, size)
	rand.Read(data)

	b.SetBytes(size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h, _ := hash(key[:])
		h.Write(data)
		h.Sum(nil)
	}
}

func benchmarkHashWithKey16(b *testing.B, hash func(key []byte) (hash.Hash, error)) {
	var key [16]byte
	data := make([]byte, size)
	rand.Read(data)

	b.SetBytes(size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h, _ := hash(key[:])
		h.Write(data)
		h.Sum(nil)
	}
}

func benchmarkHash(b *testing.B, hash func() hash.Hash) {
	data := make([]byte, size)
	rand.Read(data)

	b.SetBytes(size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := hash()
		h.Write(data)
		h.Sum(nil)
	}
}

func BenchmarkHighwayHash256(b *testing.B) {
	benchmarkHashWithKey(b, highwayhash.New)
}

func BenchmarkHighwayHash128(b *testing.B) {
	benchmarkHashWithKey(b, highwayhash.New128)
}

func highwayhashNew64(key []byte) (hash.Hash, error) {
	return highwayhash.New64(key)
}

func BenchmarkHighwayHash64(b *testing.B) {
	benchmarkHashWithKey(b, highwayhashNew64)
}

func BenchmarkSHA256_AVX512(b *testing.B) {
	b.Skip("panics on windows")
	benchmarkAvx512(b, size)
}

/*
// on windows:
golang.org/x/crypto/blake2b.supportsAVX2: relocation target runtime.support_avx2 not defined
golang.org/x/crypto/blake2b.supportsAVX: relocation target runtime.support_avx not defined

func BenchmarkBlake2b512(b *testing.B) {
	benchmarkHashWithKey(b, blake2b.New512)
}

func BenchmarkBlake2b256(b *testing.B) {
	benchmarkHashWithKey(b, blake2b.New256)
}
*/

func BenchmarkSHA1(b *testing.B) {
	benchmarkHash(b, sha1.New)
}

func BenchmarkMD5(b *testing.B) {
	benchmarkHash(b, md5.New)
}

func BenchmarkSHA512(b *testing.B) {
	benchmarkHash(b, sha512.New)
}

func BenchmarkSHA256(b *testing.B) {
	benchmarkHash(b, sha256.New)
}

// AVX512 code below

func benchmarkAvx512SingleCore(h512 []hash.Hash, body []byte) {

	for i := 0; i < len(h512); i++ {
		h512[i].Write(body)
	}
	for i := 0; i < len(h512); i++ {
		_ = h512[i].Sum([]byte{})
	}
}

func benchmarkAvx512(b *testing.B, size int) {

	server := sha256Avx512.NewAvx512Server()

	const tests = 16
	body := make([]byte, size)
	rand.Read(body)

	b.SetBytes(int64(len(body) * tests))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		h512 := make([]hash.Hash, tests)
		for i := 0; i < tests; i++ {
			h512[i] = sha256Avx512.NewAvx512(server)
		}

		benchmarkAvx512SingleCore(h512, body)
	}
}

func crc32New() hash.Hash {
	return crc32.New(crc32.MakeTable(crc32.IEEE)) // or Castagnoli or Koopman
}

func BenchmarkCRC32(b *testing.B) {
	benchmarkHash(b, crc32New)
}

func crc64New() hash.Hash {
	return crc64.New(crc64.MakeTable(crc64.ISO)) // or ECMA
}

func BenchmarkCRC64(b *testing.B) {
	benchmarkHash(b, crc64New)
}

func adler32New() hash.Hash {
	return adler32.New()
}

func BenchmarkAdler32(b *testing.B) {
	benchmarkHash(b, adler32New)
}

func fnvNew32() hash.Hash {
	return fnv.New32()
}

func BenchmarkFNV32(b *testing.B) {
	benchmarkHash(b, fnvNew32)
}

func fnvNew64() hash.Hash {
	return fnv.New64()
}

func BenchmarkFNV64(b *testing.B) {
	benchmarkHash(b, fnvNew64)
}

func fnvNew128() hash.Hash {
	return fnv.New128()
}

func BenchmarkFNV128(b *testing.B) {
	benchmarkHash(b, fnvNew128)
}

func cespareXxhashNew() hash.Hash {
	return cespare_xxhash.New()
}

func BenchmarkCespareXxhash(b *testing.B) {
	benchmarkHash(b, cespareXxhashNew)
}

func shivakarXxhashNew() hash.Hash {
	return shivakar_xxhash.New()
}

func BenchmarkShivakarXxhash(b *testing.B) {
	benchmarkHash(b, shivakarXxhashNew)
}

/*
func BenchmarBlake2b256(b *testing.B) {
	benchmarkHash(b, blake2b.New256)
}

func BenchmarBlake2b512(b *testing.B) {
	benchmarkHash(b, blake2b.New512)
}
*/

/*
// doesn't implement BlockSize()
func poly1305New() hash.Hash {
	return &poly1305.New()
}

func BenchmarkPoly1305(b *testing.B) {
	benchmarkHashWithKey(b, poly1305New)
}
*/

func siphashNew64(key []byte) (hash.Hash, error) {
	return siphash.New64(key)
}

func BenchmarkSiphash64(b *testing.B) {
	benchmarkHashWithKey16(b, siphashNew64)
}

func siphashNew128(key []byte) (hash.Hash, error) {
	return siphash.New128(key)
}

func BenchmarkSiphash128(b *testing.B) {
	benchmarkHashWithKey16(b, siphashNew128)
}

// 	"github.com/minio/blake2b-simd"
func BenchmarkBlake2b512(b *testing.B) {
	benchmarkHash(b, blake2b.New512)
}

func BenchmarkBlake2b256(b *testing.B) {
	benchmarkHash(b, blake2b.New256)
}
