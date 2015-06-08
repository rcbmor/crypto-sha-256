/**
 * Setup Crypto++
 * 
$ apt-cache pkgnames | grep -i crypto++
libcrypto++9-dbg
libcrypto++-dev
libcrypto++-doc
libcrypto++9
libcrypto++-utils

$ sudo apt-get install -y libcrypto++9 libcrypto++9-dbg libcrypto++-dev
...

$ ldconfig -p | grep crypto++
        libcrypto++.so.9 (libc6,x86-64) => /usr/lib/libcrypto++.so.9
        libcrypto++.so (libc6,x86-64) => /usr/lib/libcrypto++.so
        
$ g++ hash.cpp -lcryptopp -o hash
$ ./hash
8E423302209494D266A7AB7E1A58CA8502C9BFDAA31DFBA70AA8805D20C087BD

 * 
 */
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <iostream>
#include <fstream>

#define ARRAY_LENGTH(array) (sizeof(array)/sizeof((array)[0]))
#define BLOCK 1024
#define DIGSIZE CryptoPP::SHA256::DIGESTSIZE

int raw_to_hex(byte *digest, size_t len, std::string &output)
{
    CryptoPP::HexEncoder encoder;
    encoder.Attach( new CryptoPP::StringSink( output ) );
    encoder.Put( digest, len);
    encoder.MessageEnd();
    return 0;
}

int hash(byte *input, size_t len, byte *digest)
{
    CryptoPP::SHA256 hash;
    hash.CalculateDigest( digest, input, len );
}

int file_read_block(std::ifstream &infile, size_t pos, size_t len, byte *buffer)
{
    infile.seekg (pos);
    if (!infile.read ((char*)buffer, len)) {
        std::cout << " read failed" << std::endl;
        return -1;
    }
    return 0;
}

int hash_file_block(std::ifstream &infile, size_t pos, size_t len, byte *digest)
{
    byte buffer[BLOCK+DIGSIZE];
    if(len>BLOCK) exit(-1);

    file_read_block(infile, pos, len, buffer);
    hash(buffer, len, digest);
    return 0;
}

int hash_file_block_concat(std::ifstream &infile, size_t pos, size_t len, byte *digest)
{
    byte buffer[BLOCK+DIGSIZE];
    if(len>BLOCK) exit(-1);

    file_read_block(infile, pos, len, buffer);
    memcpy(buffer + len, digest, DIGSIZE);
    hash(buffer, len+DIGSIZE, digest);
    return 0;
}

int print_hex(byte *hex, size_t len)
{
    std::string output;
    raw_to_hex(hex, len, output);
    std::cout << output << std::endl;
    return 0;
}

int file_sha256h0(void)
{
    byte digest[ DIGSIZE ];

    // std::ifstream::ate open and position at end of file
    std::ifstream myFile ("video05.mp4", std::ifstream::in | std::ifstream::binary | std::ifstream::ate);

    size_t flen = myFile.tellg();
    unsigned int nblocks = (unsigned int) flen / BLOCK;
    size_t last_block_len = (size_t) flen % BLOCK;
    size_t pos = flen;

    if(last_block_len)
    {
        pos = pos - last_block_len;
        hash_file_block(myFile, pos, last_block_len, digest);
    }

    // from second last to first
    for(unsigned int i = nblocks; i > 0; i--)
    {
        pos = pos - BLOCK;
        hash_file_block_concat(myFile, pos, BLOCK, digest);
    }

    myFile.close();

    print_hex(digest, DIGSIZE);
    
}

int main(void)
{
    file_sha256h0();
    return 0;
}