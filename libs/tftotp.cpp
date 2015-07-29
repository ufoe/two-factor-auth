#include "tftotp.h"

TFTOTP::TFTOTP(string input)
{
    token32 = input;
    token32_len = input.size();
    decodeToken(); // TODO: add check for result
}

string TFTOTP::generateCode()
{
    int date = time(NULL) / TFTOTP_PERIOD;

    hmacSHA1(date);

    if (token32 == vtos(ctov(vtoc(stov(token32)))))
        return "Match";
    else
        return "Not match!!!";
}

int TFTOTP::hmacSHA1(int date)
{
    // Formating date to useful form ?
//    vector<unsigned char> divided_date;

    // If token is too long - will use hash instead of token
    if (token_len > TFTOTP_SHA_BLOCK) {
        // -> Update token with calculated hash
        token = ctov(SHA1(vtoc(token), token_len, 0));

        // -> Update token length
        token_len = token.size();
    }
    if (token_len < TFTOTP_SHA_BLOCK) {
        // Fill token with NULL up to end of block
        for (int i=token_len; i<TFTOTP_SHA_BLOCK; ++i)
            token.push_back(0);

        // -> Update token length
        token_len = token.size();
    }

    // Fill inner and outer vectors for HMAC-SHA calculation
    vector<unsigned char> ipad;
    vector<unsigned char> opad;
    for (int i=0; i<TFTOTP_SHA_BLOCK; ++i) {
        ipad.push_back(TFTOTP_IN_DIG);
        opad.push_back(TFTOTP_OUT_DIG);
    }

    // Calculating XOR
    ipad = vxor(ipad, token);
    opad = vxor(opad, token);

    vector<unsigned char> buffer;

    // Step 1
    //   Concat ipad with date and get hash from
    buffer = ipad;
    buffer.push_back(date);
    buffer = ctov(SHA1(vtoc(buffer), buffer.size(), 0));
    printHex("buffer with ipad", buffer);

    // Step 2
    //   Concat opad with previous hash and get hash from
    buffer.insert(buffer.begin(), opad.begin(), opad.end() );
    buffer = ctov(SHA1(vtoc(buffer), buffer.size(), 0));
    printHex("buffer with opad", buffer);

    // Step 3
    //   Get last 4 bits from last value as offset
    int offset = buffer.at(TFTOTP_SHA_LEN - 1) & 0xf;

    // Step 4
    //   Cut block and execute dynamic truncation
    vector<unsigned char> totp_block;
    for (int i=0; i<4; ++i) {
        totp_block.push_back(buffer.at(offset + i) & ( i==0 ? 0x7f : 0x77 ) );
    }
    printHex("totp_block", totp_block);

    // TODO: Convert block to digits

    return TFTOTP_SUCCESS;
}

vector<unsigned char> TFTOTP::vxor(vector<unsigned char> a, vector<unsigned char> b)
{
    vector<unsigned char> output;

    // Length will be max of incoming vector sizes
    unsigned int output_len = ( a.size() > b.size() ? a.size() : b.size() );

    for (unsigned int i=0; i < output_len; ++i) {
        output.push_back( ( i < a.size() ? a.at(i) : 0) ^ ( i < b.size() ? b.at(i) : 0) );
    }

    return output;
}

int TFTOTP::decodeToken()
{
    unsigned char *_token32 = vtoc(stov(token32));

    // Unmaping token with defined alphabet
    if (!Base32::Unmap32(_token32, token32_len, alphabet)) {
        cerr << "[TFTOTP::decodeToken] error on unmapping token" << endl;
        return 1; // TODO: replace with errno definition
    }

    // -> Update length for decoded token
    token_len = Base32::GetDecode32Length(token32_len);

    // Initialize temporary array to work with Base32::Decode32
    unsigned char *_token = new unsigned char [token_len];

    // Decoding unmapped array
    if (!Base32::Decode32(_token32, token32_len, _token)) {
        cerr << "[TFTOTP::decodeToken] error on decoding token" << endl;
        return 2; // TODO: replace with errno definition
    }

    // -> Update decoded token value
    token = ctov(_token);

    return TFTOTP_SUCCESS;
}

int TFTOTP::encodeToken()
{
    // -> Update length for encoded token
    token32_len = Base32::GetEncode32Length(token_len);

    // Initialize temporary array to work with Base32::Encode32
    unsigned char *_token32 = new unsigned char [token32_len];

    // Encoding token in base32
    if (!Base32::Encode32(vtoc(token), token_len, _token32)) {
        cerr << "[TFTOTP::encodeToken] error on encoding token" << endl;
        return 3; // TODO: replace with errno definition
    }

    // Maping token
    if (!Base32::Map32(_token32, token32_len, alphabet)) {
        cerr << "[TFTOTP::encodeToken] error on maping token" << endl;
        return 4; // TODO: replace with errno definition
    }

    // -> Update encoded token value
    token32 = vtos(ctov(_token32));

    return TFTOTP_SUCCESS;
}

// Vector to string
string TFTOTP::vtos(vector<unsigned char> input)
{
    string output = "";
    for (vector<unsigned char>::iterator it = input.begin() ; it != input.end(); ++it)
        output.append(1, static_cast<char>(*it));
    return output;
}

// String to vector
vector<unsigned char> TFTOTP::stov(string input)
{
    vector<unsigned char> output;
    for (unsigned int i=0; i<input.size(); ++i)
        output.push_back(input[i]);
    return output;
}

// Vector to unsigned char array
unsigned char *TFTOTP::vtoc(vector<unsigned char> input)
{
    unsigned char *output = new unsigned char [input.size()];
    int i = 0;
    for (vector<unsigned char>::iterator it = input.begin() ; it != input.end(); ++it) {
        output[i] = *it;
        ++i;
    }
    return output;
}

// Unsigned char array to vector
vector<unsigned char> TFTOTP::ctov(unsigned char *input)
{
    vector<unsigned char> output;
    for (unsigned int i=0; i<strlen((char*)input); ++i)
        output.push_back(input[i]);
    return output;
}

// Print vector in HEX
void TFTOTP::printHex(string name, vector<unsigned char> input)
{
    cout << name << ": " << setfill('0');

    for (vector<unsigned char>::iterator it = input.begin(); it != input.end(); ++it)
        cout << ( it != input.begin() ? ":" : "" ) << hex << setw(2) << (int)*it;
    cout << endl;
}
