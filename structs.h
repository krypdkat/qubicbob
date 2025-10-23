#pragma once
#include "defines.h"
#include "utils.h"
#include <cstddef>
#include <cstring>
#include "m256i.h"
struct RequestResponseHeader {
private:
    uint8_t _size[3];
    uint8_t _type;
    unsigned int _dejavu;

public:
    static constexpr unsigned int max_size = 0xFFFFFF;
    inline unsigned int size() const{
        if (((*((unsigned int*)_size)) & 0xFFFFFF)==0) return INT32_MAX; // size is never zero, zero means broken packets
        return (*((unsigned int*)_size)) & 0xFFFFFF;
    }

    inline void setSize(unsigned int size) {
        _size[0] = (uint8_t)size;
        _size[1] = (uint8_t)(size >> 8);
        _size[2] = (uint8_t)(size >> 16);
    }

    inline bool isDejavuZero()
    {
        return !_dejavu;
    }

    inline void zeroDejavu()
    {
        _dejavu = 0;
    }

    inline void randomizeDejavu()
    {
        rand32(&_dejavu);
        if (!_dejavu)
        {
            _dejavu = 1;
        }
    }
    void setDejavu(uint32_t dejavu)
    {
        _dejavu = dejavu;
    }

    inline uint8_t type() const
    {
        return _type;
    }

    inline void setType(const uint8_t type)
    {
        _type = type;
    }

    inline uint32_t getDejavu() const
    {
        return _dejavu;
    }

    // Return pointer to payload, which is stored behind the header.
    // The type() is not checked against the PayloadType!
    template <typename PayloadType>
    inline PayloadType* getPayload()
    {
        return reinterpret_cast<PayloadType*>(this + 1);
    }

    // Check if the payload size is as expected.
    inline bool checkPayloadSize(unsigned int expected_payload_size) const
    {
        return size() == expected_payload_size + sizeof(RequestResponseHeader);
    }

    // Check if the payload size is in the expected range.
    inline bool checkPayloadSizeMinMax(unsigned int min_payload_size, unsigned int max_payload_size) const
    {
        return min_payload_size + sizeof(RequestResponseHeader) <= size() && size() <= max_payload_size + sizeof(RequestResponseHeader);
    }

    // Get size of the payload (without checking validity of overall size).
    inline unsigned int getPayloadSize() const
    {
        return this->size() - sizeof(RequestResponseHeader);
    }
};
typedef struct
{
    unsigned char sourcePublicKey[32];
    unsigned char destinationPublicKey[32];
    long long amount;
    unsigned int tick;
    unsigned short inputType;
    unsigned short inputSize;
} Transaction;

typedef struct
{
    unsigned short tickDuration;
    unsigned short epoch;
    unsigned int tick;
    unsigned short numberOfAlignedVotes;
    unsigned short numberOfMisalignedVotes;
    unsigned int initialTick;
} CurrentTickInfo;

struct TickData
{
    unsigned short computorIndex;
    unsigned short epoch;
    unsigned int tick;

    unsigned short millisecond;
    unsigned char second;
    unsigned char minute;
    unsigned char hour;
    unsigned char day;
    unsigned char month;
    unsigned char year;

    unsigned char timelock[32];
    unsigned char transactionDigests[NUMBER_OF_TRANSACTIONS_PER_TICK][32];
    long long contractFees[NUMBER_OF_TRANSACTIONS_PER_TICK];

    unsigned char signature[SIGNATURE_SIZE];
    static constexpr unsigned char type()
    {
        return 8;
    }
};

typedef struct
{
    unsigned int tick;
} RequestedTickData;

typedef struct
{
    RequestedTickData requestedTickData;
    enum {
        type = 16,
    };
} RequestTickData;

typedef struct
{
    unsigned int tick;
    unsigned char voteFlags[(NUMBER_OF_COMPUTORS + 7) / 8];
    enum {
        type = 14,
    };
} RequestedQuorumTick;

typedef struct
{
    unsigned int tick;
    unsigned char transactionFlags[NUMBER_OF_TRANSACTIONS_PER_TICK / 8];
} RequestedTickTransactions;

typedef struct
{
    uint8_t sig[SIGNATURE_SIZE];
} SignatureStruct;
typedef struct
{
    char hash[60];
} TxhashStruct;
typedef struct
{
    std::vector<uint8_t> vecU8;
} extraDataStruct;

struct RequestLog // Fetches log
{
    unsigned long long passcode[4];
    unsigned long long fromid;
    unsigned long long toid;

    static constexpr unsigned char type()
    {
        return 44;
    }
};

struct RequestLogIdRange // Fetches logId range
{
    unsigned long long passcode[4];
    unsigned int tick;
    unsigned int txId;

    static constexpr unsigned char type()
    {
        return 48;
    }
};
struct ResponseLogIdRange // Fetches logId range
{
    long long fromLogId;
    long long length;

    static constexpr unsigned char type()
    {
        return 49;
    }
};

// Request logid ranges of all txs from a tick
struct RequestAllLogIdRangesFromTick
{
    unsigned long long passcode[4];
    unsigned int tick;

    static constexpr unsigned char type()
    {
        return 50;
    }
};

#define LOG_TX_NUMBER_OF_SPECIAL_EVENT 5
#define LOG_TX_PER_TICK (NUMBER_OF_TRANSACTIONS_PER_TICK + LOG_TX_NUMBER_OF_SPECIAL_EVENT)// +5 special events
// Response logid ranges of all txs from a tick
struct ResponseAllLogIdRangesFromTick
{
    long long fromLogId[LOG_TX_PER_TICK];
    long long length[LOG_TX_PER_TICK];

    static constexpr unsigned char type()
    {
        return 51;
    }
};


struct RespondLog // Returns buffered log; clears the buffer; make sure you fetch log quickly enough, if the buffer is overflown log stops being written into it till the node restart
{
    // Variable-size log;

    static constexpr unsigned char type()
    {
        return 45;
    }
};

// Request logid ranges of all txs from a tick
struct RequestPruningPageFiles
{
    unsigned long long passcode[4];
    unsigned long long fromLogId;
    unsigned long long toLogId;

    static constexpr unsigned char type()
    {
        return 56;
    }
};

// Response 0 if success, otherwise error code will be returned
struct ResponsePruningPageFiles
{
    long long success;
    static constexpr unsigned char type()
    {
        return 57;
    }
};

// Request logid ranges of all txs from a tick
struct RequestLogStateDigest
{
    unsigned long long passcode[4];
    unsigned int requestedTick;

    static constexpr unsigned char type()
    {
        return 58;
    }
};

// Response 0 if success, otherwise error code will be returned
struct ResponseLogStateDigest
{
    unsigned char digest[32];
    static constexpr unsigned char type()
    {
        return 59;
    }
};


/*STRUCT FOR LOGGING*/
/*
* STRUCTS FOR LOGGING
*/
struct QuTransfer
{
    m256i sourcePublicKey;
    m256i destinationPublicKey;
    long long amount;
    
};

#pragma pack(push,1)
struct AssetIssuance
{
    m256i issuerPublicKey;
    long long numberOfShares;
    long long managingContractIndex;
    char name[7];
    char numberOfDecimalPlaces;
    char unitOfMeasurement[7];

    
};
struct AssetOwnershipChange
{
    m256i sourcePublicKey;
    m256i destinationPublicKey;
    m256i issuerPublicKey;
    long long numberOfShares;
    long long managingContractIndex;
    char name[7];
    char numberOfDecimalPlaces;
    char unitOfMeasurement[7];
};

struct AssetPossessionChange
{
    m256i sourcePublicKey;
    m256i destinationPublicKey;
    m256i issuerPublicKey;
    long long numberOfShares;
    long long managingContractIndex;
    char name[7];
    char numberOfDecimalPlaces;
    char unitOfMeasurement[7];

    
};

struct AssetOwnershipManagingContractChange
{
    m256i ownershipPublicKey;
    m256i issuerPublicKey;
    unsigned int sourceContractIndex;
    unsigned int destinationContractIndex;
    long long numberOfShares;
    char assetName[7];

    
};

struct AssetPossessionManagingContractChange
{
    m256i possessionPublicKey;
    m256i ownershipPublicKey;
    m256i issuerPublicKey;
    unsigned int sourceContractIndex;
    unsigned int destinationContractIndex;
    long long numberOfShares;
    char assetName[7];

    
};
#pragma pack(pop)
struct Burning
{
    m256i sourcePublicKey;
    long long amount;
};

#pragma pack(push,1)
struct Computors
{
    // TODO: Padding
    unsigned short epoch;
    m256i publicKeys[NUMBER_OF_COMPUTORS];
    unsigned char signature[SIGNATURE_SIZE];
};
static_assert(sizeof(Computors) == 2 + 32 * NUMBER_OF_COMPUTORS + SIGNATURE_SIZE, "Something is wrong with the struct size.");

#pragma pack(pop)