/*
 * erigon_extract: ETL for Nimbus-eth1 full state
 * Reads an Erigon database, writes an DB file for Nimbus-eth1.
 *
 * Copyright (C) 2021, 2022 Jamie Lokier
 *
 * This file is licensed under either of "MIT license" or "Apache License,
 * Version 2.0", at your option.  Links to each license respectively:
 * - <http://opensource.org/licenses/MIT>
 * - <http://www.apache.org/licenses/LICENSE-2.0>.
 *
 * This file is provided without any warranty.  Use at your own risk.  It is
 * intended that excerpts be used and changed in other programs, subject to the
 * terms of the one or both of the above licenses.
 */

#include "mdbx.h"

#include <ctype.h>
#include <stdarg.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if CALCULATE_KECCAK256

#if 0
/* https://github.com/brainhub/SHA3IUF */
#include "SHA3IUF/sha3.h"
#include "SHA3IUF/sha3.c"
static inline keccak256(byte *hash, const byte *input, size_t length)
{
	sha3_context ctx;
	sha3_Init256(&ctx);
	sha3_SetFlags(&ctx, SHA3_FLAGS_KECCAK);
	sha3_Update(&ctx, input, length);
	const void *h = sha3_Finalize(&ctx);
	memcpy(hash, h, 32);
}
#else
/*
 * https://github.com/firefly/wallet
 * About 1.2 microseconds per short hash on my system.
 */
#include "wallet/source/libs/ethers/src/keccak256.h"
#include "wallet/source/libs/ethers/src/keccak256.c"
static inline keccak256(byte *hash, const byte *input, size_t length)
{
	SHA3_CTX ctx;
	keccak_init(&ctx);
	keccak_update(&ctx, input, length);
	byte hash[32];
	keccak_final(&ctx, hash);
}
#endif

#endif

static volatile sig_atomic_t stop_flag;

static void signal_handler(int sig)
{
	stop_flag = 1;
}

static void setup_signal_handler(void)
{
	signal(SIGPIPE, signal_handler);
	signal(SIGHUP, signal_handler);
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
}

typedef uint8_t byte;

static const char hex_chars[] = "0123456789abcdef";

static void print_bytes(const char *bytes, size_t start, size_t end)
{
	while (start < end) {
		byte b = bytes[start++];
		putchar(hex_chars[(b >> 4) & 0x0f]);
		putchar(hex_chars[b & 0x0f]);
	}
}

static void print_number(const char *bytes, size_t start, size_t end)
{
	while (start < end) {
		if (bytes[start] != 0)
			break;
		start++;
	}
	if (start >= end) {
		putchar('0');
	} else if ((bytes[start] >> 4) == 0) {
		putchar(hex_chars[bytes[start] & 0x0f]);
		start++;
	}
	print_bytes(bytes, start, end);
}

static void print_mdbx_val(MDBX_val *v)
{
	putchar(' ');
	print_bytes(v->iov_base, 0, v->iov_len);
	putchar('\n');
}

bool opt_verbose = true, opt_print = false;
const char *prog;

#define PRINT opt_print
#define CODE_BLOCK_NUMBER 1  /* Range 1..8        */
#define CODE_ADDRESS      9  /* Single value 9    */
#define CODE_ACCOUNT      10 /* Range 10..73      */
#define CODE_STORAGE      74 /* Range 74..249     */
#define CODE_INCARNATION  250 /* Single value 250 */
#define CODE_BLOCK_INLINE 251 /* Range 251..255   */

static void error(const char *func, int rc)
{
	if (opt_verbose)
		fprintf(stderr, "%s: %s() error %d %s\n", prog, func, rc,
			mdbx_strerror(rc));
}

static uint64_t get64be(const byte *bytes)
{
	uint64_t result = 0;
	result = (result << 8) + *(const uint8_t *)bytes++;
	result = (result << 8) + *(const uint8_t *)bytes++;
	result = (result << 8) + *(const uint8_t *)bytes++;
	result = (result << 8) + *(const uint8_t *)bytes++;
	result = (result << 8) + *(const uint8_t *)bytes++;
	result = (result << 8) + *(const uint8_t *)bytes++;
	result = (result << 8) + *(const uint8_t *)bytes++;
	result = (result << 8) + *(const uint8_t *)bytes++;
	return result;
}

static void put64be(byte *bytes, uint64_t value)
{
	*bytes++ = (byte)(value >> 56);
	*bytes++ = (byte)(value >> 48);
	*bytes++ = (byte)(value >> 40);
	*bytes++ = (byte)(value >> 32);
	*bytes++ = (byte)(value >> 24);
	*bytes++ = (byte)(value >> 16);
	*bytes++ = (byte)(value >> 8);
	*bytes++ = (byte)value;
}

static uint64_t get64be_len(const byte *bytes, size_t len)
{
	uint64_t result = 0;
	for (size_t i = 0; i < 8 && i < len; i++)
		result = (result << 8) + *(const uint8_t *)bytes++;
	return result;
}

#define ADDRESS_LEN     20
#define BALANCE_LEN     32
#define HASH_LEN        32
#define SLOT_LEN        32
#define VALUE_LEN       32
#define BLOCK_LEN       8
#define INCARNATION_LEN 8

static const byte zero_balance[BALANCE_LEN] = { 0, };
static const byte zero_code_hash[HASH_LEN] = { 0, };
static const byte empty_code_hash[HASH_LEN] = {
	0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2,
	0xdc, 0xc7, 0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b,
	0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70
};

struct ReaderItem {
	byte address[ADDRESS_LEN];
	uint64_t block;
	bool is_storage;
};

struct Account {
	struct ReaderItem item_base;
	uint64_t nonce, incarnation;
	byte balance[BALANCE_LEN], codeHash[HASH_LEN];
};

struct Storage {
	struct ReaderItem item_base;
	byte slot[HASH_LEN], value[VALUE_LEN];
	uint64_t incarnation;
};

static int decode_account(const byte *account_bytes, size_t account_len,
			  MDBX_txn *txn, MDBX_dbi dbi_codeHash,
			  uint64_t block, const byte address[ADDRESS_LEN],
			  struct Account *account)
{
	int rc;
	byte fieldset = 0;
	size_t pos = 0;

	*account = (struct Account){
		.item_base.is_storage = false,
		.item_base.block = block,
		.nonce = 0,
		.incarnation = 0,
		.balance = { 0, },
		.codeHash = { 0, },
	};
	memcpy(account->item_base.address, address, ADDRESS_LEN);

	if (account_len >= 1)
		fieldset = account_bytes[pos++];
	if (fieldset & 1) {
		if (pos >= account_len)
			goto err_decoding;
		size_t item_len = account_bytes[pos++];
		if (pos + item_len > account_len || item_len > 8)
			goto err_decoding;
		account->nonce = get64be_len(account_bytes + pos, item_len);
		pos += item_len;
	}
	if (fieldset & 2) {
		if (pos >= account_len)
			goto err_decoding;
		size_t item_len = account_bytes[pos++];
		if (pos + item_len > account_len || item_len > BALANCE_LEN)
			goto err_decoding;
		if (item_len > 0)
			memcpy(account->balance + (BALANCE_LEN - item_len), account_bytes + pos, item_len);
		pos += item_len;
	}
	if (fieldset & 4) {
		if (pos >= account_len)
			goto err_decoding;
		size_t item_len = account_bytes[pos++];
		if (pos + item_len > account_len || item_len > 8)
			goto err_decoding;
		account->incarnation = get64be_len(account_bytes + pos, item_len);
		pos += item_len;
	}
	if (fieldset & 8) {
		if (pos >= account_len)
			goto err_decoding;
		size_t item_len = account_bytes[pos++];
		if (pos + item_len > account_len || item_len != HASH_LEN)
			goto err_decoding;
		memcpy(account->codeHash, account_bytes + pos, item_len);
		pos += item_len;
	}
	if (fieldset & 0xf0)
		goto err_decoding;
	if (pos != account_len)
		goto err_decoding;

	if ((!(fieldset & 8)
	     || 0 == memcmp(account->codeHash, empty_code_hash, HASH_LEN)
	     || 0 == memcmp(account->codeHash, zero_code_hash, HASH_LEN))
		&& account->incarnation != 0) {
		byte lookup_code_hash[28];
		memcpy(lookup_code_hash, address, ADDRESS_LEN);
		put64be(lookup_code_hash + ADDRESS_LEN, account->incarnation);
		MDBX_val key, data;
		key.iov_base = lookup_code_hash;
		key.iov_len = sizeof(lookup_code_hash);
		rc = mdbx_get(txn, dbi_codeHash, &key, &data);
		if (rc == MDBX_SUCCESS) {
			// Erigon code doesn't strictly say this, but the value
			// should be exactly 32 bytes.
			if (data.iov_len != HASH_LEN) {
				rc = MDBX_INVALID;
				goto err_codeHash;
			}
			memcpy(account->codeHash, data.iov_base, HASH_LEN);
			// Erigon code doesn't strictly check this, but the
			// restored hash should not be all zeros or empty code.
			if (0 == memcmp(account->codeHash, empty_code_hash, HASH_LEN)
			    || 0 == memcmp(account->codeHash, zero_code_hash, HASH_LEN)){
				goto err_decoding;
			}
		} else if (rc == MDBX_NOTFOUND) {
			// NOTFOUND is fine and means don't replace the code hash.
		} else {
			goto err_codeHash;
		}
	}

	// Erigon code doesn't strictly check this, but zero incarnation or
	// empty code hash should be represented consistently as all zeros,
	// never `empty_code_hash` in this format.
	if (account->incarnation == 0
	    ? 0 != memcmp(account->codeHash, zero_code_hash, HASH_LEN)
	    : 0 == memcmp(account->codeHash, empty_code_hash, HASH_LEN))
	    goto err_decoding;

	return MDBX_SUCCESS;
err_decoding:
	printf("  ** DECODING_ERROR Account address=");
	print_bytes(address, 0, ADDRESS_LEN);
	printf("\n                            blob=");
	print_bytes(account_bytes, 0, account_len);
	printf("\n");
	fprintf(stderr, "Error decoding account\n");
	return MDBX_INVALID;
err_codeHash:
	printf(" ** MDBX_CODE_HASH_ERROR Account address=");
	print_bytes(address, 0, ADDRESS_LEN);
	printf("\n                               blob=");
	print_bytes(account_bytes, 0, account_len);
	error("mdbx_cursor_get PlainCodeHash", rc);
	return rc;
}

static int decode_storage(const byte *storage_bytes, size_t storage_len,
			  uint64_t block, const byte address[ADDRESS_LEN],
			  uint64_t incarnation, struct Storage *storage)
{
	if (storage_len < SLOT_LEN || storage_len > SLOT_LEN + VALUE_LEN)
		goto err_decoding;

	*storage = (struct Storage){
		.item_base.is_storage = true,
		.item_base.block = block,
		.incarnation = incarnation,
	};
	memcpy(storage->item_base.address, address, ADDRESS_LEN);
	memcpy(storage->slot, storage_bytes, SLOT_LEN);

	if (storage_len < SLOT_LEN + VALUE_LEN)
		memset(storage->value, 0, SLOT_LEN + VALUE_LEN - storage_len);
	if (storage_len > SLOT_LEN)
		memcpy(storage->value + (SLOT_LEN + VALUE_LEN - storage_len),
		       storage_bytes + SLOT_LEN, storage_len - SLOT_LEN);
	return MDBX_SUCCESS;

err_decoding:
	printf("  ** DECODING_ERROR Storage blob=");
	print_bytes(storage_bytes, 0, storage_len);
	printf("\n");
	fprintf(stderr, "Error decoding storage\n");
	return MDBX_INVALID;

}

#define T_RESET   "\033[m"
#define T_DIM     "\033[2m"
#define T_LABEL   T_DIM
#define T_BLOCK   "\033[31m"
#define T_ADDR    "\033[34m"
#define T_SLOT    "\033[35m"
#define T_CODE    "\033[33m"
#define T_ACCOUNT "\033[1;34m"
#define T_STORAGE "\033[1;35m"

static void print_file_offset(off_t offset)
{
	printf(T_DIM "(file offset=%llu offset=0x%llx)" T_RESET "\n",
	       (unsigned long long)offset, (unsigned long long)offset);
}

static void print_block_number(uint64_t block)
{
	printf(T_DIM "(set block=%llu)" T_RESET "\n", (unsigned long long)block);
}

static void print_address(const byte address[ADDRESS_LEN])
{
	printf(T_DIM "(set address=");
	print_bytes(address, 0, ADDRESS_LEN);
	printf(")" T_RESET "\n");
}

static void print_bytecode_incarnation(uint64_t bytecode_incarnation)
{
	printf(T_DIM "(bytecode_incarnation=%llu)" T_RESET "\n",
	       (unsigned long long)bytecode_incarnation);
}

static void print_account(const struct Account *account)
{
	printf("  " T_ACCOUNT "Account" T_RESET
	       T_LABEL " block=" T_RESET T_BLOCK "%llu" T_RESET
	       T_LABEL " address=" T_RESET T_ADDR,
	       (unsigned long long)account->item_base.block);
	print_bytes(account->item_base.address, 0, ADDRESS_LEN);
	printf(T_RESET "\n         "
	       T_LABEL " inc=" T_RESET "%llu"
	       T_LABEL " nonce=" T_RESET "%llu"
	       T_LABEL " balance=" T_RESET,
	       (unsigned long long)account->incarnation,
	       (unsigned long long)account->nonce);
	print_number(account->balance, 0, BALANCE_LEN);
	printf(T_RESET T_LABEL " codeHash=" T_RESET T_CODE);
	if (0 == memcmp(account->codeHash, empty_code_hash, HASH_LEN)
	    || 0 == memcmp(account->codeHash, zero_code_hash, HASH_LEN)) {
		printf("0");
	} else {
		print_bytes(account->codeHash, 0, HASH_LEN);
	}
	printf(T_RESET "\n");
}

static void print_storage(const struct Storage *storage)
{
	printf("  " T_STORAGE "Storage" T_RESET
	       T_LABEL " block=" T_RESET T_BLOCK "%llu" T_RESET
	       T_LABEL " slot=" T_RESET T_ADDR,
		(unsigned long long)storage->item_base.block);
	print_bytes(storage->item_base.address, 0, ADDRESS_LEN);
	printf(T_RESET "/" T_SLOT);
	print_bytes(storage->slot, 0, sizeof(storage->slot));
	printf(T_RESET "\n         "
	       T_LABEL " inc=" T_RESET "%llu"
	       T_LABEL " value=" T_RESET,
	       (unsigned long long)storage->incarnation);
	print_number(storage->value, 0, sizeof(storage->value));
	printf("\n");
}

struct File {
	FILE *file;
	char *buffer;
	char name[1];
};

static struct File *file_open(bool for_write, const char *format, ...)
{
	struct File *file;
	size_t file_name_size = 256;
	while (1) {
		file = malloc(offsetof(struct File, name) + file_name_size);
		if (!file) {
			perror("malloc");
			errno = ENOMEM;
			return NULL;
		}
		va_list ap;
		va_start(ap, format);
		size_t size = vsnprintf(file->name, file_name_size, format, ap);
		va_end(ap);
		if (size < file_name_size)
			break;
		free(file);
		file_name_size *= 2;
	}

	file->file = fopen(file->name, for_write ? "w" : "r");
	if (!file->file) {
		int save_error = errno;
		perror("fopen");
		free(file);
		errno = save_error;
		return NULL;
	}

	/* Larger file buffer for slightly faster reading/writing. */
	const size_t buffer_size = 262144;
	file->buffer = malloc(buffer_size);
	if (!file->buffer) {
		perror("malloc");
		fclose(file->file);
		free(file);
		errno = ENOMEM;
		return NULL;
	}
	if (setvbuf(file->file, file->buffer, _IOFBF, buffer_size) != 0) {
		perror("setvbuf");
		free(file->buffer);
		fclose(file->file);
		free(file);
		errno = EIO;
		return NULL;
	}

	return file;
}

static int file_close(struct File *file, bool delete_file)
{
	if (!file)
		return 0;
	if (delete_file)
		unlink(file->name);
	if (ferror(file->file)) {
		/* `ferror` doesn't set `errno`. */
		fclose(file->file);
		fprintf(stderr, "Error processing file %s\n", file->name);
		free(file->buffer);
		free(file);
		errno = EIO;
		return -1;
	}
	if (fclose(file->file) != 0) {
		int save_error = errno;
		perror("fclose");
		free(file->buffer);
		free(file);
		errno = save_error;
		return -1;
	}
	free(file->buffer);
	free(file);
	return 0;
}

struct Writer {
	struct File *file;
	uint64_t count_accounts, count_storage_slots;
	int strategy;
	bool have_block, have_address;
	uint64_t block, nonce, account_incarnation, storage_incarnation;
	byte address[ADDRESS_LEN];
	byte balance[BALANCE_LEN];
	byte code_hash[HASH_LEN];
	byte storage_slot[SLOT_LEN];
};

struct Reader {
	struct File *file;
	int strategy;
	union {
		struct Account account;
		struct Storage storage;
	};
	uint64_t block, nonce, account_incarnation, storage_incarnation;
	uint64_t bytecode_incarnation;
	byte address[ADDRESS_LEN];
	byte balance[BALANCE_LEN];
	byte code_hash[HASH_LEN];
	byte storage_slot[SLOT_LEN];
};

static void writer_state_init(struct Writer *writer)
{
	writer->have_block = false;
	writer->have_address = false;
	writer->block = 0;
	writer->account_incarnation = 0;
	writer->storage_incarnation = 0;
	memset(writer->address, 0, ADDRESS_LEN);
	memset(writer->balance, 0, BALANCE_LEN);
	memset(writer->code_hash, 0, HASH_LEN);
	memset(writer->storage_slot, 0, SLOT_LEN);
}

static void writer_init(struct Writer *writer, struct File *file,
			int strategy)
{
	writer->file = file;
	writer->count_accounts = 0;
	writer->count_storage_slots = 0;
	writer->strategy = strategy;
	writer_state_init(writer);
}

static void reader_state_init(struct Reader *reader)
{
	reader->block = 0;
	reader->account_incarnation = 0;
	reader->storage_incarnation = 0;
	reader->bytecode_incarnation = 0;
	memset(reader->address, 0, ADDRESS_LEN);
	memset(reader->balance, 0, BALANCE_LEN);
	memset(reader->code_hash, 0, HASH_LEN);
	memset(reader->storage_slot, 0, SLOT_LEN);
}

static void reader_init(struct Reader *reader, struct File *file,
			int strategy)
{
	reader->file = file;
	reader->strategy = strategy;
	reader_state_init(reader);
}

static void write_number(struct Writer *writer, const byte *bytes, size_t len)
{
	FILE *file = writer->file->file;
	size_t i;
	for (i = 0; i < len; i++)
		if (bytes[i] != 0)
			break;
	if (i == len)
		putc(0, file);
	else if (i + 1 == len && bytes[i] < 224)
		putc(bytes[i], file);
	else {
		byte prefix_code = (len - i) + 223;
		putc(prefix_code, file);
		for (; i < len; i++)
			putc(bytes[i], file);
	}
}

/* Must match `write_number`. */
static void read_number(struct Reader *reader, byte *value, size_t len)
{
	FILE *file = reader->file->file;
	byte b = getc(file);
	if (b < 224) {
		memset(value, 0, len);
		value[len-1] = b;
	} else {
		b -= 223;
		if (b < len) {
			memset(value, 0, len - b);
			value += len - b;
			len = b;
		}
		for (size_t i = 0; i < len; i++)
			value[i] = getc(file);
	}
}

static void write_u64(struct Writer *writer, uint64_t value)
{
	byte bytes[8];
	put64be(bytes, value);
	write_number(writer, bytes, sizeof(bytes));
}

/* Must match `write_u64`. */
static uint64_t read_u64(struct Reader *reader)
{
	byte bytes[8];
	read_number(reader, bytes, 8);
	return get64be(bytes);
}

static void write_array(struct Writer *writer, const byte *bytes, size_t len)
{
	FILE *file = writer->file->file;
	for (size_t i = 0; i < len; i++)
		putc(bytes[i], file);
}

/* Must match `write_array`. */
static void read_array(struct Reader *reader, byte *array, size_t len)
{
	FILE *file = reader->file->file;
	for (size_t i = 0; i < len; i++)
		array[i] = getc(file);
}

static void delta(byte *delta_out, const byte *value_in, byte *accumulator, size_t len)
{
	for (int i = len-1, borrow = 1; i >= 0; i--) {
		int delta = (int)value_in[i] - (int)accumulator[i] - borrow;
		accumulator[i] = value_in[i];
		borrow = delta < 0;
		delta_out[i] = (byte)delta;
	}
}

static void sum(byte *value_out, const byte *delta_in, byte *accumulator, size_t len)
{
	for (int i = len-1, carry = 1; i >= 0; i--) {
		int sum = (int)delta_in[i] + (int)accumulator[i] + carry;
		carry = sum >= 256;
		value_out[i] = accumulator[i] = (byte)sum;
	}
}

static void invert(byte *bytes, size_t len)
{
	for (int i = 0; i < (int)len; i++)
		bytes[i] = ~bytes[i];
}

static void write_block_number(struct Writer *writer, uint64_t block)
{
	if (writer->have_block && block == writer->block)
		return;
	uint64_t delta_block = block - writer->block;
	writer->have_block = true;
	writer->block = block;

	if (PRINT)
		print_block_number(block);

	if (writer->strategy == 0)
		delta_block = block;

	byte bytes[8];
	put64be(bytes, delta_block);
	size_t i;
	for (i = 0; i < 7; i++)
		if (bytes[i] != 0)
			break;
	if (i == 7 && bytes[7] <= 4) {
		putc(CODE_BLOCK_INLINE + bytes[7], writer->file->file);
	} else {
		putc(CODE_BLOCK_NUMBER + (7 - i), writer->file->file);
		for (; i < 8; i++)
			putc(bytes[i], writer->file->file);
	}
}

/* Must match `write_block_number`. */
static void read_block_number(struct Reader *reader, uint64_t *block_number,
			      byte b)
{
	uint64_t encoded_block;
	if (b >= CODE_BLOCK_INLINE) {
		encoded_block = b - CODE_BLOCK_INLINE;
	} else {
		int len = (int)(b - CODE_BLOCK_NUMBER + 1);
		encoded_block = 0;
		for (int i = 0; i < len; i++) {
			encoded_block <<= 8;
			encoded_block += getc(reader->file->file);
		}
	}
	if (reader->strategy != 0)
		encoded_block += reader->block;
	*block_number = encoded_block;
}

static void write_address(struct Writer *writer, const byte address[ADDRESS_LEN])
{
	if (writer->have_address
	    && 0 == memcmp(address, writer->address, ADDRESS_LEN))
		return;
#if 0
	byte delta_address[ADDRESS_LEN];
	delta(delta_address, address, writer->address, ADDRESS_LEN);
#endif
	writer->have_address = true;
	memcpy(writer->address, address, ADDRESS_LEN);

	if (PRINT)
		print_address(address);

	putc(CODE_ADDRESS, writer->file->file);
	write_array(writer, address, ADDRESS_LEN);

	if (writer->strategy >= 1) {
		/* New address resets some other compression values. */
		writer->block = 0;
		writer->nonce = 0;
		memset(writer->balance, 0, BALANCE_LEN);
		memset(writer->code_hash, 0, HASH_LEN);
	}
	/* `write_storage` uses incarnation reference with strategy == 0 too. */
	writer->account_incarnation = 0;
	writer->storage_incarnation = 0;
}

/* Must match `write_address`. */
static void read_address(struct Reader *reader, byte address[ADDRESS_LEN])
{
	read_array(reader, reader->address, ADDRESS_LEN);
	if (reader->strategy >= 1) {
		reader->block = 0;
		reader->nonce = 0;
		memset(reader->balance, 0, BALANCE_LEN);
		memset(reader->code_hash, 0, HASH_LEN);
	}
	reader->account_incarnation = 0;
	reader->storage_incarnation = 0;
}

//#define SPECIAL_LOG_ADDRESS 0x00, 0x52, 0xb9, 0x4f, 0x97, 0x43, 0x12, 0x9d, 0x87, 0x78, 0x8b, 0x17, 0x75, 0x38, 0x66, 0xa5, 0x6b, 0xe2, 0x2e, 0xce
//#define SPECIAL_LOG_ADDRESS 0x05, 0x14, 0xb6, 0x31, 0x17, 0xd2, 0x93, 0x1a, 0x88, 0x48, 0xb0, 0xc5, 0x47, 0x7b, 0xb1, 0x8b, 0x65, 0xe8, 0x0e, 0x07
#define SPECIAL_LOG_ADDRESS 0x39, 0xd2, 0xa8, 0x51, 0x4c, 0xac, 0x3b, 0xb6, 0xcb, 0x7d, 0xbd, 0x85, 0xaa, 0x3a, 0x48, 0x93, 0x78, 0x77, 0xc1, 0x3b

#ifdef SPECIAL_LOG_ADDRESS
static const byte special[ADDRESS_LEN] = { SPECIAL_LOG_ADDRESS };
#endif

static void write_account(struct Writer *writer, const struct Account *account)
{
	writer->count_accounts++;
	byte flags = 0;

	const byte *encoded_code_hash = account->codeHash;
	bool is_zero_code_hash = false;
	if (0 == memcmp(account->codeHash, zero_code_hash, HASH_LEN)
	    || 0 == memcmp(account->codeHash, empty_code_hash, HASH_LEN)) {
		encoded_code_hash = zero_code_hash;
		is_zero_code_hash = true;
	}

	if (!is_zero_code_hash && account->incarnation == 0) {
		/* These don't occur, so class their appearance as an error. */
		print_account(account);
		fflush(stdout);
		fprintf(stderr, "Error: ^ Account with non-zero codeHash and zero incarnation\n");
		abort();
	}
#if 0
	if (is_zero_code_hash && account->incarnation != 0) {
		/*
		 * Many of these occur in `PlainState`, in too many to list.
		 * Much fewer the in the history.
		 */
		print_account(account);
		fflush(stdout);
		fprintf(stderr, "Warning: ^ Account with zero codeHash and non-zero incarnation\n");
		//abort();
	}
#endif
	if (account->incarnation != 0
	    && account->incarnation - writer->account_incarnation >= 3) {
		/* A few of these occur. */
		print_account(account);
		fflush(stdout);
		fprintf(stderr, "Warning: ^ Account with delta incarnation >= 3\n");
		//abort();
	}

	/* Nonce delta encoding alone saves ~1.5% of storage. */
	uint64_t encoded_nonce, encoded_incarnation;
	if (writer->strategy == 0) {
		encoded_nonce = account->nonce;
		encoded_incarnation = account->incarnation;
	} else {
		encoded_nonce = account->nonce - writer->nonce;
		if (writer->strategy == 3 && is_zero_code_hash)
			encoded_incarnation = account->incarnation;
		else
			encoded_incarnation = account->incarnation - writer->account_incarnation;
	}

	/* Balance delta encoding saves ~8% of storage. */
	byte encoded_balance[BALANCE_LEN];
	if (writer->strategy == 0) {
		memcpy(encoded_balance, account->balance, BALANCE_LEN);
	} else {
		delta(encoded_balance, account->balance, writer->balance, BALANCE_LEN);
		if (encoded_balance[0] >= (byte)0x80) {
			invert(encoded_balance, BALANCE_LEN);
			flags |= (1 << 5);
		}
	}
	if (0 != memcmp(encoded_balance, zero_balance, BALANCE_LEN))
		flags |= (1 << 0);

#ifdef SPECIAL_LOG_ADDRESS
	static int special_counter = 0;
	if (special_counter || 0 == memcmp(account->item_base.address, special, ADDRESS_LEN)) {
		if (special_counter == 0)
			special_counter = 10;
		special_counter--;
		printf("Write special case, block=%llu\n", (unsigned long long)account->item_base.block);
		print_file_offset(ftello(writer->file->file));
		print_account(account);
	}
#endif /* SPECIAL_LOG_ADDRESS */

	/*
	 * At mainnet block 10094566, there is a self-destruct, create, sstore
	 * on account 000000000000006f6502b7f2bbac8c30a3f67e9a.  It has the
	 * effect of pairing an inc=1 account entry (from before the
	 * self-destruct) with inc=2 storage entries (from before the sstore).
	 * Later at block 10094587, the balance changes which adds the inc=2
	 * account entry for the create at 10094566.  The sequence when address
	 * is the primary order, and account/state updates as at
	 * last-block-number:
	 *
	 * (set block=10094566)
	 * Account block=10094566 address=000000000000006f6502b7f2bbac8c30a3f67e9a
	 *         inc=1 nonce=1976 balance=1 codeHash=a81d7f06c942f28e7852465c195e233d05e645893ae829822e95b4ff420d93c2
	 * Storage block=10094566 slot=000000000000006f6502b7f2bbac8c30a3f67e9a/0000000000000000000000000000000000000000000000000000000000005850
	 *         inc=2 value=0
	 * Storage block=10094566 slot=000000000000006f6502b7f2bbac8c30a3f67e9a/0000000000000000000000003452954838762313786992245132387393331546
	 *         inc=2 value=0
	 * (set block=10094587)
	 * Account block=10094587 address=000000000000006f6502b7f2bbac8c30a3f67e9a
	 *         inc=2 nonce=1 balance=1 codeHash=b06895d1ddccd23a5648db366bf46ecaf7e60d6364a7974e8785d9eb5f04cc18
	 *
	 * Due to this sequence, simply delta-compressing inc results in zero
	 * delta for the second account entry, which doesn't match the encoding
	 * constraint that codeHash only changes when there is delta inc.  To
	 * maintain the constraint, delta-compression of account inc is done
	 * relative to the previous account inc.  This problem goes away when
	 * we change all account/state updates to Nimbus first-block-number
	 * order, and constrain storage inc ranges correctly.  But that is only
	 * possible after merging the transposed state files.
	 *
	 * TODO: When that's done, there will be no need to encode all-zeros
	 * code hashes for self-destructed accounts.
	 */
	if (writer->strategy == 0) {
		if (!is_zero_code_hash)
			flags |= (1 << 1);
	} else if (0 != memcmp(writer->code_hash, encoded_code_hash, HASH_LEN)) {
		flags |= (1 << 1);
		if (!is_zero_code_hash && encoded_incarnation == 0) {
			print_account(account);
			fflush(stdout);
			fprintf(stderr, "Warning: ^ Change of code hash with no change of incarnation\n");
			//abort();
		}
	}

	if (writer->strategy == 2) {
		if (account->balance == 0) {
			flags |= (1 << 3);
			flags &= ~(1 << 0);
		}
		if (encoded_nonce >= 1) {
			flags |= (1 << 2);
		}
	} else {
		if (encoded_nonce >= 3) {
			flags |= (3 << 2);
		} else {
			flags |= (byte)encoded_nonce << 2;
		}
	}

	if (writer->strategy == 0) {
		if (encoded_incarnation >= 3)
			flags |= (3 << 4);
		else
			flags |= (byte)encoded_incarnation << 4;
	} else {
		/*
		 * In account entries, in the block ranges measured (blocks
		 * 10-10.1M), `encoded_incarnation` was 0 in 99.865% of
		 * entries, 1 in 0.135% of entries, and never >= 2.  It is
		 * rare, so there is no need for efficient inline encoding of
		 * >= 2, but it must be supported because multiple
		 * self-destruct+create pairs are allowed in the same block.
		 */
		if (encoded_incarnation == 1) {
			flags |= (1 << 4);
		} else if (encoded_incarnation != 0) {
			if (PRINT)
				print_bytecode_incarnation(encoded_incarnation);
			putc(CODE_INCARNATION, writer->file->file);
			write_u64(writer, encoded_incarnation);
		}
	}

	if (PRINT)
		print_account(account);
	putc(CODE_ACCOUNT + flags, writer->file->file);
	if (flags & (1 << 0))
		write_number(writer, encoded_balance, BALANCE_LEN);
	if (flags & (1 << 1))
		write_array(writer, encoded_code_hash, HASH_LEN);
	if (writer->strategy == 2) {
		if ((flags & (1 << 2)) == (1 << 2))
			write_u64(writer, encoded_nonce);
	} else {
		if ((flags & (3 << 2)) == (3 << 2))
			write_u64(writer, encoded_nonce);
	}
	if (writer->strategy == 0 && ((flags & (3 << 4)) == (3 << 4)))
		write_u64(writer, encoded_incarnation);

	/*
	 * `write_storage` uses the incarnation base with both strategies,
	 * and a new account updates the storage incarnation base.
	 */
	writer->nonce = account->nonce;
	writer->account_incarnation = account->incarnation;
	writer->storage_incarnation = account->incarnation;
	memcpy(writer->balance, account->balance, BALANCE_LEN);
	memcpy(writer->code_hash, account->codeHash, HASH_LEN);
}

/* Must match `write_account`. */
static void read_account(struct Reader *reader, struct Account *account,
			 byte b)
{
	byte flags = b - CODE_ACCOUNT;
	*account = (struct Account){
		.item_base.is_storage = false,
		.item_base.block = reader->block,
		.nonce = 0,
		.incarnation = 0,
		.balance = { 0, },
		.codeHash = { 0, },
	};
	memcpy(account->item_base.address, reader->address, ADDRESS_LEN);

	byte encoded_balance[BALANCE_LEN];
	if (flags & (1 << 0)) {
		read_number(reader, encoded_balance, BALANCE_LEN);
	} else {
		memset(encoded_balance, 0, BALANCE_LEN);
	}
	if (reader->strategy == 0) {
		memcpy(account->balance, encoded_balance, BALANCE_LEN);
	} else {
		if (flags & (1 << 5))
			invert(encoded_balance, BALANCE_LEN);
		sum(account->balance, encoded_balance, reader->balance, BALANCE_LEN);
	}

	if (flags & (1 << 1)) {
		byte encoded_code_hash[HASH_LEN];
		read_array(reader, encoded_code_hash, HASH_LEN);
		memcpy(account->codeHash, encoded_code_hash, HASH_LEN);
	} else if (reader->strategy == 0) {
		memset(account->codeHash, 0, HASH_LEN);
	} else {
		memcpy(account->codeHash, reader->code_hash, HASH_LEN);
	}

	uint64_t encoded_nonce;
	if ((flags & (3 << 2)) != (3 << 2)) {
		encoded_nonce = (flags >> 2) & 3;
	} else {
		encoded_nonce = read_u64(reader);
	}

	uint64_t encoded_incarnation;
	if (reader->strategy == 0) {
		if ((flags & (3 << 4)) != (3 << 4)) {
			encoded_incarnation = (flags >> 4) & 3;
		} else {
			encoded_incarnation = read_u64(reader);
		}
	} else {
		if (flags & (1 << 4)) {
			encoded_incarnation = 1;
		} else {
			encoded_incarnation = reader->bytecode_incarnation;
		}
	}

	if (reader->strategy == 0) {
		account->nonce = encoded_nonce;
		account->incarnation = encoded_incarnation;
	} else {
		account->nonce = encoded_nonce + reader->nonce;
		account->incarnation = encoded_incarnation + reader->account_incarnation;
		if (0 && encoded_incarnation >= 3) {
			print_account(account);
			fflush(stdout);
			fprintf(stderr, "Warning: ^ Account with delta incarnation >= 3\n");
			//abort();
		}
	}

	reader->nonce = account->nonce;
	reader->account_incarnation = account->incarnation;
	reader->storage_incarnation = account->incarnation;
	memcpy(reader->balance, account->balance, BALANCE_LEN);
	memcpy(reader->code_hash, account->codeHash, HASH_LEN);

#ifdef SPECIAL_LOG_ADDRESS
	static int special_counter = 0;
	if (special_counter || 0 == memcmp(account->item_base.address, special, ADDRESS_LEN)) {
		if (special_counter == 0)
			special_counter = 10;
		special_counter--;
		printf("Read special case\n");
		print_account(account);
	}
#endif /* SPECIAL_LOG_ADDRESS */
}

static void write_storage(struct Writer *writer, const struct Storage *storage)
{
	writer->count_storage_slots++;
	byte flags = 0;

	if (storage->incarnation == 0 || (int64_t)storage->incarnation < 0) {
		/* These don't occur. */
		print_storage(storage);
		fflush(stdout);
		fprintf(stderr, "Error: ^ Storage with zero or negative incarnation\n");
		abort();
	}

	/*
	 * Because storage incarnation must be >= 1, if
	 * writer->storage_incarnation == 0, treat it as 1 for delta purposes.
	 */
	uint64_t base_incarnation = writer->storage_incarnation;
	if (base_incarnation == 0)
		base_incarnation = 1;
	/*
	 * In storage entries, in the block ranges measured (blocks 10-10.1M),
	 * non-zero `encoded_incarnation` here was extremely rare, just 1 in
	 * 55M (0.0000018%).  This is much rarer than in account entries
	 * because storage is usually preceded by an account entry with the
	 * same incarnation.  So there is no need for efficient encoding of
	 * non-zero values, but it must be supported because
	 * self-destruct+create+sstore sequences can occur the same block.
	 */
	if (storage->incarnation != base_incarnation) {
		if (storage->incarnation < base_incarnation) {
			/*
			 * Just a warning, because the "same-address
			 * incarnation decreasing" has been seen in Goerli
			 * `PlainState`, so perhaps it is acceptable:
			 *
			 * (set address=00000000005eaadadcd5bc0a2c4999980aa8deb8)
			 *   Account block=5636094 address=00000000005eaadadcd5bc0a2c4999980aa8deb8
			 *           inc=4 nonce=1 balance=0 codeHash=6f9335e439a585778643aa1b5759da8241a489df9dbaddf797164a5f0b379ec1
			 *   Storage block=5636094 slot=00000000005eaadadcd5bc0a2c4999980aa8deb8/0000000000000000000000000000000000000000000000000000000000000002
			 *           inc=3 value=40
			 * Warning: Storage with same-address incarnation decreasing
			 *   Storage block=5636094 slot=00000000005eaadadcd5bc0a2c4999980aa8deb8/0000000000000000000000000000000000000000000000000000000000000002
>			 *           inc=3 value=40
			 */
			if (!PRINT)
				print_storage(storage);
			fflush(stdout);
			if (storage->incarnation == 0)
				fprintf(stderr, "Warning: ^ Storage with incarnation == 0\n");
			else
				fprintf(stderr, "Warning: ^ Storage with same-address incarnation decreasing\n");

			if (storage->incarnation == 0)
				exit(EXIT_FAILURE);
		}
		uint64_t encoded_incarnation = storage->incarnation - base_incarnation;
		writer->storage_incarnation = storage->incarnation;

		if (PRINT)
			print_bytecode_incarnation(encoded_incarnation);
		putc(CODE_INCARNATION, writer->file->file);
		write_u64(writer, encoded_incarnation);
	}

	/* Calculate the delta in slot key, minus 1. */
	bool is_new_slot =
		(0 != memcmp(storage->slot, writer->storage_slot, SLOT_LEN));
	byte delta_slot[SLOT_LEN];
	delta(delta_slot, storage->slot, writer->storage_slot, SLOT_LEN);

	/* Figure out whether the slot key or delta uses fewer bytes. */
	int slot_bytes, delta_bytes;
	for (slot_bytes = SLOT_LEN; slot_bytes > 0; slot_bytes--)
		if (storage->slot[SLOT_LEN - slot_bytes] != 0)
			break;
	for (delta_bytes = SLOT_LEN; delta_bytes > 0; delta_bytes--)
		if (delta_slot[SLOT_LEN - delta_bytes] != 0)
			break;
	if (slot_bytes != 1 || storage->slot[SLOT_LEN-1] >= 224)
		slot_bytes++;
	if (delta_bytes != 1 || delta_slot[SLOT_LEN-1] >= 224)
		delta_bytes++;

	/*
	 * Switch to using the delta if it's strictly shorter.  In the block
	 * ranges measured (blocks 10-10.1M), having the choice uses about
	 * 30.6% less space compared with always using delta encoding here.
	 */
	const byte *encoded_slot = &storage->slot[0];
	if (delta_bytes < slot_bytes) {
		encoded_slot = delta_slot;
		slot_bytes = delta_bytes;
		flags |= (1 << 3);
	}

	/* Set the slot key encoding bits in the first byte. */
	if (slot_bytes == 1 && encoded_slot[SLOT_LEN-1] < 9)
		flags |= (encoded_slot[SLOT_LEN-1] << 4);
	else if (slot_bytes < 33)
		flags |= (9 << 4);
	else
		flags |= (10 << 4);

	/*
	 * Set the value encoding bits in the first byte, and figure
	 * out whether the value or its inverse uses fewer bytes.
	 */
	byte encoded_value[VALUE_LEN];
	memcpy(encoded_value, storage->value, VALUE_LEN);
	if (encoded_value[0] <= (byte)0x7f) {
		int value_bytes;
		for (value_bytes = VALUE_LEN; value_bytes > 0; value_bytes--)
			if (encoded_value[VALUE_LEN - value_bytes] != 0)
				break;
		if (value_bytes <= 1 && encoded_value[VALUE_LEN-1] < 6)
			flags |= (encoded_value[VALUE_LEN-1] << 0);
		else
			flags |= (6 << 0);
	} else {
		invert(encoded_value, VALUE_LEN);
		flags |= (7 << 0);
	}

	/* Output the first byte, optional slot or delta, optional value or inverse. */
	if (PRINT)
		print_storage(storage);
	putc(CODE_STORAGE + flags, writer->file->file);

	if ((byte)(flags >> 4) == 9)
		write_number(writer, encoded_slot, SLOT_LEN);
	else if ((byte)(flags >> 4) == 10)
		write_array(writer, encoded_slot, SLOT_LEN);

	if ((flags & (7 << 0)) >= (6 << 0))
		write_number(writer, encoded_value, VALUE_LEN);

	/* New slot resets some other compression values. */
	if (writer->strategy >= 3 && is_new_slot) {
		writer->block = 0;
	}
}

/* Must match `write_storage`. */
static void read_storage(struct Reader *reader, struct Storage *account,
			 byte b)
{
	byte flags = b - CODE_STORAGE;
	struct Storage *storage = &reader->storage;
	*storage = (struct Storage){
		.item_base.is_storage = true,
		.item_base.block = reader->block,
		.incarnation = 0,
		.slot = { 0, },
		.value = { 0, },
	};
	memcpy(storage->item_base.address, reader->address, ADDRESS_LEN);

	storage->incarnation = reader->storage_incarnation;
	if (storage->incarnation == 0)
		storage->incarnation = 1;
	if (reader->bytecode_incarnation != 0)
		storage->incarnation += reader->bytecode_incarnation;

	byte encoded_slot[SLOT_LEN];
	if ((flags >> 4) < 9) {
		memset(encoded_slot, 0, SLOT_LEN);
		encoded_slot[SLOT_LEN-1] = (flags >> 4);
	} else if ((byte)(flags >> 4) == 9) {
		read_number(reader, encoded_slot, SLOT_LEN);
	} else {
		read_array(reader, encoded_slot, SLOT_LEN);
	}

	if (flags & (1 << 3)) {
		sum(storage->slot, encoded_slot, reader->storage_slot, SLOT_LEN);
	} else {
		memcpy(storage->slot, encoded_slot, SLOT_LEN);
	}

	if ((flags & 7) < 6) {
		memset(storage->value, 0, VALUE_LEN);
		storage->value[VALUE_LEN-1] = (flags & 7);
	} else {
		read_number(reader, storage->value, VALUE_LEN);
		if (flags & (1 << 0))
			invert(storage->value, VALUE_LEN);
	}

	bool is_new_slot =
		(0 != memcmp(storage->slot, reader->storage_slot, SLOT_LEN));
	reader->storage_incarnation = storage->incarnation;
	if (reader->strategy >= 3 && is_new_slot) {
		reader->block = 0;
	}
	memcpy(reader->storage_slot, storage->slot, SLOT_LEN);
}

static void write_header(struct Writer *writer, uint64_t file_size)
{
	uint64_t words[16] = { 0, };
	words[0] = 202202111;
	words[1] = file_size;
	words[2] = (sizeof(words) / sizeof(words[0])) * 8;
	words[3] = 12;

	rewind(writer->file->file);
	for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
		byte bytes[8];
		put64be(bytes, words[i]);
		write_array(writer, bytes, sizeof(bytes));
	}
}

/*
 * Parse file input and return the next `Account` or `Storage` item.  There's a
 * loop because it sometimes needs to parse multiple codes in the stream before
 * getting to `Account` or `Storage`.
 *
 * Returns 0 on success and sets `*item_out`, or -1 and sets `errno`.
 *
 * 0 with `*item_out == NULL` is returned on an acceptable end of file, meaning
 * one that doesn't stop the syntax.
 *
 * Error `EINVAL` is used when bad input syntax is found.
 * Error `EIO` is used when `ferror()` indicates a file error or EOF.
 * Error `EINTR` is used when `stop_flag` was set.
 */
static int read_item(struct Reader *reader, bool print, struct ReaderItem **item_out)
{
	FILE *file = reader->file->file;
	bool first_time = true;
	int b;
	reader->bytecode_incarnation = 0;

	while (!stop_flag) {
		/* `feof()` will not return true until this returns EOF. */
		b = getc(file);
		if (b == EOF) {
			/* EOF is only ok before any codes have been read. */
			if (!first_time || ferror(file))
				goto err_syntax;
			*item_out = NULL;
			return 0;
		}
		first_time = false;

		if (b < CODE_BLOCK_NUMBER) {
			goto err_syntax;
		} else if (b <= CODE_BLOCK_NUMBER + 7) {
			read_block_number(reader, &reader->block, b);
			if (feof(file) || ferror(file))
				goto err_file;
			if (print)
				print_block_number(reader->block);
		} else if (b == CODE_ADDRESS) {
			read_address(reader, reader->address);
			if (feof(file) || ferror(file))
				goto err_file;
			if (print)
				print_address(reader->address);
		} else if (b <= CODE_ACCOUNT + 63) {
			struct Account *account = &reader->account;
			read_account(reader, account, b);
			if (feof(file) || ferror(file))
				goto err_syntax;
			if (print)
				print_account(account);
			// Break ouf of the loop and return from this parser function.
			*item_out = &account->item_base;
			return 0;
		} else if (b <= CODE_STORAGE + 160 + 15) {
			struct Storage *storage = &reader->storage;
			read_storage(reader, storage, b);
			if (feof(file) || ferror(file))
				goto err_file;
			if (print)
				print_storage(storage);
			// Break ouf of the loop and return from this parser function.
			*item_out = &storage->item_base;
			return 0;
		} else if (b <= CODE_INCARNATION) {
			reader->bytecode_incarnation = read_u64(reader);
			if (print)
				print_bytecode_incarnation(reader->bytecode_incarnation);
		} else if (b <= CODE_BLOCK_INLINE + 4) {
			read_block_number(reader, &reader->block, b);
			if (feof(file) || ferror(file))
				goto err_file;
			if (print)
				print_block_number(reader->block);
		} else {
			goto err_syntax;
		}
	}
	// `stop_flag` was set.
	errno = EAGAIN;
	return -1;
err_syntax:
	if (ferror(file))
		goto err_file;
	if (b == EOF)
		fprintf(stderr, "Invalid file input: EOF before next item, offset %lld\n",
			(long long)ftello(file));
	else
		fprintf(stderr, "Invalid file input: Byte 0x%02x, offset %lld\n",
			(unsigned)b, (long long)ftello(file) - 1);
	errno = EINVAL;
	return -1;
err_file:
	fprintf(stderr, "Error reading file\n");
	errno = EIO;
	return -1;
}

/*
 * Fetch the block number associated with an Erigon sync stage, which is a
 * string.  For tables `PlainState`, `AccountChangeSet` and `StorageChangeSet`,
 * the relevant stage is "Execution".
 */
static int get_sync_stage(MDBX_env *env, MDBX_txn *txn, const char *stage_name,
			  uint64_t *block)
{
	int rc;
	MDBX_dbi dbi;
	MDBX_val key, value;

	*block = (uint64_t)-1;

	rc = mdbx_dbi_open(txn, "SyncStage", MDBX_DB_ACCEDE, &dbi);
	if (rc != MDBX_SUCCESS) {
		error("mdbx_dbi_open SyncStage", rc);
		goto err;
	}

	key.iov_base = (void *)stage_name;
	key.iov_len = strlen(stage_name);
	rc = mdbx_get(txn, dbi, &key, &value);
	if (rc != MDBX_SUCCESS) {
		error("mdbx_cursor_get MDBX_SET", rc);
		goto err;
	}

	if (value.iov_len != 8) {
		rc = MDBX_INVALID;
		fprintf(stderr, "get(SyncStage, \"%s\") result is not 8 bytes\n",
			stage_name);
		goto err;
	}
	*block = get64be(value.iov_base);
err:
	return rc;
}

/*
 * Scan a range of block numbers and record the account and slot changes during
 * them from the `AccountChangeSet` and `StorageChangeSet` tables.  Annoyingly,
 * the block numbers don't correspond to the first block when the change took
 * effect, so this is not a correct extraction of the account/storage history.
 * But it is about the same size, so good for exercising Nimbus.
 */
static int extract_blockrange(MDBX_env *env, MDBX_txn *txn,
			      uint64_t block_start, uint64_t block_end)
{
	int rc;
	MDBX_dbi dbi_accountCs, dbi_storageCs, dbi_codeHash;
	MDBX_cursor *cursor_accountCs, *cursor_storageCs;
	MDBX_val key_account, data_account, key_storage, data_storage;

	rc = mdbx_dbi_open(txn, "AccountChangeSet", MDBX_DB_ACCEDE, &dbi_accountCs);
	if (rc != MDBX_SUCCESS) {
		error("mdbx_dbi_open AccountChangeSet", rc);
		goto err_dbi_accountCs;
	}
	rc = mdbx_cursor_open(txn, dbi_accountCs, &cursor_accountCs);
	if (rc != MDBX_SUCCESS) {
		error("mdbx_cursor_open AccountChangeSet", rc);
		goto err_cursor_accountCs;
	}
	rc = mdbx_dbi_open(txn, "StorageChangeSet", MDBX_DB_ACCEDE, &dbi_storageCs);
	if (rc != MDBX_SUCCESS) {
		error("mdbx_dbi_open StorageChangeSet", rc);
		goto err_dbi_storageCs;
	}
	rc = mdbx_cursor_open(txn, dbi_storageCs, &cursor_storageCs);
	if (rc != MDBX_SUCCESS) {
		error("mdbx_cursor_open StorageChangeSet", rc);
		goto err_cursor_storageCs;
	}
	rc = mdbx_dbi_open(txn, "PlainCodeHash", MDBX_DB_ACCEDE, &dbi_codeHash);
	if (rc != MDBX_SUCCESS) {
		error("mdbx_dbi_open PlainCodeHash", rc);
		goto err_dbi_codeHash;
	}

	struct File *file = file_open(true, "./data/blocks-%llu-%llu.dat",
				      (unsigned long long)block_start,
				      (unsigned long long)block_end);
	if (!file) {
		rc = MDBX_EIO;
		goto err;
	}
	fprintf(stderr, "Starting extract_blockrange file=%s\n", file->name);

	struct Writer writer;
	writer_init(&writer, file, 0);

	bool first_item = true;
	bool have_account = false, have_storage = false;
	bool done_accounts = false, done_storage = false;

	while (!stop_flag && (!done_accounts || !done_storage)) {
		uint64_t key_block_be;
		if (first_item) {
			put64be((byte *)&key_block_be, block_start);
			key_account.iov_base = (void *)&key_block_be;
			key_account.iov_len = 8;
			key_storage.iov_base = (void *)&key_block_be;
			key_storage.iov_len = 8;
		}
		if (!have_account && !done_accounts) {
			rc = mdbx_cursor_get(cursor_accountCs, &key_account, &data_account,
					     first_item ? MDBX_SET_RANGE : MDBX_NEXT);
			if (rc == MDBX_SUCCESS) {
				have_account = true;
			} else if (rc == MDBX_NOTFOUND) {
				done_accounts = true;
			} else {
				error("mdbx_cursor_get AccountChangeSet", rc);
				goto err;
			}
		}
		if (!have_storage && !done_storage) {
			rc = mdbx_cursor_get(cursor_storageCs, &key_storage, &data_storage,
					     first_item ? MDBX_SET_RANGE : MDBX_NEXT);
			if (rc == MDBX_SUCCESS) {
				have_storage = true;
			} else if (rc == MDBX_NOTFOUND) {
				done_storage = true;
			} else {
				error("mdbx_cursor_get StorageChangeSet", rc);
				goto err;
			}
		}
		first_item = false;

		if (have_account && (key_account.iov_len != 8 || data_account.iov_len < ADDRESS_LEN)) {
			fprintf(stderr, "AccountChangeSet key len != 8 || data len < 20\n");
			print_mdbx_val(&key_account);
			print_mdbx_val(&data_account);
			rc = MDBX_INVALID;
			goto err;
		}
		if (have_storage && (key_storage.iov_len != (BLOCK_LEN + ADDRESS_LEN + INCARNATION_LEN)
				     || data_storage.iov_len < SLOT_LEN
				     || data_storage.iov_len > SLOT_LEN + VALUE_LEN)) {
			fprintf(stderr, "StorageChangeSet key len != 36 || data len < 32 || data len > 64\n");
			print_mdbx_val(&key_storage);
			print_mdbx_val(&data_storage);
			rc = MDBX_INVALID;
			goto err;
		}

		int cmp;
		if (have_account && have_storage) {
			cmp = memcmp(key_account.iov_base, key_storage.iov_base, BLOCK_LEN);
		} else if (have_account) {
			cmp = -1;
		} else if (have_storage) {
			cmp = +1;
		} else {
			break;
		}

		if (cmp == 0) {
			cmp = memcmp(data_account.iov_base,
				     (const byte *)key_storage.iov_base + BLOCK_LEN,  ADDRESS_LEN);
			if (cmp == 0)
				cmp = -1;
		}

		bool is_account = (cmp <= 0);
		uint64_t block = get64be(is_account ? key_account.iov_base : key_storage.iov_base);
		/* `block_end` is inclusive. */
		if (block > block_end)
			break;

		const byte *address = (is_account ? data_account.iov_base
				       : (const byte *)key_storage.iov_base + BLOCK_LEN);

		write_block_number(&writer, block);
		write_address(&writer, address);

		if (is_account) {
			have_account = false;
			struct Account account;
			rc = decode_account((const byte *)data_account.iov_base + ADDRESS_LEN,
					    data_account.iov_len - ADDRESS_LEN,
					    txn, dbi_codeHash, block, address, &account);
			if (rc != MDBX_SUCCESS)
				goto err;
			write_account(&writer, &account);
		} else {
			have_storage = false;
			uint64_t incarnation = get64be((const byte *)key_storage.iov_base + (8 + ADDRESS_LEN));
			struct Storage storage;
			rc = decode_storage((const byte *)data_storage.iov_base,
					    data_storage.iov_len,
					    block, address, incarnation, &storage);
			if (rc != MDBX_SUCCESS)
				goto err;
			write_storage(&writer, &storage);
		}
	}

	fprintf(stderr, "Finished extract_blockrange file=%s -> accounts=%llu storage_slots=%llu\n",
		file->name,
		(unsigned long long)writer.count_accounts,
		(unsigned long long)writer.count_storage_slots);
	rc = MDBX_SUCCESS;
err:
	file_close(file, rc != MDBX_SUCCESS);
err_dbi_codeHash:
	mdbx_cursor_close(cursor_storageCs);
err_cursor_storageCs:
	/* Don't use mdbx_dbi_close: It's neither thread safe nor necessary. */
err_dbi_storageCs:
	mdbx_cursor_close(cursor_accountCs);
err_cursor_accountCs:
	/* Don't use mdbx_dbi_close: It's neither thread safe nor necessary. */
err_dbi_accountCs:
	return rc;
}

/*
 * Extract the "PlainState" data, which contains account and storage values for
 * `block`.
 *
 * Note: If this might run concurrently with Erigon, the block number _must_
 * be the value from the "SyncStage" table, key "Execution", _in the same
 * transaction (`txn`)_ as "PlainState" is read, otherwise the data is invalid.
 */
static int extract_plainstate(MDBX_env *env, MDBX_txn *txn, uint64_t block)
{
	int rc;
	MDBX_dbi dbi_plainState, dbi_codeHash;
	MDBX_cursor *cursor_plainState;
	MDBX_val key_plainState, data_plainState;

	rc = mdbx_dbi_open(txn, "PlainState", MDBX_DB_ACCEDE, &dbi_plainState);
	if (rc != MDBX_SUCCESS) {
		error("mdbx_dbi_open PlainState", rc);
		goto err_dbi_plainState;
	}
	rc = mdbx_cursor_open(txn, dbi_plainState, &cursor_plainState);
	if (rc != MDBX_SUCCESS) {
		error("mdbx_cursor_open PlainState", rc);
		goto err_cursor_plainState;
	}
	rc = mdbx_dbi_open(txn, "PlainCodeHash", MDBX_DB_ACCEDE, &dbi_codeHash);
	if (rc != MDBX_SUCCESS) {
		error("mdbx_dbi_open PlainCodeHash", rc);
		goto err_dbi_codeHash;
	}

	struct File *file = file_open(true, "./data/plainstate-%llu.dat",
				      (unsigned long long)block);
	if (!file) {
		rc = MDBX_EIO;
		goto err;
	}
	fprintf(stderr, "Starting extract_plainstate file=%s\n", file->name);

	struct Writer writer;
	// Strategy 0 is smaller than strategy 1 for plainstate.
	writer_init(&writer, file, 0);

	bool first_time = true;

	while (!stop_flag) {
		rc = mdbx_cursor_get(cursor_plainState, &key_plainState, &data_plainState,
				     first_time ? MDBX_FIRST : MDBX_NEXT);
		if (rc == MDBX_SUCCESS) {
			first_time = false;
		} else if (rc == MDBX_NOTFOUND) {
			break;
		} else {
			error("mdbx_cursor_get PlainState", rc);
			goto err;
		}

		if (key_plainState.iov_len != ADDRESS_LEN
		    && key_plainState.iov_len != ADDRESS_LEN + INCARNATION_LEN) {
			fprintf(stderr, "PlainState key len != 20 && key len != 28\n");
			print_mdbx_val(&key_plainState);
			print_mdbx_val(&data_plainState);
			rc = MDBX_INVALID;
			goto err;
		}
		if (key_plainState.iov_len != ADDRESS_LEN
		    && (data_plainState.iov_len < SLOT_LEN
			|| data_plainState.iov_len > SLOT_LEN + VALUE_LEN)) {
			fprintf(stderr, "PlainState key len == 28 && (data len < 32 || data len > 64)\n");
			print_mdbx_val(&key_plainState);
			print_mdbx_val(&data_plainState);
			rc = MDBX_INVALID;
			goto err;
		}

#if 0
		if (*(const byte *)key_plainState.iov_base >= 0x05)
			break;
#endif

		bool is_account = key_plainState.iov_len == ADDRESS_LEN;
		const byte *address = key_plainState.iov_base;

		write_block_number(&writer, block);
		write_address(&writer, address);

		if (is_account) {
			struct Account account;
			rc = decode_account((const byte *)data_plainState.iov_base,
					    data_plainState.iov_len,
					    txn, dbi_codeHash, block, address, &account);
			if (rc != MDBX_SUCCESS)
				goto err;
			write_account(&writer, &account);
		} else {
			uint64_t incarnation = get64be((const byte *)key_plainState.iov_base + ADDRESS_LEN);
			struct Storage storage;
			rc = decode_storage((const byte *)data_plainState.iov_base,
					    data_plainState.iov_len,
					    block, address, incarnation, &storage);
			if (rc != MDBX_SUCCESS)
				goto err;
			write_storage(&writer, &storage);
		}
	}

	fprintf(stderr, "Finished extract_plainstate file=%s -> accounts=%llu storage_slots=%llu\n",
		file->name,
		(unsigned long long)writer.count_accounts,
		(unsigned long long)writer.count_storage_slots);
	rc = MDBX_SUCCESS;
err:
	file_close(file, rc != MDBX_SUCCESS);
err_dbi_codeHash:
	mdbx_cursor_close(cursor_plainState);
err_cursor_plainState:
err_dbi_plainState:
	return rc;
}

/*
 * Extract all the block bodies, which are mainly transactions, and a few bytes
 * of uncle data.
 *
 * This version extracts duplicate block numbers (with different hashes) if
 * they are present, rather than filtering to the canonical chain blocks.
 * Duplicate blocks numbers appear in clusters surprisingly far in the past.
 * Those are not useful, and incorrect if the reader is assuming these blocks
 * form a single chain, so the non-canonical blocks should be filtered out.
 *
 * These are called `txbodies` because they are almost entirely transactions,
 * and `txbodies` is visually distinct and easier to do file name completion
 * with than `blocks`, when used alongside other files also called `blocks`.
 */
static int extract_txbodies(MDBX_env *v, MDBX_txn *txn,
			    uint64_t block_start, uint64_t block_end)
{
	int rc;
	MDBX_dbi dbi_blockBody, dbi_blockTransaction;
	MDBX_cursor *cursor_blockBody, *cursor_blockTransaction;
	MDBX_val key_blockBody, data_blockBody;

	rc = mdbx_dbi_open(txn, "BlockBody", MDBX_ACCEDE, &dbi_blockBody);
	if (rc != MDBX_SUCCESS) {
		error("mdbx_dbi_open BlockBody", rc);
		goto err_dbi_blockBody;
	}
	rc = mdbx_cursor_open(txn, dbi_blockBody, &cursor_blockBody);
	if (rc != MDBX_SUCCESS) {
		error("mdbx_cursor_open BlockBody", rc);
		goto err_cursor_blockBody;
	}
	rc = mdbx_dbi_open(txn, "BlockTransaction", MDBX_ACCEDE, &dbi_blockTransaction);
	if (rc != MDBX_SUCCESS) {
		error("mdbx_dbi_open BlockTransaction", rc);
		goto err_dbi_blockTransaction;
	}
	rc = mdbx_cursor_open(txn, dbi_blockTransaction, &cursor_blockTransaction);
	if (rc != MDBX_SUCCESS) {
		error("mdbx_cursor_open BlockTransaction", rc);
		goto err_cursor_blockTransaction;
	}

	struct File *file = file_open(true, "./data/txbodies-%llu-%llu.dat",
				      (unsigned long long)block_start,
				      (unsigned long long)block_end);
	if (!file) {
		rc = MDBX_EIO;
		goto err;
	}
	fprintf(stderr, "Starting extract_txbodies file=%s\n", file->name);

	struct Writer writer;
	writer_init(&writer, file, 0);

	bool first_time = true;
	uint64_t block_count = 0, tx_count = 0, total_size = 0;
	uint64_t block_expected = block_start, block_dups = 0;

	while (!stop_flag) {
		uint64_t key_block_be;
		if (first_time) {
			put64be((byte *)&key_block_be, block_start);
			key_blockBody.iov_base = (void *)&key_block_be;
			key_blockBody.iov_len = 8;
		}
		rc = mdbx_cursor_get(cursor_blockBody,
				     &key_blockBody, &data_blockBody,
				     first_time ? MDBX_SET_RANGE : MDBX_NEXT);
		if (rc != MDBX_SUCCESS) {
			if (rc == MDBX_NOTFOUND)
				break;
			error("mdbx_cursor_get BlockBody", rc);
			goto err;
		}
		first_time = false;

		if (key_blockBody.iov_len != 8 + 32) {
			fprintf(stderr, "BlockBody key len != 8 + 32\n");
			print_mdbx_val(&key_blockBody);
			print_mdbx_val(&data_blockBody);
			rc = MDBX_INVALID;
			goto err;
		}

		uint64_t block = get64be((const byte *)key_blockBody.iov_base);
		/* `block_end` is inclusive. */
		if (block > block_end)
			break;
		if (block != block_expected) {
			if (block_expected != block_start
			    && block == block_expected - 1) {
				/*
				 * Duplicate block numbers with different
				 * hashes occur in the data, surprisingly far
				 * into the past.
				 */
				block_expected -= 1;
				block_dups++;
			} else {
				fprintf(stderr, "BlockBody next block %llu != expected %llu\n",
					(unsigned long long)block,
					(unsigned long long)(block_start + block_count));
				rc = MDBX_INVALID;
				goto err;
			}
		}
		block_expected++;
		block_count++;

		uint64_t tx_index, tx_amount;

		/*
		 * The `BlockBody` entry is an RLP encoded list: [tx_index,
		 * tx_amount, [uncles]].  We won't parse the RLP carefully, or
		 * even correctly.  In particular there are no bounds checks
		 * here.  Just extract what we need, assuming it is correct.
		 */
		const byte *rlp_base = (const byte *)data_blockBody.iov_base;
		const byte *rlp = rlp_base;
		size_t rlp_len = data_blockBody.iov_len;
		if (rlp_len < 4)
			goto err_syntax_blockBody;

		/* Decode RLP list header. */
		if (*rlp < 0xc3)
			goto err_syntax_blockBody;
		size_t list_len = *rlp - 0xc0;
		if (*rlp >= 0xf8) {
			size_t len_len = *rlp - 0xf7;
			list_len = 0;
			while (len_len-- > 0)
				list_len = (list_len << 8) | *++rlp;
		}
		rlp++;

		/* Decode RLP tx_index number. */
		if (*rlp <= 0x7f) {
			tx_index = *rlp;
		} else if (*rlp > 0x88) {
			goto err_syntax_blockBody;
		} else {
			size_t num_len = *rlp - 0x80;
			tx_index = 0;
			while (num_len-- > 0)
				tx_index = (tx_index << 8) | *++rlp;
		}
		rlp++;

		/* Decode RLP tx_amount number. */
		if (*rlp <= 0x7f) {
			tx_amount = *rlp;
		} else if (*rlp > 0x88) {
			goto err_syntax_blockBody;
		} else {
			size_t num_len = *rlp - 0x80;
			tx_amount = 0;
			while (num_len-- > 0)
				tx_amount = (tx_amount << 8) | *++rlp;
		}
		rlp++;

		/* Write block number, transaction count and uncles. */
		write_u64(&writer, block);
		write_u64(&writer, tx_amount);
		size_t uncles_len = rlp_len - (rlp - rlp_base);
		write_u64(&writer, uncles_len);
		write_array(&writer, rlp, uncles_len);

		/* Write transactions. */
		bool first_tx_in_block = true;
		for (; tx_amount != 0; tx_index++, tx_amount--) {
			MDBX_val key_blockTransaction, data_blockTransaction;
			uint64_t key_tx_index_be;
			if (first_tx_in_block) {
				put64be((byte *)&key_tx_index_be, tx_index);
				key_blockTransaction.iov_base = (void *)&key_tx_index_be;
				key_blockTransaction.iov_len = 8;
			}
			rc = mdbx_cursor_get(cursor_blockTransaction,
					     &key_blockTransaction, &data_blockTransaction,
					     first_tx_in_block ? MDBX_SET : MDBX_NEXT);
			if (rc != MDBX_SUCCESS) {
				error("mdbx_cursor_get BlockTransaction", rc);
				goto err;
			}
			first_tx_in_block = false;

			uint64_t key_tx_index = get64be((const byte *)key_blockTransaction.iov_base);
			if (key_tx_index != tx_index) {
				fprintf(stderr, "BlockTransaction next tx_index %llu != expected %llu\n",
					(unsigned long long)key_tx_index,
					(unsigned long long)tx_index);
				rc = MDBX_INVALID;
				goto err;
			}

			size_t tx_len = data_blockTransaction.iov_len;
			tx_count++;
			total_size += tx_len;
			write_u64(&writer, tx_len);
			write_array(&writer, data_blockTransaction.iov_base, tx_len);
		}
	}

	fprintf(stderr, "Finished extract_txbodies file=%s, blocks=%llu, dups=%llu, txs=%llu, total_size=%llu\n",
		file->name, (unsigned long long)block_count,
		(unsigned long long)block_dups,
		(unsigned long long)tx_count,
		(unsigned long long)total_size);
	rc = MDBX_SUCCESS;
err:
	file_close(file, rc != MDBX_SUCCESS);
	mdbx_cursor_close(cursor_blockTransaction);
err_cursor_blockTransaction:
err_dbi_blockTransaction:
	mdbx_cursor_close(cursor_blockBody);
err_cursor_blockBody:
err_dbi_blockBody:
	return rc;
err_syntax_blockBody:
	fprintf(stderr, "BlockBody value syntax error\n");
	print_mdbx_val(&key_blockBody);
	print_mdbx_val(&data_blockBody);
	rc = MDBX_INVALID;
	goto err;
}

/*
 * Read and display an encoded file of accounts and storages.  This is used to
 * see what's in there, and to test that the ad-hoc format parser.
 *
 * It shows order and details of each item encounted, i.e. block numbers,
 * addresses, accounts, storage etc.
 *
 * The printed output should be identical to the formatted output if `PRINT`
 * was set when generating that file, and this can be used to verify that the
 * reader decoding logic matches the writer encoding logic.
 */
static int show_file(int strategy, const char *filename)
{
	int rc;
	struct File *file = file_open(false, "%s", filename);
	if (!file) {
		rc = MDBX_EIO;
		goto err;
	}
	fprintf(stderr, "Starting show_file file=%s\n", file->name);

	struct Reader reader;
	reader_init(&reader, file, strategy);

	while (!stop_flag) {
		print_file_offset(ftello(reader.file->file));
		struct ReaderItem *item;
		if (read_item(&reader, true, &item) != 0) {
			if (stop_flag)
				break;
			rc = (errno == EINVAL) ? MDBX_INVALID : MDBX_EIO;
			goto err;
		} else if (!item) {
			break;
		}
	}

	fprintf(stderr, "Finished show_file file=%s\n", file->name);
	rc = MDBX_SUCCESS;
err:
	file_close(file, false);
	return rc;
}

/*
 * Read and write an encoded file of accounts and storages.  This is used to
 * verify that the ad-hoc format parser (`read_account` etc) correctly matches
 * the ad-hoc format writer (`write_account` etc) on real data.
 */
static int copy_file(int strategy_in, int strategy_out,
		     const char *filename_in, const char *filename_out)
{
	int rc;
	struct File *file_in = NULL, *file_out = NULL;

	file_in = file_open(false, "./data/%s", filename_in);
	if (!file_in)
		goto err_file;

	file_out = file_open(true, "./data/%s", filename_out);
	if (!file_out)
		goto err_file;

	fprintf(stderr, "Starting copy_file file_in=%s file_out=%s\n",
		file_in->name, file_out->name);

	struct Reader reader;
	reader_init(&reader, file_in, strategy_in);

	struct Writer writer;
	writer_init(&writer, file_out, strategy_out);

	while (!stop_flag) {
		struct ReaderItem *item;
		if (read_item(&reader, false, &item) != 0) {
			if (stop_flag)
				break;
			rc = (errno == EINVAL) ? MDBX_INVALID : MDBX_EIO;
			goto err;
		} else if (!item) {
			break;
		}

		if (strategy_out == 0) {
			write_block_number(&writer, item->block);
			write_address(&writer, item->address);
		} else {
			write_address(&writer, item->address);
			write_block_number(&writer, item->block);
		}

		if (!item->is_storage) {
			write_account(&writer, (const struct Account *)item);
		} else {
			write_storage(&writer, (const struct Storage *)item);
		}
	}

	fprintf(stderr, "Finished copy_file file_in=%s file_out=%s -> accounts=%llu storage_slots=%llu\n",
		file_in->name, file_out->name,
		(unsigned long long)writer.count_accounts,
		(unsigned long long)writer.count_storage_slots);
	rc = MDBX_SUCCESS;
err:
	file_close(file_out, rc != MDBX_SUCCESS);
	file_close(file_in, false);
	return rc;
err_file:
	rc = MDBX_EIO;
	goto err;
}

static int transpose_sort_order(const void *arg1, const void *arg2)
{
	struct ReaderItem *item1 = *(struct ReaderItem **)arg1;
	struct ReaderItem *item2 = *(struct ReaderItem **)arg2;
	int cmp = memcmp(item1->address, item2->address, ADDRESS_LEN);
	if (cmp == 0 && (item1->is_storage || item2->is_storage)) {
		if (!item1->is_storage)
			cmp = -1;
		else if (!item2->is_storage)
			cmp = +1;
		else {
			struct Storage *storage1 = (struct Storage *)item1;
			struct Storage *storage2 = (struct Storage *)item2;
			cmp = memcmp(storage1->slot, storage2->slot, SLOT_LEN);
		}
	}
	if (cmp == 0) {
		cmp = (item1->block < item2->block ? -1
		       : item1->block > item2->block ? +1 : 0);
	}
	if (cmp == 0) {
		if (!item1->is_storage)
			print_account((struct Account *)item1);
		else
			print_storage((struct Storage *)item1);
		if (!item2->is_storage)
			print_account((struct Account *)item2);
		else
			print_storage((struct Storage *)item2);
		fprintf(stderr, "Warning: ^^ Two equal keys\n");
		/* The data should never contain duplicate keys. */
		abort();
	}
	return cmp;
}

static int transpose_blockrange(uint64_t block_start, uint64_t block_end)
{
	int rc;
	struct File *file_in = NULL, *file_out = NULL;
	size_t vector_len = 0, vector_cap = 0;
	struct ReaderItem **vector_data = NULL;

	file_in = file_open(false, "./data/blocks-%llu-%llu.dat",
			    (unsigned long long)block_start,
			    (unsigned long long)block_end);
	if (!file_in)
		goto err_file;
	fprintf(stderr, "Starting transpose_blockrange file_in=%s\n", file_in->name);

	struct Reader reader;
	reader_init(&reader, file_in, 0);

	while (!stop_flag) {
		struct ReaderItem *item;
		if (read_item(&reader, false, &item) != 0) {
			if (stop_flag)
				break;
			rc = (errno == EINVAL) ? MDBX_INVALID : MDBX_EIO;
			goto err;
		} else if (!item) {
			break;
		}

		/* `block_end` is inclusive. */
		if (item->block < block_start || item->block > block_end) {
			fprintf(stderr, "Warning: ^ Transpose input read block %llu, out of range %llu..%llu\n",
				(unsigned long long)item->block,
				(unsigned long long)block_start,
				(unsigned long long)block_end);
			/* Abort because there's definitely a bug if this happens. */
			abort();
		}

		size_t item_copy_size =
			item->is_storage ? sizeof(struct Storage) : sizeof(struct Account);
		void *item_copy = malloc(item_copy_size);
		if (!item_copy)
			goto err_nomem;
		memcpy(item_copy, item, item_copy_size);

		if (vector_len == vector_cap) {
			vector_cap = vector_cap > 0 ? 2*vector_cap : 256;
			void **new_data = realloc(vector_data, vector_cap * sizeof(*vector_data));
			if (!new_data)
				goto err_nomem;
			vector_data = (struct ReaderItem **)new_data;
		}
		vector_data[vector_len] = item_copy;
		vector_len++;
	}
	if (stop_flag)
		goto done;

	fprintf(stderr, "Sorting in transpose_blockrange file_in=%s\n", file_in->name);
	qsort(vector_data, vector_len, sizeof(*vector_data), transpose_sort_order);

	file_out = file_open(true, "./data/transposed-%llu-%llu.dat",
			     (unsigned long long)block_start,
			     (unsigned long long)block_end);
	if (!file_out)
		goto err_file;
	fprintf(stderr, "Writing in transpose_blockrange file_out=%s\n", file_out->name);

	struct Writer writer;
	writer_init(&writer, file_out, 1);

	for (size_t i = 0; i < vector_len && !stop_flag; i++) {
		struct ReaderItem *item = vector_data[i];
		/* Write address first, so all block deltas work including the first. */
		write_address(&writer, item->address);
		write_block_number(&writer, item->block);
		if (!item->is_storage) {
			write_account(&writer, (const struct Account *)item);
		} else {
			write_storage(&writer, (const struct Storage *)item);
		}
	}

done:
	fprintf(stderr, "Finished transpose_blockrange file_in=%s\n", file_in->name);
	rc = MDBX_SUCCESS;
err:
	file_close(file_out, rc != MDBX_SUCCESS);
	file_close(file_in, false);
	if (vector_data) {
		for (size_t i = 0; i < vector_len; i++)
			free(vector_data[i]);
		free(vector_data);
	}
	return rc;
err_nomem:
	rc = MDBX_ENOMEM;
	goto err;
err_file:
	rc = MDBX_EIO;
	goto err;
}

static int merge_files(const char *filename1, const char *filename_plain,
		       const char *filename_out)
{
	//filename_plain = NULL;
	//filename1 = NULL;

	int rc;
	int num_inputs = 2;
	struct MergeInput {
		struct File *file;
		struct Reader reader;
		struct ReaderItem *item;
		bool ended, is_plain;
	};
	struct MergeInput *inputs = NULL;
	struct File *file_out = NULL;
	struct Writer writer;

	inputs = malloc(sizeof(struct MergeInput) * num_inputs);
	if (!inputs)
		goto err_nomem;
	for (int i = 0; i < num_inputs; i++) {
		struct MergeInput *input = &inputs[i];
		input->file = NULL;
		input->item = NULL;
		input->ended = false;
		input->is_plain = (i == num_inputs - 1);
	}

	file_out = file_open(true, "./data/%s", filename_out);
	if (!file_out)
		goto err_file;
	writer_init(&writer, file_out, 1);

	for (int i = 0; i < num_inputs; i++) {
		struct MergeInput *input = &inputs[i];
		const char *filename =
			input->is_plain ? filename_plain : filename1;
		if (!filename)
			continue;
		input->file = file_open(false, "./data/%s", filename);
		if (!input->file)
			goto err_file;
		reader_init(&input->reader, input->file,
			    input->is_plain ? 0 : 1);
		fprintf(stderr, "Starting merge_files file_in=%s (%d of %d) file_out=%s\n",
			input->file->name, i + 1, num_inputs, file_out->name);
	}

	bool have_address = false, have_slot = false;
	byte current_address[ADDRESS_LEN];
	byte current_slot[SLOT_LEN];
	uint64_t next_block_change = 0;

	uint64_t input_counts[2] = { 0, 0 };
	while (!stop_flag) {
		for (int i = 0; i < num_inputs; i++) {
			struct MergeInput *input = &inputs[i];
			if (input->item || input->ended || !input->file)
				continue;
			if (read_item(&input->reader, false, &input->item) != 0) {
				if (stop_flag)
					break;
				rc = (errno == EINVAL) ? MDBX_INVALID : MDBX_EIO;
				goto err;
			}
			/*
			 * Add +1 to `PlainState` block so that the comparison
			 * function works.  All the transposed files have
			 * entries up to block=N which are the state _before_
			 * executing block N, but `PlainState` has entries at
			 * block=N which are the state _after_ executing the
			 * block.  Logically we should -1 all the transposed
			 * files, but they contain block=0 entries and the type
			 * is unsigned. We have to adjust the block nubmers
			 * before writing anyway, so +1 is helpful here.
			 */
			if (!input->item)
				input->ended = true;
			else if (input->is_plain)
				input->item->block++;
		}

		int lowest_item_index = -1;
		for (int i = 0; i < num_inputs; i++) {
			struct MergeInput *input = &inputs[i];
			if (!input->item)
				continue;
			if (lowest_item_index < 0
			    || transpose_sort_order(&input->item,
						    &inputs[lowest_item_index].item) < 0) {
				lowest_item_index = i;
			}
		}

		if (lowest_item_index < 0)
			break;

		struct MergeInput *input = &inputs[lowest_item_index];
		struct ReaderItem *item = input->item;
		input->item = NULL;
		input_counts[lowest_item_index]++;

		bool same_address_and_slot = true;
		if (!have_address
		    || 0 != memcmp(current_address, item->address, ADDRESS_LEN)) {
			memcpy(current_address, item->address, ADDRESS_LEN);
			have_address = true;
			same_address_and_slot = false;
		}
		if (!item->is_storage) {
			have_slot = false;
		} else if (!have_slot
			   || 0 != memcmp(current_slot, ((struct Storage *)item)->slot, SLOT_LEN)) {
			memcpy(current_slot, ((struct Storage *)item)->slot, SLOT_LEN);
			have_slot = true;
			same_address_and_slot = false;
		}

		uint64_t adjusted_block = same_address_and_slot ? next_block_change : 0;
		next_block_change = item->block;
		item->block = adjusted_block;

		/* There must be a 1 block step forward minimum. */
		if (adjusted_block >= next_block_change) {
			/* Genesis entries don't need to be written. */
			if (adjusted_block == 0)
				continue;
			if (!item->is_storage)
				print_account((struct Account *)item);
			else
				print_storage((struct Storage *)item);
			fflush(stdout);
			fprintf(stderr, "Warning: ^ Adjusted block number has not moved backward\n");
			//abort();
		}

		/* Write address first, so all block deltas work including the first. */
		write_address(&writer, item->address);
		write_block_number(&writer, item->block);
		if (!item->is_storage) {
			write_account(&writer, (const struct Account *)item);
		} else {
			write_storage(&writer, (const struct Storage *)item);
		}
	}

	assert(inputs[0].item == NULL);
	assert(inputs[1].item == NULL);

	fprintf(stderr, "Finished merge_files (%d) file_out=%s -> read=%llu+%llu accounts=%llu storage_slots=%llu\n",
		num_inputs, file_out->name,
		(unsigned long long)input_counts[0],
		(unsigned long long)input_counts[1],
		(unsigned long long)writer.count_accounts,
		(unsigned long long)writer.count_storage_slots);
	rc = MDBX_SUCCESS;
err:
	file_close(file_out, rc != MDBX_SUCCESS);
	for (int i = 0; i < num_inputs; i++) {
		if (inputs[i].file)
			file_close(inputs[i].file, false);
	}
	return rc;
err_nomem:
	rc = MDBX_ENOMEM;
	goto err;
err_file:
	rc = MDBX_EIO;
	goto err;
}

struct Job {
	pthread_t thread;
	uint64_t range_start, range_end;
	MDBX_env *env;
	MDBX_txn *txn;
	int (*fn)(MDBX_env *env, MDBX_txn *txn,
		  uint64_t range_start, uint64_t range_end);
};

static pthread_mutex_t jobs_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  jobs_cond  = PTHREAD_COND_INITIALIZER;
static int             jobs_count = 0;

static void job_allocate(int max_concurrent)
{
	pthread_mutex_lock(&jobs_mutex);
	while (jobs_count >= max_concurrent)
		pthread_cond_wait(&jobs_cond, &jobs_mutex);
	++jobs_count;
	pthread_mutex_unlock(&jobs_mutex);
}

static void job_completed(void)
{
	pthread_mutex_lock(&jobs_mutex);
	--jobs_count;
	pthread_mutex_unlock(&jobs_mutex);
	pthread_cond_signal(&jobs_cond);
}

static void jobs_wait_finish(void)
{
	job_allocate(1);
}

static void *job_run(void *arg)
{
	struct Job *job = arg;
	MDBX_txn *txn = job->txn;
	if (txn != NULL) {
		job->fn(job->env, txn, job->range_start, job->range_end);
	} else {
		int rc = mdbx_txn_begin(job->env, NULL, MDBX_TXN_RDONLY, &txn);
		if (rc != MDBX_SUCCESS) {
			error("mdbx_txn_begin", rc);
		} else {
			job->fn(job->env, txn, job->range_start, job->range_end);
			mdbx_txn_abort(txn);
		}
	}
	job_completed();
	free(job);
	return NULL;
}

static int jobs_run_multithread(MDBX_env *env, MDBX_txn *txn_only_if_shared,
				uint64_t range_start, uint64_t range_end,
				uint64_t range_step, int max_concurrent,
				int (*fn)(MDBX_env *env, MDBX_txn *txn,
					  uint64_t range_start,
					  uint64_t range_end))
{
	while (!stop_flag && range_start < range_end) {
		job_allocate(max_concurrent);

		uint64_t end = range_start + range_step;
		if (end > range_end)
			end = range_end;

		struct Job *job = malloc(sizeof(*job));
		job->range_start = range_start;
		job->range_end = end;
		range_start = end;
		job->env = env;
		job->txn = txn_only_if_shared;
		job->fn = fn;
		pthread_create(&job->thread, NULL, job_run, job);
	}
	return MDBX_SUCCESS;
}

static int extract_blockrange_multithread(MDBX_env *env, MDBX_txn *txn,
					  uint64_t block_start, uint64_t block_end)
{
	return jobs_run_multithread(env, NULL, block_start, block_end,
				    100000, 64, extract_blockrange);
}

static int equal_or_greater(const MDBX_val *a, const MDBX_val *b) {
  return (a->iov_len == b->iov_len &&
          memcmp(a->iov_base, b->iov_base, a->iov_len) == 0)
             ? 0
             : 1;
}

static void show_usage(void)
{
	fprintf(stderr,
		"Usage: %s [OPTIONS] </path/to/erigon/chaindata>\n"
		"Options:\n"
		"-q    Don't output some messages\n"
		"-p    Print accounts and storages as they are written\n"
		"-s    Show contents of a file instead of doing transformations\n"
		"-S    Like -S but for files with strategy 1\n"
		"-T    Like -S but for files with strategy 3\n",
		prog);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
	bool opt_show = false;
	int opt_strategy = 0;

	prog = argv[0];
	if (argc < 2)
		show_usage();

	int ch;
	while ((ch = getopt(argc, argv, "qpsST")) != EOF) {
		switch (ch) {
		case 'q':
			opt_verbose = false;
			break;
		case 'p':
			opt_print = true;
			break;
		case 's':
			opt_show = true;
			break;
		case 'S':
			opt_show = true;
			opt_strategy = 1;
			break;
		case 'T':
			opt_show = true;
			opt_strategy = 1;
			break;
		default:
			show_usage();
		}
	}

	if (optind != argc - 1)
		show_usage();

	setup_signal_handler();

	const char *input_db_path = argv[optind];

	if (opt_show) {
		int rc = show_file(opt_strategy, input_db_path);
		if (rc == MDBX_NOTFOUND)
			rc = MDBX_SUCCESS;
		if (rc == MDBX_EINTR && opt_verbose)
			fprintf(stderr, "Interrupted by signal/user\n");
		return rc ? EXIT_FAILURE : EXIT_SUCCESS;
	}

	MDBX_env *env;
	int rc = mdbx_env_create(&env);
	if (rc != MDBX_SUCCESS) {
		error("mdbx_env_create", rc);
		return EXIT_FAILURE;
	}

	/*
	 * The number of dbis is the maximum number of tables allowed to be
	 * accessed while this file is open, even if they are not at the same
	 * time.  (dbis are never closed).
	 *
	 * We need 7 dbis: `SyncStage`, `AccountChangeSet`, `StorageChangeSet`,
	 *`PlainCodeHash`, `PlainState`, `BlockBody`, `BlockTransaction`.  Add
	 * some extra so we're not confused when we use open another.
	 */
	rc = mdbx_env_set_maxdbs(env, 15);
	if (rc != MDBX_SUCCESS) {
		error("mdbx_env_set_maxdbs", rc);
		goto env_close;
	}

	// `MDBX_NORDAHEAD`: Disabling readahead reduces wasted use of kernel
	// cache RAM when reading very large files.  This helps cacheability
	// when reading archive mode DBs, and when reading relatively small
	// tables from very large MDBX files.  Like B-trees generally, MDBX
	// files are heavily fragmented internally, so the pages for a small
	// table become scattered all over the large file space.  So any tables
	// read and up taking a lot more RAM cache than necessary, and the
	// effect of that during repeated runs is more important than potential
	// benefits from readahead.
	rc = mdbx_env_open(env, input_db_path, MDBX_RDONLY | MDBX_NORDAHEAD, 0);
	if (rc != MDBX_SUCCESS) {
		error("mdbx_env_open", rc);
		goto env_close;
	}

	MDBX_txn *txn;
	rc = mdbx_txn_begin(env, NULL, MDBX_TXN_RDONLY, &txn);
	if (rc != MDBX_SUCCESS) {
		error("mdbx_txn_begin", rc);
		goto env_close;
	}

	uint64_t latest_block = (uint64_t)-1;
	rc = get_sync_stage(env, txn, "Execution", &latest_block);
	if (rc != MDBX_SUCCESS)
		goto txn_abort;
	printf("Reading block range 0 to %llu\n", (unsigned long long)latest_block);

#if 1
	/*
	 * Operations scaled for Goerli.  Simpler than Mainnet.  We don't need
	 * many parallel operations, or to transpose via intermediate files,
	 * because the intermedia state fits in the server's RAM.
	 */
	//rc = extract_blockrange(env, txn, latest_block - 100000, latest_block);
	//rc = transpose_blockrange(latest_block - 100000, latest_block);
	//rc = extract_blockrange(env, txn, 0, latest_block);
	//rc = transpose_blockrange(0, latest_block);
	//rc = extract_plainstate(env, txn, latest_block);
	rc = merge_files("transposed-0-5636094.dat", "plainstate-5636094.dat", "goerli-full-history-5636094.dat");
	//rc = copy_file(0, 0, "blocks-0-5636094.dat", "blocks-0-5636094-2.dat");
	//rc = copy_file(1, 3, "transposed-0-5636094.dat", "transposed-0-5636094-2.dat");
	//rc = copy_file(0, 0, "plainstate-5636094.dat", "plainstate-5636094-2.dat");
	//rc = copy_file(1, 1, "goerli-full-history-5636094.dat", "goerli-full-history-5636094-2.dat");
	//rc = extract_txbodies(env, txn, 0, latest_block);
	//rc = extract_blockrange(env, txn, 4000000, 4100000);
	//rc = copy_file(0, 0, "blocks-4000000-4099999.dat", "blocks-4000000-4099999-2.dat");
	//rc = transpose_blockrange(4000000, 4100000);
	//rc = copy_file(1, 1, "transposed-4000000-4099999.dat", "transposed-4000000-4099999-2.dat");
	//rc = copy_file(1, 1, "transposed-4000000-4099999-2.dat", "transposed-4000000-4099999-3.dat");
#else
	//rc = extract_txbodies(env, txn, 0, 100000);
	//rc = extract_txbodies(env, txn, 0, latest_block);
	//rc = jobs_run_multithread(env, NULL, 0, latest_block, 100000, 64, extract_txbodies);

	//rc = extract_blockrange(env, txn, 13520000, 14005000);
//	rc = extract_blockrange(env, txn, 5000000, 13807650);
	//rc = extract_blockrange_multithread(env, txn, 8000000, 8300000);
	//rc = extract_blockrange_multithread(env, txn, 13000000, 13100000);
	//rc = extract_blockrange_multithread(env, txn, 13800000, latest_block);
	//rc = extract_blockrange_multithread(env, txn, 0, latest_block);
	//rc = extract_plainstate(env, txn, latest_block);
	//rc = show_file("./data/blocks-plainstate-13818907.dat", true);
	//rc = show_file("./data/blocks-13800000-13818906.dat", true);
	//rc = transpose_blockrange(100000, 200000);
	//rc = show_file("./data/blocks-100000-199999.dat");
	//rc = show_file("./data/transposed-100000-199999.dat");
	//rc = extract_blockrange(env, txn, 10094500, 10100000);
	//rc = transpose_blockrange(10000000, 10100000);
	//rc = show_file("./data/blocks-10000000-10099999.dat");
	//rc = show_file("./data/transposed-10000000-10099999.dat");
#endif

	if (rc == MDBX_NOTFOUND)
		rc = MDBX_SUCCESS;
	if (rc == MDBX_EINTR && opt_verbose)
		fprintf(stderr, "Interrupted by signal/user\n");

	jobs_wait_finish();

txn_abort:
	mdbx_txn_abort(txn);
env_close:
	mdbx_env_close(env);

	return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
