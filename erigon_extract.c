/* mdbx_dump.c - memory-mapped database dump tool */

/*
 * Copyright 2015-2021 Leonid Yuriev <leo@yuriev.ru>
 * and other libmdbx authors: please see AUTHORS file.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>. */

#ifdef _MSC_VER
#if _MSC_VER > 1800
#pragma warning(disable : 4464) /* relative include path contains '..' */
#endif
#pragma warning(disable : 4996) /* The POSIX name is deprecated... */
#endif                          /* _MSC_VER (warnings) */

#define xMDBX_TOOLS /* Avoid using internal mdbx_assert() */
//#include "internals.h"
#include "mdbx.h"

#include <ctype.h>
#include <stdarg.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(_WIN32) || defined(_WIN64)
#include "libmdbx/src/wingetopt.h"

static volatile BOOL user_break;
static BOOL WINAPI ConsoleBreakHandlerRoutine(DWORD dwCtrlType) {
  (void)dwCtrlType;
  user_break = true;
  return true;
}

#else /* WINDOWS */

static volatile sig_atomic_t user_break;
static void signal_handler(int sig) {
  (void)sig;
  user_break = 1;
}

#endif /* !WINDOWS */

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

static void print_mdbx_val(MDBX_val *v) {
	putchar(' ');
	print_bytes(v->iov_base, 0, v->iov_len);
	putchar('\n');
}

bool quiet = false;
const char *prog;

#define PRINT 0
#define CODE_BLOCK_NUMBER 1  /* Range 1..8        */
#define CODE_ADDRESS      9  /* Single value 9    */
#define CODE_ACCOUNT      10 /* Range 10..73      */
#define CODE_STORAGE      74 /* Range 74..249     */
#define CODE_INCARNATION  250 /* Single value 250 */
#define CODE_BLOCK_INLINE 251 /* Range 251..255   */

static void error(const char *func, int rc) {
	if (!quiet)
		fprintf(stderr, "%s: %s() error %d %s\n", prog, func, rc,
			mdbx_strerror(rc));
}

static uint64_t get64be(const byte *bytes) {
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

static void put64be(byte *bytes, uint64_t value) {
	*bytes++ = (byte)(value >> 56);
	*bytes++ = (byte)(value >> 48);
	*bytes++ = (byte)(value >> 40);
	*bytes++ = (byte)(value >> 32);
	*bytes++ = (byte)(value >> 24);
	*bytes++ = (byte)(value >> 16);
	*bytes++ = (byte)(value >> 8);
	*bytes++ = (byte)value;
}

static uint64_t get64be_len(const byte *bytes, size_t len) {
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
	bool is_storage;
	byte address[ADDRESS_LEN];
	uint64_t block;
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
	bool have_block, have_address;
	uint64_t block, nonce, account_incarnation, storage_incarnation;
	byte address[ADDRESS_LEN];
	byte balance[BALANCE_LEN];
	byte code_hash[HASH_LEN];
	byte slot[SLOT_LEN];
	uint64_t count_accounts, count_slots;
	int strategy;
};

static void writer_init(struct Writer *writer, struct File *file)
{
	writer->file = file;
	writer->have_block = false;
	writer->have_address = false;
	writer->block = 0;
	writer->account_incarnation = 0;
	writer->storage_incarnation = 0;
	memset(writer->address, 0, ADDRESS_LEN);
	memset(writer->balance, 0, BALANCE_LEN);
	memset(writer->code_hash, 0, HASH_LEN);
	memset(writer->slot, 0, SLOT_LEN);
	writer->count_accounts = 0;
	writer->count_slots = 0;
	writer->strategy = 0;
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

static void write_u64(struct Writer *writer, uint64_t value)
{
	byte bytes[8];
	put64be(bytes, value);
	write_number(writer, bytes, sizeof(bytes));
}

static void write_array(struct Writer *writer, const byte *bytes, size_t len)
{
	FILE *file = writer->file->file;
	for (size_t i = 0; i < len; i++)
		putc(bytes[i], file);
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

static void delta(byte *delta_out, const byte *value_in, byte *accumulator, size_t len)
{
	for (int i = len-1, borrow = 1; i >= 0; i--) {
		int delta = (int)value_in[i] - (int)accumulator[i] - borrow;
		accumulator[i] = value_in[i];
		borrow = delta < 0;
		delta_out[i] = (byte)delta;
	}
}

static void invert(byte *bytes, size_t len)
{
	for (int i = 0; i < (int)len; i++)
		bytes[i] = ~bytes[i];
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

static void write_account(struct Writer *writer, const struct Account *account)
{
	writer->count_accounts++;

	if (PRINT)
		print_account(account);

	/* Nonce delta encoding alone saves ~1.5% of storage. */
	uint64_t encoded_nonce, encoded_incarnation;
	if (writer->strategy == 0) {
		encoded_nonce = account->nonce;
		encoded_incarnation = account->incarnation;
	} else {
		encoded_nonce = account->nonce - writer->nonce;
		encoded_incarnation = account->incarnation - writer->account_incarnation;
		if (encoded_incarnation >= 3)
			abort();
		writer->nonce = account->nonce;
	}
	/* `write_storage` uses incarnation reference with strategy == 0 too. */
	writer->account_incarnation = account->incarnation;
	writer->storage_incarnation = account->incarnation;

	byte flags = 0;

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

	if (0 != memcmp(account->balance, zero_balance, VALUE_LEN))
		flags |= 1;
	if (0 != memcmp(account->codeHash, zero_code_hash, HASH_LEN)
	    && 0 != memcmp(account->codeHash, empty_code_hash, HASH_LEN)) {
		flags |= 2;
	}

	const byte *encoded_code_hash = (flags & 2) ? account->codeHash : zero_code_hash;
	/*
	 * At block 10094566, there is a self-destruct, create, sstore on
	 * account 000000000000006f6502b7f2bbac8c30a3f67e9a.  It has the effect
	 * of pairing an inc=1 account entry (from before the self-destruct)
	 * with inc=2 storage entries (from before the sstore).  Later at block
	 * 10094587, the balance changes which adds the inc=2 account entry for
	 * the create at 10094566.  The sequence when address is the primary
	 * order, and account/state updates as at last-block-number:
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
	 */
	if (encoded_incarnation == 0 && writer->strategy >= 1) {
		if (0 != memcmp(writer->code_hash, encoded_code_hash, HASH_LEN)) {
			fprintf(stderr, "Change of code hash with no change of incarnation\n");
			print_account(account);
			abort();
		}
		flags &= ~2;
	} else {
		memcpy(writer->code_hash, encoded_code_hash, HASH_LEN);
	}

	if (encoded_nonce >= 3)
		flags |= (3 << 2);
	else
		flags |= (byte)encoded_nonce << 2;

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
			putc(CODE_INCARNATION, writer->file->file);
			write_u64(writer, encoded_incarnation);
		}
	}

	putc(CODE_ACCOUNT + flags, writer->file->file);
	if (flags & 1)
		write_number(writer, encoded_balance, VALUE_LEN);
	if (flags & 2)
		write_array(writer, account->codeHash, HASH_LEN);
	if ((flags & (3 << 2)) == (3 << 2))
		write_u64(writer, encoded_nonce);
#if 1
	if ((flags & (3 << 4)) == (3 << 4))
		write_u64(writer, encoded_incarnation);
#endif
}

static void write_storage(struct Writer *writer, const struct Storage *storage)
{
	writer->count_slots++;

	if (PRINT)
		print_storage(storage);

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
			if (storage->incarnation == 0)
				fprintf(stderr, "Error: Storage with incarnation == 0\n");
			else
				fprintf(stderr, "Error: Storage with same-address incarnation decreasing\n");
			print_storage(storage);
			exit(EXIT_FAILURE);
		}
		uint64_t encoded_incarnation = storage->incarnation - base_incarnation;
		writer->storage_incarnation = storage->incarnation;
		putc(CODE_INCARNATION, writer->file->file);
		write_u64(writer, encoded_incarnation);
	}

	byte flags = 0;

	/* Calculate the delta in slot key, minus 1. */
	byte delta_slot[SLOT_LEN];
	delta(delta_slot, storage->slot, writer->slot, SLOT_LEN);

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
	const byte *slot = &storage->slot[0];
	if (1 || delta_bytes < slot_bytes) {
		slot = delta_slot;
		slot_bytes = delta_bytes;
		flags |= (1 << 3);
	}

	/* Set the slot key encoding bits in the first byte. */
	if (slot_bytes == 1 && slot[SLOT_LEN-1] < 9)
		flags |= (slot[SLOT_LEN-1] << 4);
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
	if (encoded_value[0] >= (byte)0x80) {
		invert(encoded_value, VALUE_LEN);
		flags |= (6 << 0);
	} else {
		int value_bytes;
		for (value_bytes = VALUE_LEN; value_bytes > 0; value_bytes--)
			if (encoded_value[VALUE_LEN - value_bytes] != 0)
				break;
		if (value_bytes <= 1 && encoded_value[VALUE_LEN-1] < 6)
			flags |= (encoded_value[VALUE_LEN-1] << 0);
		else
			flags |= (7 << 0);
	}

	/* Output the first byte, optional slot or delta, optional value or inverse. */
	putc(CODE_STORAGE + flags, writer->file->file);

	if ((byte)(flags >> 4) == 9)
		write_number(writer, slot, SLOT_LEN);
	else if ((byte)(flags >> 4) == 10)
		write_array(writer, slot, SLOT_LEN);

	if ((flags & (7 << 0)) >= (6 << 0))
		write_number(writer, encoded_value, VALUE_LEN);
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

	struct File *file = file_open(true, "./data/blocks-x-%llu-%llu.dat",
				      (unsigned long long)block_start,
				      (unsigned long long)(block_end - 1));
	if (!file) {
		rc = MDBX_EIO;
		goto err;
	}
	fprintf(stderr, "Starting extract_blockrange file=%s\n", file->name);

	struct Writer writer;
	writer_init(&writer, file);

	bool first_item = true;
	bool have_account = false, have_storage = false;
	bool done_accounts = false, done_storage = false;

	while (!user_break && (!done_accounts || !done_storage)) {
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
		if (block >= block_end)
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

	fprintf(stderr, "Finished extract_blockrange file=%s accounts=%llu slots=%llu\n",
		file->name, (unsigned long long)writer.count_accounts,
		(unsigned long long)writer.count_slots);
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

	struct File *file = file_open(true, "./data/blocks-plainstate-%llu.dat",
				      (unsigned long long)block);
	if (!file) {
		rc = MDBX_EIO;
		goto err;
	}
	fprintf(stderr, "Starting extract_plainstate file=%s\n", file->name);

	struct Writer writer;
	writer_init(&writer, file);

	bool first_time = true;

	while (!user_break) {
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

	fprintf(stderr, "Finished extract_plainstate file=%s accounts=%llu slots=%llu\n",
		file->name, (unsigned long long)writer.count_accounts,
		(unsigned long long)writer.count_slots);
	rc = MDBX_SUCCESS;
err:
	file_close(file, rc != MDBX_SUCCESS);
err_dbi_codeHash:
	mdbx_cursor_close(cursor_plainState);
err_cursor_plainState:
err_dbi_plainState:
	return rc;
}

struct Reader {
	struct File *file;
	uint64_t block, incarnation;
	byte address[ADDRESS_LEN], slot[SLOT_LEN];
	union {
		struct Account account;
		struct Storage storage;
	};
};

static void reader_init(struct Reader *reader, struct File *file)
{
	reader->file = file;
	reader->block = 0;
	reader->incarnation = 0;
	memset(reader->address, 0, sizeof(reader->address));
	memset(reader->slot, 0, sizeof(reader->slot));
}

static void read_array(struct Reader *reader, byte *array, size_t len)
{
	FILE *file = reader->file->file;
	for (size_t i = 0; i < len; i++)
		array[i] = getc(file);
}

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

static uint64_t read_u64(struct Reader *reader)
{
	byte bytes[8];
	read_number(reader, bytes, 8);
	return get64be(bytes);
}

/*
 * Parse file input and return the next `Account` or `Storage` item.  There's a
 * loop because it sometimes needs to parse multiple codes in the stream before
 * getting to `Account` or `Storage`.
 *
 * Returns 0 on success and sets `*item_out`, or -1 and sets `errno`.
 *
 * 0 with `*item_out == NULL` is returned on an acceptable end of file, meaning
 * one that doesn't interrupt the syntax.
 *
 * Error `EINVAL` is used when bad input syntax is found.
 * Error `EIO` is used when `ferror()` indicates a file error or EOF.
 * Error `EINTR` is used when `user_break` was set.
 */
static int read_item(struct Reader *reader, bool print, struct ReaderItem **item_out)
{
	FILE *file = reader->file->file;
	bool first_time = true;
	int b;

	while (!user_break) {
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
			int len = (int)(b - CODE_BLOCK_NUMBER + 1);
			reader->block = 0;
			for (int i = 0; i < len; i++)
				reader->block = (reader->block << 8) + getc(file);
			if (feof(file) || ferror(file))
				goto err_file;
			if (print)
				print_block_number(reader->block);
		} else if (b == CODE_ADDRESS) {
			read_array(reader, reader->address, ADDRESS_LEN);
			if (feof(file) || ferror(file))
				goto err_file;
			if (print)
				print_address(reader->address);
		} else if (b <= CODE_ACCOUNT + 63) {
			byte flags = b - CODE_ACCOUNT;
			struct Account *account = &reader->account;
			*account = (struct Account){
				.item_base.is_storage = false,
				.item_base.block = reader->block,
				.nonce = 0,
				.incarnation = 0,
				.balance = { 0, },
				.codeHash = { 0, },
			};
			memcpy(account->item_base.address, reader->address, ADDRESS_LEN);

			if (flags & 1)
				read_number(reader, account->balance, VALUE_LEN);
			if (flags & 2)
				read_array(reader, account->codeHash, HASH_LEN);
			if ((flags & (3 << 2)) == (3 << 2)) {
				account->nonce = read_u64(reader);
			} else {
				account->nonce = ((flags >> 2) & 3);
			}
			if ((flags & (3 << 4)) == (3 << 4)) {
				account->incarnation = read_u64(reader);
			} else {
				account->incarnation = ((flags >> 4) & 3);
			}
			if (account->incarnation != 0)
				reader->incarnation = account->incarnation;
			if (feof(file) || ferror(file))
				goto err_syntax;
			if (print)
				print_account(account);
			// Break ouf of the loop and return from this parser function.
			*item_out = &account->item_base;
			return 0;
		} else if (b <= CODE_STORAGE + 160 + 15) {
			byte flags = b - CODE_STORAGE;
			struct Storage *storage = &reader->storage;
			*storage = (struct Storage){
				.item_base.is_storage = true,
				.item_base.block = reader->block,
				.incarnation = reader->incarnation,
			};
			memcpy(storage->item_base.address, reader->address, ADDRESS_LEN);

			if ((flags >> 4) < 9) {
				memset(storage->slot, 0, SLOT_LEN);
				storage->slot[SLOT_LEN-1] = (flags >> 4);
			} else if ((byte)(flags >> 4) == 9) {
				read_number(reader, storage->slot, SLOT_LEN);
			} else {
				read_array(reader, storage->slot, SLOT_LEN);
			}

			if (flags & (1 << 3)) {
				for (int i = SLOT_LEN - 1, carry = 1; i >= 0; i--) {
					int delta = (int)reader->slot[i] + (int)storage->slot[i] + carry;
					carry = delta >= 256;
					storage->slot[i] = (byte)delta;
				}
			}
			memcpy(reader->slot, storage->slot, SLOT_LEN);

			if ((flags & 7) < 6) {
				memset(storage->value, 0, sizeof(storage->value));
				storage->value[VALUE_LEN-1] = (flags & 7);
			} else {
				read_number(reader, storage->value, VALUE_LEN);
				if ((flags & 7) == 6) {
					for (int i = 0; i < VALUE_LEN; i++)
						storage->value[i] = (byte)(~storage->value[i]);
				}
			}

			if (feof(file) || ferror(file))
				goto err_file;
			if (print)
				print_storage(storage);
			// Break ouf of the loop and return from this parser function.
			*item_out = &storage->item_base;
			return 0;
		} else if (b <= CODE_INCARNATION + 4) {
			if (b - CODE_INCARNATION < 4)
				reader->incarnation = b - CODE_INCARNATION + 1;
			else
				reader->incarnation = read_u64(reader);
		} else {
			goto err_syntax;
		}
	}
	// `user_break` was set.
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

static int show_file(const char *filename)
{
	int rc;
	struct File *file = file_open(false, "%s", filename);
	if (!file) {
		rc = MDBX_EIO;
		goto err;
	}
	fprintf(stderr, "Starting show_file file=%s\n", file->name);

	struct Reader reader;
	reader_init(&reader, file);

	while (!user_break) {
		struct ReaderItem *item;
		if (read_item(&reader, true, &item) != 0) {
			if (user_break)
				break;
			rc = (errno == EINVAL) ? MDBX_INVALID : MDBX_EIO;
			goto err;
		} else if (!item) {
			break;
		}
	}

done:
	rc = MDBX_SUCCESS;
err:
	file_close(file, false);
	return rc;
}

static int transpose_sort_order(const void *arg1, const void *arg2)
{
	struct ReaderItem *item1 = *(struct ReaderItem **)arg1;
	struct ReaderItem *item2 = *(struct ReaderItem **)arg2;
	int cmp = memcmp(item1->address, item2->address, ADDRESS_LEN);
	if (cmp == 0) {
		cmp = (item1->block < item2->block ? -1
		       : item1->block > item2->block ? +1 : 0);
	}
	if (1 && cmp == 0 && (item1->is_storage || item2->is_storage)) {
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
			    (unsigned long long)(block_end - 1));
	if (!file_in)
		goto err_file;

	fprintf(stderr, "Starting transpose_blockrange file_in=%s\n", file_in->name);

	struct Reader reader;
	reader_init(&reader, file_in);

	while (!user_break) {
		struct ReaderItem *item;
		if (read_item(&reader, false, &item) != 0) {
			if (user_break)
				break;
			rc = (errno == EINVAL) ? MDBX_INVALID : MDBX_EIO;
			goto err;
		} else if (!item) {
			break;
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
	if (user_break)
		goto done;

	fprintf(stderr, "Sorting in transpose_blockrange file_in=%s\n", file_in->name);
	qsort(vector_data, vector_len, sizeof(*vector_data), transpose_sort_order);

	file_out = file_open(true, "./data/transposed-%llu-%llu.dat",
			     (unsigned long long)block_start,
			     (unsigned long long)(block_end - 1));
	if (!file_out)
		goto err_file;
	fprintf(stderr, "Writing in transpose_blockrange file_out=%s\n", file_out->name);

	struct Writer writer;
	writer_init(&writer, file_out);
	writer.strategy = 1;

	for (size_t i = 0; i < vector_len && !user_break; i++) {
		struct ReaderItem *item = vector_data[i];
		/* Write address first, so all block deltas work including the first. */
		write_address(&writer, item->address);
		write_block_number(&writer, item->block);
		if (!item->is_storage)
			write_account(&writer, (const struct Account *)item);
		else
			write_storage(&writer, (const struct Storage *)item);
	}

done:
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
	while (!user_break && range_start < range_end) {
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

static void usage(void) {
  fprintf(stderr,
          "usage: %s [-V] [-q] [-f file] [-l] [-p] [-r] [-a|-s subdb] "
          "dbpath\n"
          "  -V\t\tprint version and exit\n"
          "  -q\t\tbe quiet\n"
          "  -f\t\twrite to file instead of stdout\n"
          "  -l\t\tlist subDBs and exit\n"
          "  -s name\tdump only the specified named subDB\n"
          "  \t\tby default dump only the main DB\n",
          prog);
  exit(EXIT_FAILURE);
}

static int equal_or_greater(const MDBX_val *a, const MDBX_val *b) {
  return (a->iov_len == b->iov_len &&
          memcmp(a->iov_base, b->iov_base, a->iov_len) == 0)
             ? 0
             : 1;
}

int main(int argc, char *argv[]) {
	int i, rc;
	MDBX_env *env;
	MDBX_txn *txn;
	prog = argv[0];
	char *envname;
	unsigned envflags = 0;
	bool list = false;

	if (argc < 2)
		usage();

	while ((i = getopt(argc, argv,
			   "f:"
			   "l"
			   "n"
			   "V"
			   "q")) != EOF) {
		switch (i) {
		case 'V':
			printf("mdbx_dump version %d.%d.%d.%d\n"
			       " - source: %s %s, commit %s, tree %s\n"
			       " - build: %s for %s by %s\n"
			       " - flags: %s\n"
			       " - options: %s\n",
			       mdbx_version.major, mdbx_version.minor, mdbx_version.release,
			       mdbx_version.revision, mdbx_version.git.describe,
			       mdbx_version.git.datetime, mdbx_version.git.commit,
			       mdbx_version.git.tree, mdbx_build.datetime,
			       mdbx_build.target, mdbx_build.compiler, mdbx_build.flags,
			       mdbx_build.options);
			return EXIT_SUCCESS;
		case 'l':
			list = true;
			/*FALLTHROUGH*/;
			//__fallthrough;
		case 'f':
			if (freopen(optarg, "w", stdout) == NULL) {
				fprintf(stderr, "%s: %s: reopen: %s\n", prog, optarg,
					mdbx_strerror(errno));
				exit(EXIT_FAILURE);
			}
			break;
		case 'n':
			break;
		case 'q':
			quiet = true;
			break;
		default:
			usage();
		}
	}

	if (optind != argc - 1)
		usage();

#if defined(_WIN32) || defined(_WIN64)
	SetConsoleCtrlHandler(ConsoleBreakHandlerRoutine, true);
#else
#ifdef SIGPIPE
	signal(SIGPIPE, signal_handler);
#endif
#ifdef SIGHUP
	signal(SIGHUP, signal_handler);
#endif
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
#endif /* !WINDOWS */

	envname = argv[optind];
	if (!quiet) {
		fprintf(stderr, "mdbx_dump %s (%s, T-%s)\nRunning for %s...\n",
			mdbx_version.git.describe, mdbx_version.git.datetime,
			mdbx_version.git.tree, envname);
		fflush(NULL);
	}

	rc = mdbx_env_create(&env);
	if (rc != MDBX_SUCCESS) {
		error("mdbx_env_create", rc);
		return EXIT_FAILURE;
	}

	// Need 5 dbis: `SyncStage`, `AccountChangeSet`, `StorageChangeSet`,
	// `PlainCodeHash` and `PlainState`.
	rc = mdbx_env_set_maxdbs(env, 5);
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
	rc = mdbx_env_open(env, envname, envflags | MDBX_RDONLY | MDBX_NORDAHEAD, 0);
	if (rc != MDBX_SUCCESS) {
		error("mdbx_env_open", rc);
		goto env_close;
	}

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

	if (rc == MDBX_NOTFOUND)
		rc = MDBX_SUCCESS;
	if (rc == MDBX_EINTR && !quiet)
		fprintf(stderr, "Interrupted by signal/user\n");

	jobs_wait_finish();

txn_abort:
	mdbx_txn_abort(txn);
env_close:
	mdbx_env_close(env);

	return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
