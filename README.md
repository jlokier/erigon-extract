# Super-compact "archive mode" state history for Ethereum Mainnet

## Size headline figures

**Mainnet Ethereum "archive mode" state history in 167.47&nbsp;GiB**.
(Blocks 0 to 13818907.  The final block is dated 2021-12-16 22:38:47 UTC).

This compares extremely favourably\* with [8,646&nbsp;GiB and 8,719&nbsp;GiB
(charts)](https://etherscan.io/chartsync/chainarchive) used by popular
implementations Geth and OpenEthereum respectively at the same time frame.

It's a profound improvement over [22,911&nbsp;GiB for
Nimbus-eth1](https://github.com/status-im/nimbus-eth1/issues/863)
(=&nbsp;24.6&nbsp;TB), which this approach to storage was designed to address.

\* Note that those Etherscan charts show space used by other things than just
state-history, but state-history accounts for almost all of that space.  To
finish the comparison, minimum required Merkle hashes, block bodies, block
headers, contract code and receipts must be added.  Some more space on top is
required in an actively updated database.  Some experiments have been done and
there are good reasons to believe all those things can be fitted in less than
420&nbsp;GiB more "estimated worst case".

## Pruned size

"Pruned mode" state history comes to **25.03&nbsp;GiB**.  (Blocks
13728908-13818907, 90k history).

This also compares favourably\* with [pruned mode
charts](https://etherscan.io/chartsync/chaindefault), but the picture is more
complicated with pruned state, as the other things contribute more
significantly to the size in those charts.  Even so, the pruned state size is
promising.

## Lookup performance

Any account or storage can be looked up at any point in block time in O(log N)
time using these files.  This proof of concept is focused more on demonstrating
small size than time, so the constant factor of the big-O notation is quite
high, but when fully optimised the constant factor will be superbly low for
IOPS, and reasonable for CPU and memory.

## Summary of this program

This program makes a compact version of the entire Ethereum Mainnet state
history, sometimes called "archive mode".

It reads the state history from a database made by
[Erigon](https://github.com/ledgerwatch/erigon), and outputs a new,
super-compact database.

The new format is both a compressed file and a database, and can be used
directly as full archive data set.  Even though it looks too simple to be
updated efficiently, it actually can be updated in place with the right
algorithms: It really is a prepopulated database as well as a compressed file.
Both reads (queries) and writes (updates) take O(log N) time.O(log N) time.

## Space first, speed second

This is a proof of concept designed to highlight space used, rather than time.

The super-compact database is part of an implementation in progress of an
on-disk data structure designed to be fast as well, for Ethereum use cases.
Specifically, fast at random-access writes for EVM execution, and fast with low
write-amplification for network state synchronisation.  It is neither a B-tree
nor an LSM-tree but has elements of both.

However the current implementation iss not a particularly fast O(log N).  The
time constant needs to be improved, and the number of I/O operations (IOPS) is
also higher than necessary.

R&D is ongoing in improving the format and in the query and update algorithms.
It's likely the size will increase as critical features and performance
metadata are added.

Speed will improve greatly when index blocks and structures inside each block
are added to improve the performance.  With those in place, the IOPS will drop
to less than 1 IOPS per account/storage query on average, during EVM executions,
even at Mainnet archive scale.

The structure is also designed to support fast network sync, and to store the
received data efficiently without write-amplification.

The ad-hoc encoding of individual values has been through many iterations to
optimise the assignment of bits and opcodes to different purposes, but there
are several changes to add which have been identified.  These reduce the size
further, but the index structures to speed up reads and writes will likely take
more than the amount saved by better compression.

## How to use this program

You will need:

- **At least 75 GiB of unused RAM** to run the Mainnet conversion
- **At least 750 GB free disk space**
- An Erigon instance that has been synced up to Mainnet and then stopped

It's possible to read from the Erigon database without stopping Erigon, but
that's not recommended as it will rapidly and permanently inflate the size of
Erigon's database, and when it reaches 2.1TB, Erigon cannot function any more
and stops working.

After building `libmdbx` do:

```sh
make

# Or symbolic link to your preferred location:
mkdir data

# Use the path to Erigon's `chaindata` directory.  `-M` is important,
# otherwise it will take a very long time to run on Mainnet:
./erigon_extract -M ~/.erigon/mainnet/chaindata
```

Then wait a while.  On my system it takes a couple of hours.

The final output file is called something like
`./data/full-history-0-13818907.dat` for Mainnet at block number 13818907.

That file contains the entire "archive mode" accounts and storage history from
blocks 0 up to that block number.

**Mainnet full history currently takes 167.47&nbsp;GiB**.

Other networks can also be used, and the starting block can be changed by
editing the code.  A "pruned mode" 90k blocks file can be generated using the
`-P` option.  **Mainnet pruned to 90k blocks currently takes 25.03&nbsp;GiB.**

The data format has been tested more with Goerli testnet than Mainnet at this
point, but there is no reason to think they are different except for scale.
**The Goerli archive mode file is 10.6&nbsp;GiB**, and **Goerli pruned is
3.18&nbsp;GiB**.

## Summary

This program is to do a large, one-off ETL ("extract, transform, load")
pipeline of the entire Ethereum (eth1) state history archive, extracting from
the database of a fully sync'd Erigon instance, and writing the data in a
compact and transposed format, to be imported to
[Nimbus-eth1](https://github.com/status-im/nimbus-eth1).

It converts what takes about 9-10 TB in most implementations (Geth etc), down
to _less than 200 GB_ currently.  That is only the full account and storage
slot history, which have been tackled as they are the tricky part, as much for
performance (speed) as space.

Temporary space of about 1 TB will be required.

To be fair, much of the legwork is done here by Erigon.  However the data
transposition and field skipping & compression steps are key to reducing the
size further.

Because this code was intended as "quick" temporary scaffolding, and to gather
hard data on size and performance, until
[Nimbus-eth1](https://github.com/status-im/nimbus-eth1) can generate the data
directly by writing to the database itself.  So it is rather ad-hoc, and has
been edited repeatedly to iterate one transform to the next.  Some source
editing is required to use it.

## Data sizes

The 200 GB output size is for the full archive history of accounts and storage
slots.  Actually the size is smaller, but it's changing as encoding parameters
and sort order are adjusted.  200 GB will do as an upper bound.

It does not include Merkle hashes, block headers and transactions, receipts or
code.  Each of those except the Merkle hashes is relatively simple and doesn't
need exploratory research the same way.  We know how to handle them already.

We have an upper bound on all those items of approximately 450 GB without
compression.

The block transactions (bodies) come to about 330 GB uncompressed.  Testing a
variety of compression methods I found they can be compressed by about 50%, so
165 GB.  The time to compress and decompress is not significant for individual
blocks, but it should be taken into account for bulk sync on fast networks.

Layout out of the Merkle hashes is its own interesting problem.  It makes more
sense to generate and verify those in the final packing (using 13.5 million
parallel Merkle accumulators), than to extract them, because they are not all
required.  These are intimately connected to the sync algorithm.

When not holding the entire Ethereum archive, if instead the account/storage
history is pruned and proposal
[EIP-4444](https://eips.ethereum.org/EIPS/eip-4444) is adopted, these figures
reduce by a factor of apprximately 4, perhaps more.  The pruned version has not
been investigated much, as the goal here is to show something more impressive:
The full archive is known to be very large.

When queryable and updatable structures are added, to make the files into a
database with suitable performance, a size increase in the 200 GB part of
roughly +50% should be expected.  Same for the 70 GB (estimated) of Merkle
hashes.  This is a combination of tree structure data (block pointers etc), and
some fragmentation which is required when a sorted key-value table is updated
efficiently.  This is an estimate, and the implementation must be completed to
get a more accurate measure.

## Projected total size

The above brings the projected total size for Ethereum archive mode state in an
active DB to roughly 620 GB, and in a read-only format to roughly 485 GB.
That's for 13.5 million blocks in December 2021.

Compare this to roughly [9.6 TB for Geth and
OpenEthereum](https://etherscan.io/chartsync/chainarchive), 1.5-1.6 TB for
Erigon at the current time, and a whopping 24.6 TB for
[Nimbus-eth1](https://github.com/status-im/nimbus-eth1).  (All around mid
December 2021).

A projected size for Ethereum pruned mode is not known yet, but it is loosely
estimated as 443 GB including blocks etc.

## Data representation

The representation here, parameters, opcode bytes etc. have been explored a
number of ways to get the size down.  Not least because the conversion process
is so slow and takes a lot of space, that's motivation by itself!

The encoding is tuned for a number of things, but it is not the "final" format.
Specifically, it does not contain structural metadata to support fast queries
and updates.

If you don't know where this work is heading, it is likely to look like just
another large, serialised data file.  But in fact it isn't.  Only a few more
fields are needed to turn it into a database as well, supporting the types of
queries and updates used in the Ethereum execution and sync processes.  These
fields are inter-block key-pointers, which give the file a tree structure
similar to a "buffered B-tree", and intra-block skip-forwards to speed up
queries in spite of the compression.

The ad-hoc encoding was designed "quickly" for the ETL pipeline, and it turned
out to be easily tweakable, which improved ETL speed and helped get a good
early bound on data size.  However, search-compatible entropy coding is planned
and in some ways simpler.  Thanks to information theory, it gets the same or
better results by adjusting numbers on a continuum, instead of the ad-hoc
encoding/decoding logic.  Especially for mostly-0 or mostly-1 flags.

## Space performance

In pursuing the ad-hoc encoding shown here, it has yielded useful data about
the encoding that is appropriate in the real thing, and *most usefully, a rough
upper bound on the size of the DB*.

## Query performance

I have worked out expected IOPS per random-access read query to accounts and
storage slots.  It comes to be about 1/2 to 1/3 of the IOPS used by Erigon
during contract executions, and a smaller fraction of the IOPS used by Geth for
account/storage queries.

## Relationship to database

This ETL output looks like a set of "compressed" files using an ad-hoc method
(field update opcodes etc), but in fact this is a few steps short of a
fast-queryable (and updateable) database, which efficiently supports each of
the operations needed by an Ethereum node.

What is missing from this output is structural metadata that supports fast
queries and updates.

The final encoding steps, first to make a read-only queryable version of the
file, then an updateable version, are to be completed in Nim.

This is because the final encoding steps are almost identical to the code which
is required for updating the database at run-time, and have quite a bit of
detail; there is no point implementing it twice.

For write queries, estimating IOPS it is fairly complex, both because writes
can be optimised differently than reads, and because the Merkle hashes must be
queried and updated.  It is better to simply implement and measure.  However
the design theory says how to expect them to scale.

It is because the Merkle hashes multiply up the amount of I/O required that we
must take advantage of write optimisations available, instead of treating
writes similarly to read queries and counting on O() dominance.

Write IOPS are expected to be more LSM-like or B-tree-like, depending on the
type of access.  In Ethereum, execution and syncing (using Nimbus-eth1's
storage-efficient hybrid sync algorithm) uses very different types of write
patterns.  Neither an LSM-tree or B-tree provide good performance for both
kinds; the target structure does.

The target structure (the encoding this code is for) is efficient at both kinds
of write.  It is called "Bubble Tree", but unfortunately there are no published
papers at this time describing the technique.  Its relevant claims for the
Ethereum storage problem are that it performs fast, random-access writes (like
an LSM-tree; used for contract execution) simultaneous with fast bulk range
updates (like a B-tree; used for syncing), does not have large spikes in I/O or
large spikes in storage space requirement, does not rely critically on
filesystem allocation performance, gradually orders data into a shape that is
good for sequential access, compacts away holes, and supports some amount
prefix- and field-compression between related entries.  All these are useful
for Ethereum storage, to reduce space and perform the necessary operations
efficiently.  The structure is also surprisingly simple, once understood.
