## Summary

This program is to do a large, one-off ETL ("extract, transform,
load") pipeline of the entire Ethereum (eth1) state history archive,
extracting from the database of a fully sync'd Erigon instance, and
writing the data in a compact and transposed format.

It converts what takes almost 9 TB in most implementations (Geth etc),
down to less than 200 GB currently.  That is only the full account and
storage slot history, which have been tackled as they are the tricky
part, as much for performance (speed) as space.

Temporary space of about 1 TB will be required.

To be fair, much of the legwork is done here by Erigon, which squeezes
this state data into a few hundred GB.  However the data transposition and
field skipping & compression steps are key.

The 200 GB size does not include Merkle hashes, block headers and
transactions, or receipts.  Each of those is relatively simple and
doesn't need exploratory research the same way.  We know how to handle
them already.

Because this code was intended as "quick" temporary scaffolding, and
to gather hard data on size and performance, until Nimbus-eth1 can
generate the data directly by writing to the database itself.  So it
is rather ad-hoc, and has been edited repeatedly to iterate one
transform to the next.

## Data representation

The representation here, parameters, opcode bytes etc. have been
explored a number of ways to get the size down.  Not least because the
conversion process is so slow and takes a lot of space, that's
motivation by itself!

The encoding is tuned for a number of things, but it is not the
"final" format.  Specifically, it does not contain structural metadata
to support fast queries and updates.  If you don't know where this
work is heading, it is likely to look like just another large,
serialised data file.

But in fact it isn't.  Only a few more fields are needed to turn it
into a database as well, supporting the types of queries and updates
used in the Ethereum execution and sync processes.

## Relationship to database

This output looks like a set of "compressed" files using an ad-hoc
method (field update opcodes etc), but in fact this is a few steps
short of a fast-queryable (and updateable) database, which efficiently
supports each of the operations needed by an Ethereum node.

What is missing from this output is structural metadata that supports
fast queries and updates.

The final encoding steps, first to make a read-only queryable version
of the file, then an updateable version, are to be completed in Nim.
This is because the final encoding steps are almost identical to the
code which is required for updating the database at run-time.

## Space performance

In pursuing the ad-hoc encoding shown here, it has yielded useful data
about the encoding that is appriate in the real thing, and *most
usefully, an approximate upper bound on the size of the DB*.

## Query performance

We have worked out expected IOPS per read query.  It comes to be about
1/2 to 1/3 of the IOPS used by Erigon during contract executions, and
a smaller fraction of the IOPS used by Geth for account/storage
queries.

For write queries, it is fairly complex, both because writes can be
optimised differently than reads, and because the Merkle hashes must
be queried and updated.  It is because of the Merkle hashes
multiplying up the amount of I/O required that we must take advantage
of write optimisations available to divide it back down, instead of
treating writes similarly to reads.

Write IOPS are a balance LSM-like and B-tree-like, depending on the
type of access.  In Ethereum, execution and syncing (using
Nimbus-eth1's storage-efficient hybrid sync algorithm) uses very
different types of write patterns.  Neither an LSM-tree or B-tree
provide good performance for both kinds; the target structure does.

The target structure whose encoding is being approximated by the code
here is efficient at both kinds of write.  It is called "Bubble Tree",
but unfortunately there are no published papers at this time
describing the technique.  Its relevant claims for the Ethereum
storage problem are that it performs fast, random-access writes (like
an LSM-tree; used for contract execution) simultaneous with fast bulk
range updates (like a B-tree; used for syncing), does not have large
spikes in I/O or large spikes in storage space requirement, does not
rely critically on filesystem allocation performance, gradually orders
data into a shape that is good for sequential access, compacts away
holes, and supports some amount prefix- and field-compression between
related entries.  All these are useful for Ethereum storage, to reduce
space and perform the necessary operations efficiently.  The structure
is also surprisingly simple, once understood.
