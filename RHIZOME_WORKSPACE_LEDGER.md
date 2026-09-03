# Durable Workspace operation ledger

This branch adds a protocol-neutral storage primitive for idempotent Workspace
operations. It stores opaque identifiers, a canonical request digest, operation
state, and opaque terminal bytes. The ledger does not decode a wire protocol,
authorize commands, produce signatures, or execute effects.

The storage key is a versioned tuple consisting of a Workspace scope, an
operation discriminator, and a request identifier. The encoded record is also
versioned and is bound to both its key digest and canonical request digest. A
domain-separated checksum covers the complete record so corrupted storage is
rejected; the checksum is not an authorization or authenticity proof.

Pending creation and terminal transitions are serialized through the
filesystem's sole `WriteCoordinator` and flushed before success is returned.
Calls with the same key and request digest replay the existing record. Reusing a
key with a different request digest conflicts. Once terminal, the exact outcome
bytes are immutable.

An absent record means the outcome is unknown. It must not be interpreted as
proof that an effect was not committed. Likewise, an error after a local apply
has an unknown outcome and must converge through readback instead of blind
mutation retry.

The coordinator request owns the sequencing guard until durable completion.
Cancelling the caller therefore cannot release serialization while the queued
write is still completing.

This branch intentionally contains no Rhizome protobuf definitions, generated
bindings, descriptors, schema provenance, service implementation, or private
control-plane fields.
