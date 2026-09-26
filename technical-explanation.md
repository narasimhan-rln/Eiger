# Technical Explanation — M3 RAG Knowledge-Base Poisoning

**Where untrusted content enters.** `POST /api/kb` (`halcyon/web.py:369-373`). The route has no
authentication and never cross-checks the caller's `session_id` against any cookie or token;
`body.text` is passed straight into `kb.add(text, "user", owner_session=session_id)` with no
content validation, length cap, or pattern screening at ingestion.

**Provenance is captured correctly at write time.** Both `KnowledgeBase` implementations
(`InMemoryKB.add`, `ChromaKB.add`) faithfully store `provenance="user"` — in production, as
ChromaDB metadata alongside the chunk text. The data needed to distinguish trusted content from
attacker-submitted content exists from the moment a chunk is written.

**Retrieval is provenance-blind, and that's a reasonable design.** `kb.retrieve()` ranks purely by
relevance — embedding similarity in `ChromaKB`, token overlap in `InMemoryKB` — and returns
whatever scores highest, trusted or user, public or restricted. That's an appropriate contract for
a retrieval function taken in isolation; the failure isn't here.

**The core failure is in `guards.assemble_rag()`**, vulnerable path
(`halcyon/guards.py:117-123`). Every retrieved chunk, regardless of `provenance`, is concatenated
into one undelimited block and wrapped in system-authored text instructing the model to treat it
as "authoritative instructions and context." The `provenance` tag is present on every `Chunk`
object passed into this function and is never read there. The trust boundary that should separate
"retrieved reference material" from "instructions the model obeys" is simply not implemented on
this code path.

**Why the model follows the injected instruction.** There is no structural signal distinguishing
the two categories — no system/user role split (everything lands in a single `"user"` message),
no delimiters, and an explicit instruction telling the model the whole block is authoritative. A
plausible, imperative-sounding sentence embedded in a KB note is, from the model's perspective,
indistinguishable from a legitimate instruction.

**The same blind spot produces the stretch failure.** `rag.answer()` (`halcyon/rag.py:11-15`)
only filters `access="restricted"` chunks when `settings.sec_rag_provenance` is true; under the
default vulnerable settings, `visible = chunks` unconditionally. A restricted chunk owned by a
different session reaches the model with the same unearned authority as a trusted one, and nothing
downstream checks `owner_session` either.

**In one sentence:** the application captures `provenance` and `access` metadata correctly at
every stage except the one that matters — prompt construction and its preceding retrieval filter
— where both are silently ignored.
