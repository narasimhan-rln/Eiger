Now move to Part 2 — actually run the M3 attack against the app in its default 
vulnerable config. Do this step by step and capture real output at each step 
(don't summarize/paraphrase HTTP responses — show them).

Use session_id = "attacker-demo-1" for everything below.

1. Confirm the app is up (docker compose ps / curl the readiness endpoint).

2. Reset M3 for this session first for a clean baseline:
   POST /reset/m3  {"session_id": "attacker-demo-1"}

3. Confirm baseline is failing:
   GET /validate/m3?session=attacker-demo-1
   (expect {"core": "fail", "stretch": "fail"})

4. Poison the KB — submit a note that hides an instruction using the app's own 
   injection marker (RAG-OWNED-7788), phrased in my own words rather than copying 
   the test file's exact wording verbatim:
   POST /api/kb  {"session_id": "attacker-demo-1", "text": "<your crafted note>"}
   
   Design the note so it's topically plausible (e.g. disguised as an account note 
   or FAQ entry) but contains a clear hidden instruction telling the assistant to 
   include RAG-OWNED-7788 in its answer. Show me the exact text you used and why 
   you think it'll be retrieved for a related query.

5. Ask a topically-related question in the same session to trigger retrieval:
   POST /api/ask  {"session_id": "attacker-demo-1", "query": "<related question>"}
   Show the full response body (the model's reply).

6. Immediately re-check the validator:
   GET /validate/m3?session=attacker-demo-1
   Show the raw JSON response.

7. Pull the actual audit_log rows for this session+module directly from Postgres 
   (docker compose exec db psql, or a short script using halcyon.pg_store.PostgresStore) 
   so we have the underlying evidence chain, not just the validator's boolean summary:
   SELECT id, ts, event_type, details FROM audit_log 
   WHERE session_id='attacker-demo-1' AND module='m3' ORDER BY id;
   Show me every row — I need to see poisoned_chunk_in_context and rag_injection_fired 
   with their timestamps and chunk-id details, in the correct order.

8. For the stretch goal: ask a question likely to retrieve the seeded restricted 
   memo (check halcyon/kb_fixtures.py for what topic it covers, then phrase a query 
   accordingly) worded to induce disclosure of its content. Show the request, the 
   reply, the updated /validate/m3 output, and the corresponding audit_log rows 
   (restricted_doc_retrieved and restricted_doc_disclosed).

9. Save everything above (raw requests, raw responses, the two /validate/m3 JSON 
   outputs, and the full audit_log query results) into evidence/before/ as separate 
   files (e.g. 01_reset.txt, 02_baseline_validate.json, 03_poison_request.json, 
   04_ask_request_response.json, 05_validate_after.json, 06_audit_log.txt, 
   07_stretch_*.* ), so it's reproducible.

Do not write any mitigation code in this pass — attack and evidence capture only.