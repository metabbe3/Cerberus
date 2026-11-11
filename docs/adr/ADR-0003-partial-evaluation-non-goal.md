# ADR-0003: Partial Evaluation Helper as Non-Goal for Parity Sprint

## Status
Accepted (Non-Goal)

## Context
OPA provides a compile API endpoint (`POST /v1/compile`) for partial evaluation that reduces policies against partially known inputs into residual Rego or AST representations (often used to translate policy rules into SQL/Elasticsearch queries or downstream filter ASTs).

During Phase 2 of the Cerberus OPA Parity Sprint, adding a partial evaluation endpoint (`POST /v1/compile-style`) was evaluated.

## Decision
We deliberately skip the implementation of `POST /v1/compile` in this phase.
Cerberus operates as an authoritative runtime gateway decision engine with prepared-query evaluation, singleflight, and in-memory LRU caching targeting sub-millisecond execution for LLM/tool/gateway stages. Implementing full partial evaluation AST serialization and compile-style queries adds significant complexity without directly serving the primary gateway authorization use cases.

Partial evaluation remains a potential candidate for a future phase if client-side query pushdown into backend databases is required.
