# Native Parser Roadmap (Track 3)

This roadmap moves Java, C#, and Go analysis from heuristic-heavy parsing toward native structural fidelity.

## Objectives

- Improve route/controller extraction fidelity.
- Improve auth/ownership semantic detection quality.
- Improve cross-file call graph correctness.

## Minimum Parser Contract (per language)

### 1) AST completeness

- Parse classes/methods/functions with stable source ranges.
- Capture decorators/annotations/attributes relevant to auth and routing.
- Preserve import/use graph for cross-file symbol resolution.

### 2) Framework auth and routing semantics

- **Java**: Spring MVC/WebFlux annotations (`@RequestMapping`, `@GetMapping`, `@PreAuthorize`, `@Secured`, etc.)
- **C#**: ASP.NET attributes (`[HttpGet]`, `[Authorize]`, `[AllowAnonymous]`, policy/role attributes)
- **Go**: net/http, chi, gin, echo route registration and middleware chain modeling

### 3) Ownership/auth flow requirements

- Track resource parameter extraction (`id`, `userId`, route params)
- Track auth context extraction (principal, claims, identity)
- Detect missing ownership guards before lookup/mutation sinks

## Phased Implementation Plan

1. **Parity corpus first**
   - Lock expected outcomes on curated framework snippets.
2. **Adapter layer**
   - Introduce language-specific parser adapters with stable IR output.
3. **Rule migration**
   - Port auth/IDOR logic from regex/heuristics to structural signals.
4. **Confidence modeling**
   - Mark findings with `analysis_kind` and confidence by parser depth.

## Acceptance Gates

- Structural parser path enabled for at least one non-Python/non-JS language.
- Measurable precision/recall improvement on parity corpus and real-world manifest cases.
- No major speed regression against target budget.

## Suggested first milestone

- Implement Java Spring annotation extractor + auth/ownership signal graph.
- Validate against WebGoat and dedicated parity corpus cases.
