# CLAUDE.md

<!-- PROJECT-SPECIFIC: Fill in these sections per project -->

## Project Overview
A self-hostable, mini Autonomous SOC that ingests a startup's dev-stack telemetry (GitHub, AWS CloudTrail, Okta, Falco) in each vendor's native schema, correlates entities in a security graph, runs specialized AI agents in parallel to triage and investigate, and stages one-click response actions behind a human-approval gate — demonstrated against a scripted supply-chain attack replay built from **real public attack datasets**.

## Stack
**Language / Runtime:** Python 3.12 (control plane, agents, ingestion), TypeScript / Next.js 15 (dashboard).

**External Libraries:**
- Backend: `fastapi`, `pydantic`, `pydantic-ai`, `sqlalchemy`, `asyncpg`, `pgvector`, `neo4j` (official Python driver), `redis`, `httpx`, `structlog`, `prometheus-client`, `tenacity`, `ollama` (Python client).
- Frontend: `next`, `react`, `tailwindcss`, `shadcn/ui`, `react-force-graph-2d`, `@tanstack/react-query`, `lucide-react`.
- Test/eval: `pytest`, `pytest-asyncio`, `respx`, `polyfactory`.

**Infrastructure (all official Docker images, all free):** `ollama/ollama`, `neo4j:5-community`, `pgvector/pgvector:pg16`, `redis:7`, `prom/prometheus`, `grafana/grafana-oss`, plus your own `api` / `worker` / `dashboard` images.

- Neo4j + Cypher (one weekend ramp; patterns stay simple — entities, edges, path queries).
- `react-force-graph-2d` (drop-in).
- Sigma rule YAML format (read the spec, copy starter rules from SigmaHQ).
- A working mental model of MITRE ATT&CK techniques (you'll reference IDs, not invent them).
- Ollama model selection (default `qwen2.5:7b-instruct` or `llama3.1:8b-instruct`; pulled on first run by an init container).
-->

## Project Rules
 Everything that the project development and testing should be done inside a Docker container. Nothing should be installed on my local system, and no local port should be used to run the application other than running a Docker container, of course.


---

## Workflow Orchestration

### 1. Plan First
- Enter plan mode for ANY non-trivial task (3+ steps or architectural decisions)
- If something goes sideways, STOP and re-plan immediately - don't keep pushing
- Use plan mode for verification steps, not just building
- Write detailed specs upfront to reduce ambiguity

### 2. Subagent Strategy
- Use subagents liberally to keep main context window clean
- Offload research, exploration, and parallel analysis to subagents
- For complex problems, throw more compute at it via subagents
- One task per subagent for focused execution

### 3. Self-Improvement Loop
- After ANY correction from the user: update `tasks/lessons.md` with the pattern
- Write rules for yourself that prevent the same mistake
- Ruthlessly iterate on these lessons until mistake rate drops
- Review lessons at session start for relevant project

### 4. Autonomous Bug Fixing
- When given a bug report: just fix it. Don't ask for hand-holding
- Point at logs, errors, failing tests - then resolve them
- Zero context switching required from the user
- Go fix failing CI tests without being told how

### 5. Demand Elegance (Balanced)
- For non-trivial changes: pause and ask "is there a more elegant way?"
- If a fix feels hacky: "Knowing everything I know now, implement the elegant solution"
- Skip this for simple, obvious fixes - don't over-engineer
- Challenge your own work before presenting it

## Task Management

1. **Plan First**: Write plan to `tasks/todo.md` with checkable items
2. **Verify Plan**: Check in before starting implementation
3. **Track Progress**: Mark items complete as you go
4. **Explain Changes**: High-level summary at each step
5. **Document Results**: Add review section to `tasks/todo.md`
6. **Capture Lessons**: Update `tasks/lessons.md` after corrections

## Core Principles

- **Simplicity First**: Make every change as simple as possible. Impact minimal code.
- **No Laziness**: Find root causes. No temporary fixes. Senior developer standards.
- **Minimal Impact**: Changes should only touch what's necessary. Avoid introducing bugs.

---

## Verification Stories

The project maintains a `verification/stories.yaml` using this format:

```yaml
stories:
  - name: "User signs in and manages their first document"
    url: "http://localhost:<PORT>"
    workflow: |
      Navigate to http://localhost:<PORT>/auth
      Type "{{TEST_EMAIL}}" in the email input field
      Type "{{TEST_PASSWORD}}" in the password input field
      Click the "Sign In" button
      Verify the dashboard loads with the user's name visible
      Click "Upload Document" and upload a test file
      Verify the document appears in the document list
      Click on the uploaded document
      Verify the document detail view opens with correct metadata
      Navigate back to the dashboard
      Verify the document count has updated
```

Credentials use `{{VAR}}` placeholders. Actual values live in `verification/.env` (gitignored).
A committed `verification/.env.example` documents available variable names.

### Story Rules
- **1-2 stories per feature, not per commit.** Each story should be a multi-step workflow
  combining related features into a realistic end-to-end user journey. Prefer extending
  an existing story with new steps over creating a new story. Only create a new story when
  the feature genuinely doesn't fit any existing journey.
- **Never remove stories** unless the feature was intentionally removed.
- **Stories ARE committed.** `stories.yaml` uses `{{VAR}}` placeholders for credentials -
  never write raw credentials in story workflows.
- **Credentials live in `verification/.env`** (gitignored). A committed
  `verification/.env.example` documents available variables with placeholder values.
- **Interpolation before execution.** Before passing workflow text to test agents, load
  `verification/.env` and replace all `{{VAR}}` tokens with their values.
- **Gitignore setup.** When initializing a project's verification folder, ensure `.gitignore`
  includes `verification/.env` (to protect credentials) and does NOT broadly ignore the
  entire `verification/` directory (so that `stories.yaml` and `.env.example` are tracked).
  If a broad `verification*` or `verification/` pattern exists, replace it with `verification/.env`.
- **Plan mode must include stories.** When planning multi-commit work, specify which
  existing stories to extend or what new stories to create, keeping to 1-2 per feature.

## Testing Gate (MANDATORY - no exceptions)

- **All testing runs inside Docker.** Backend tests, API smoke tests, and UI review run against
  Docker containers - never against a local dev setup.

### Backend tests: every commit
- Run `pytest` + API smoke tests inside Docker after each commit. These are cheap and
  catch regressions early.
- When only backend code was changed, backend tests alone satisfy the testing gate -
  UI stories are not required.

### UI stories (`/ui-review`): end of plan only
- Run verification stories once after the final commit of a multi-commit plan, not after
  every intermediate commit. Unit tests, curl, or manual browser testing do NOT count.
- The testing sequence is: **implement -> commit (backend tests pass) -> ... -> final
  commit -> write/update stories -> docker up -> /ui-review -> fix -> retest failed
  stories -> done.**
- On retest rounds, only re-run previously failed stories (via a temporary `_retest.yaml`).
  Stories that passed in the initial run do not need to be re-verified.
- If `/ui-review` is unavailable for a full-stack project, **stop and tell the user.**
- Partial pass does NOT authorize a merge. ALL applicable stories must pass.
