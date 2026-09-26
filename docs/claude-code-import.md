# Claude Code project MCP import

The read-only importer turns a supported `.mcp.json` into a redacted server inventory. Explicit role bindings can also create an editable `memory-handoff` scenario. It never launches a server, runs a command or `headersHelper`, connects to a URL, expands environment variables, or inspects credentials.

中文摘要：先读取项目 `.mcp.json`，只输出服务名称、传输类型和字段存在情况及数量。提供明确的 source、memory、publish 角色绑定后，可以生成用于分析的记忆交接模型。配置存在、模板假设与实际运行证据分别保留；导入成功不表示真实部署已获得保护。

## Two useful starting points

Inspect your project configuration without creating a model:

```sh
structural-safety import-claude-code .mcp.json --output inventory.json
```

This returns `inventory_only`, with exit code `3` and `model: null`. The report identifies the additional role bindings and model assumptions needed for the next step.

Create `bindings.json` using the actual server names from your inventory:

```json
{
  "schema_version": "sst.claude-code-bindings/0.1",
  "template": "memory-handoff",
  "variant": "exposed",
  "servers": {
    "source": "private-files",
    "memory": "shared-memory",
    "publish": "publisher"
  }
}
```

Then generate and analyze the model:

```sh
structural-safety import-claude-code .mcp.json --bindings bindings.json --output import-report.json --model-output model.json
structural-safety analyze model.json --format markdown --output analysis.md
```

Exit code `0` from the import command means model generation succeeded. The generated model still requires review against your actual source restrictions, version lineage, task grants, recipients, memory behavior, control independence and normal tasks. Analysis has its own exit codes and retains the model's stated scope.

Bindings require three distinct existing servers. A remote entry with an empty URL cannot be bound. Additional servers remain in the inventory but are outside this finite scenario. `exposed` and `controlled` select authored template variants; the controlled variant assumes a particular gate exists. The importer neither installs nor verifies that gate.

Only `memory-handoff` supports configuration binding in this first adapter. The other business templates remain independently available through `get_template` and the template CLI.

## Supported configuration subset

The root object must contain exactly `mcpServers`, whose value is a server-name-to-definition object. A supported server entry accepts only the fields listed below.

| Transport | Required fields | Optional fields |
|---|---|---|
| `stdio`, including omitted `type` | Nonempty string `command` | `type`, string array `args`, string map `env` |
| `http` or `streamable-http` | String `type`, string `url` | String map `headers`, nonempty string `headersHelper` |
| `sse` or `ws` | String `type`, string `url` | String map `headers`, nonempty string `headersHelper` |

`streamable-http` appears as `http` in the inventory. A remote empty URL appears as `unconfigured`. `configured` means only that the accepted fields were supplied; endpoints and environment references are not resolved or validated by connecting.

The adapter rejects a URL-only entry without `type`, `sdk`, mixed transport fields, unknown fields and malformed values. It also explicitly rejects extensions such as `oauth`, `timeout`, `alwaysLoad` and `cwd`; their values are not silently ignored. Rejection identifies a fixed diagnostic category and position without reproducing the unknown name or value.

Server names must use ASCII letters, digits, hyphens or underscores. The currently documented reserved names `workspace`, `claude-in-chrome` and `computer-use` are rejected. Documented reserved names containing spaces also fail this subset's name syntax. This bounded check does not claim to anticipate future reserved names or configuration extensions.

Only project configuration is covered. Local and user configuration, plugins, claude.ai connectors, managed settings, server approval state, and built-in tools such as Bash, Read and WebFetch are outside the imported inventory. The model cannot establish deployment completeness from this file.

## Evidence and redaction

The inventory returns server names, normalized transport, configuration status, supported-field presence and argument/environment/header counts. It omits command and argument values, environment names and values, URLs, header names and values, helpers, and unknown field contents. Server names are retained deliberately, so use nonsecret names.

| Model record | Acquisition | What it establishes |
|---|---|---|
| `ev:claude-code-config` | `configuration_read` | Supported configuration entries appeared in the supplied JSON. Its model scope is empty, so it does not attest to a technical capability or control. |
| `ev:claude-code-bindings` | `supplied_assertion` | The caller mapped server names to the three scenario roles and selected a template variant. |
| `ev:template-premises` | `supplied_assertion` | The authored finite model's objects, permissions, controls, task structure and timing. |

The importer maps the template interfaces consistently to `if:claude-code:source`, `if:claude-code:memory` and `if:claude-code:publish`. It updates their references and records the mapping in supplied-assertion evidence. Every generated model passes the toolkit's normal validator before being returned.

The model retains these limits in `context.known_limits` and its evidence records. Its synthetic time and completeness premises describe the scenario. They do not become live deployment observations. The import report always has `analysis_performed: false` and `execution_performed: false`.

## API and limits

```python
import json
from pathlib import Path
from structural_safety import import_claude_code_json

result = import_claude_code_json(
    Path(".mcp.json").read_bytes(),
    bindings_document=Path("bindings.json").read_bytes(),
)
report = result.to_dict()
if result.import_status == "model_created":
    Path("model.json").write_text(
        json.dumps(report["model"], indent=2) + "\n", encoding="utf-8"
    )
```

The API accepts raw JSON text or bytes and an optional `Limits`. Results are immutable; `to_dict()` returns an independent copy. Ordinary invalid input yields `input_invalid`. Resource limits yield `resource_rejected`. CLI input errors return `2`, and file-operation errors return `5`.

Parsing rejects duplicate keys, nonfinite numbers, invalid UTF-8, unpaired Unicode surrogates, comments and trailing commas. The byte cap covers configuration and bindings together. The adapter counts every JSON object member and array entry against the combined `max_records` cap, and enforces `max_depth` before decoding. The generated model must also fit the normal model limits, including `max_actions`.

The package includes `integrations/claude-code-example.json` and `integrations/claude-code-bindings.json`, accessible with `importlib.resources`. Their commands are fictitious and the URL uses `example.invalid`. They are importer examples, not a working MCP deployment.

## Upstream reference

Checked **2026-09-26** against the official [Claude Code MCP documentation](https://code.claude.com/docs/en/mcp), particularly transport configuration, project scope, JSON import, server-name restrictions, reserved names and empty-URL behavior. This adapter intentionally supports the narrower table above; later upstream additions require an explicit adapter update.
