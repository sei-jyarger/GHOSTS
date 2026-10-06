// Copyright 2017 Carnegie Mellon University. All Rights Reserved. See LICENSE.md file for terms.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Amazon.BedrockRuntime.Model;
using Amazon.Runtime.Documents;
using Ghosts.Api.Infrastructure.ScenarioDocuments;
using Microsoft.Extensions.DependencyInjection;
using NLog;

namespace Ghosts.Api.Infrastructure.Services
{
    /// <summary>What one tool call returned: the text sent back to the model, and for a validate, what to keep.</summary>
    public record AuthoringToolOutcome(string Text, bool Ok, AuthoringValidation Validation = null);

    /// <summary>A validation that returned: the exact document text, its hash, and the findings (C2).</summary>
    public record AuthoringValidation(string Document, string Hash, bool DryRun, IReadOnlyList<ScenarioFinding> Findings)
    {
        public int Errors => Findings.Count(f => f.Severity == ScenarioFinding.Error);
        public int Warnings => Findings.Count(f => f.Severity == ScenarioFinding.Warning);
    }

    /// <summary>
    /// The agent's five tools, calling the services the import endpoint and the MCP server already use. The
    /// names and parameters are the MCP server's, which the system prompt was written against. There is no
    /// import tool (A1): only the server imports, on the developer's action.
    /// </summary>
    public class ScenarioAuthoringTools(IServiceScopeFactory scopes, IHttpClientFactory clients, TimeSpan validatorTimeout)
    {
        private static readonly Logger _log = LogManager.GetCurrentClassLogger();
        private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);

        public const string Validate = "scenario_document_validate";
        public const string TechniqueLookup = "attack_technique_lookup";
        public const string GroupLookup = "attack_group_lookup";
        public const string Export = "scenario_document_export";
        public const string List = "scenario_list";

        public static ToolConfiguration Configuration() => new()
        {
            Tools =
            [
                Spec(Validate,
                    "Validates a GHOSTS scenario document and returns the findings. Writes nothing, ever, so it is safe on a draft. With dryRun it also creates the scenario and generates its population inside a transaction that is always rolled back, adding tier-4 findings. Call this before import and after every edit.",
                    """{"type":"object","properties":{"document":{"type":"string","description":"The scenario document as a JSON object (schema 1.1.0)."},"dryRun":{"type":"boolean","description":"When true, also create the scenario and generate its population in a rolled-back transaction and report what that found."}},"required":["document"]}"""),
                Spec(TechniqueLookup,
                    "Resolves MITRE ATT&CK techniques by id or by a fragment of a name, from the index GHOSTS validates against. Returns id, name, domains, and whether MITRE revoked or deprecated it. Use this for every technique id that goes into a document; never write one from memory.",
                    """{"type":"object","properties":{"query":{"type":"string","description":"An ATT&CK technique id such as T1566.002, an id prefix, or part of a technique name such as \"spearphishing\"."},"take":{"type":"integer","description":"Maximum number of matches to return."}},"required":["query"]}"""),
                Spec(GroupLookup,
                    "Resolves MITRE ATT&CK intrusion sets (groups) by id, by a fragment of the primary name, or by a fragment of a known alias, from the same corpus attack_technique_lookup uses. Returns id, name, aliases, domains, and whether MITRE revoked or deprecated it. Use this before naming a real adversary in a document; never write a group id from memory.",
                    """{"type":"object","properties":{"query":{"type":"string","description":"An ATT&CK group id such as G0034, an id prefix, or part of a name or alias such as \"sandworm\"."},"take":{"type":"integer","description":"Maximum number of matches to return."}},"required":["query"]}"""),
                Spec(Export,
                    "Fetches one GHOSTS scenario as a canonical scenario document: no database ids, no timestamps, no run state. Use it only to see the shape of a valid document.",
                    """{"type":"object","properties":{"scenarioId":{"type":"integer","description":"GHOSTS scenario id."}},"required":["scenarioId"]}"""),
                Spec(List,
                    "Fetches and returns the current list of GHOSTS scenarios: id, name and description.",
                    """{"type":"object","properties":{"take":{"type":"integer","description":"Maximum number of scenarios to return."}}}""")
            ]
        };

        private static Tool Spec(string name, string description, string schema) => new()
        {
            ToolSpec = new ToolSpecification
            {
                Name = name,
                Description = description,
                InputSchema = new ToolInputSchema { Json = AuthoringBlocks.ToDocument(JsonNode.Parse(schema)) }
            }
        };

        public async Task<AuthoringToolOutcome> RunAsync(string name, JsonNode input, CancellationToken turn)
        {
            try
            {
                return name switch
                {
                    Validate => await ValidateAsync(input, turn),
                    TechniqueLookup => Ok(Techniques(Str(input, "query"), Int(input, "take", 25))),
                    GroupLookup => Ok(Groups(Str(input, "query"), Int(input, "take", 25))),
                    Export => await ExportAsync(Int(input, "scenarioId", 0), turn),
                    List => await ListAsync(Int(input, "take", 25), turn),
                    _ => new AuthoringToolOutcome(Error($"There is no tool named {name}."), false)
                };
            }
            catch (OperationCanceledException) when (turn.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                _log.Warn(ex, $"Authoring tool {name} failed");
                return new AuthoringToolOutcome(Error($"{name} failed: {ex.Message}"), false);
            }
        }

        /// <summary>
        /// The validate endpoint's own sequence, with a timeout of its own (G4). The document text the model
        /// passed is what is hashed and kept, so an import later uses those exact bytes (A2).
        /// </summary>
        private async Task<AuthoringToolOutcome> ValidateAsync(JsonNode input, CancellationToken turn)
        {
            var text = input?["document"] switch
            {
                JsonValue v when v.TryGetValue<string>(out var s) => s,
                JsonNode n => n.ToJsonString(),
                _ => null
            };
            if (text == null) return new AuthoringToolOutcome(Error("scenario_document_validate needs a document."), false);

            var dryRun = input?["dryRun"] is JsonValue d && d.TryGetValue<bool>(out var b) && b;
            var hash = Hash(text);

            using var limit = CancellationTokenSource.CreateLinkedTokenSource(turn);
            limit.CancelAfter(validatorTimeout);
            var stage = "the validator (tiers 1 and 2)";
            try
            {
                var findings = new List<ScenarioFinding>();
                JsonObject document = null;
                try
                {
                    document = JsonNode.Parse(text) as JsonObject;
                    if (document == null)
                        findings.Add(ScenarioFinding.Err(1, "SCHEMA_NOT_AN_OBJECT", string.Empty, "A scenario document must be a JSON object."));
                }
                catch (JsonException ex)
                {
                    findings.Add(ScenarioFinding.Err(1, "SCHEMA_NOT_JSON", string.Empty, ex.Message));
                }

                if (document != null)
                {
                    var result = await ScenarioDocumentValidator.ValidateAsync(document, clients, limit.Token);
                    findings.AddRange(result.Findings);

                    if (dryRun && result.IsValid)
                    {
                        stage = "the dry run";
                        // Its own scope: the dry run rolls back and then clears its context's change tracker,
                        // which must not be the context holding this session.
                        await using var scope = scopes.CreateAsyncScope();
                        var dry = scope.ServiceProvider.GetRequiredService<IScenarioDryRunService>();
                        findings.AddRange(await dry.RunAsync(document, limit.Token));
                    }
                    else if (dryRun)
                    {
                        findings.Add(ScenarioFinding.Note(4, "DRYRUN_SKIPPED", string.Empty,
                            "The dry run did not run: the document has errors, and loading a document that cannot be imported says nothing."));
                    }
                }

                var ordered = ScenarioDocumentValidator.Ordered(findings);
                var validation = new AuthoringValidation(text, hash, dryRun, ordered);
                var body = new JsonObject
                {
                    ["valid"] = validation.Errors == 0,
                    ["errors"] = validation.Errors,
                    ["warnings"] = validation.Warnings,
                    ["findings"] = JsonSerializer.SerializeToNode(ordered, Web)
                };
                return new AuthoringToolOutcome(body.ToJsonString(), true, validation);
            }
            catch (OperationCanceledException) when (limit.IsCancellationRequested && !turn.IsCancellationRequested)
            {
                _log.Warn($"Authoring validate timed out after {validatorTimeout.TotalSeconds:0} s waiting on {stage}, document {hash}, dryRun {dryRun}");
                return new AuthoringToolOutcome(
                    Error($"The validator did not answer within {validatorTimeout.TotalSeconds:0} seconds (waiting on {stage}). Nothing was saved."), false);
            }
        }

        private static string Techniques(string query, int take)
        {
            var matches = AttackIndex.Search(query, take);
            return JsonSerializer.Serialize(new
            {
                query,
                provenance = AttackIndex.Provenance,
                indexed = AttackIndex.Count,
                count = matches.Count,
                techniques = matches.Select(t => new { id = t.Id, name = t.Name, domains = t.Domains, revoked = t.Revoked, deprecated = t.Deprecated })
            });
        }

        private static string Groups(string query, int take)
        {
            var matches = AttackGroupIndex.Search(query, take);
            return JsonSerializer.Serialize(new
            {
                query,
                provenance = AttackGroupIndex.Provenance,
                indexed = AttackGroupIndex.Count,
                count = matches.Count,
                groups = matches.Select(g => new { id = g.Id, name = g.Name, aliases = g.Aliases, domains = g.Domains, revoked = g.Revoked, deprecated = g.Deprecated })
            });
        }

        private async Task<AuthoringToolOutcome> ExportAsync(int scenarioId, CancellationToken turn)
        {
            await using var scope = scopes.CreateAsyncScope();
            var scenarios = scope.ServiceProvider.GetRequiredService<IScenarioService>();
            try
            {
                return Ok(await scenarios.ExportDocumentAsync(scenarioId, false, turn));
            }
            catch (InvalidOperationException)
            {
                return new AuthoringToolOutcome(Error($"There is no scenario {scenarioId}."), false);
            }
        }

        private async Task<AuthoringToolOutcome> ListAsync(int take, CancellationToken turn)
        {
            await using var scope = scopes.CreateAsyncScope();
            var scenarios = scope.ServiceProvider.GetRequiredService<IScenarioService>();
            var all = await scenarios.GetAllAsync(turn);
            return Ok(JsonSerializer.Serialize(all.Take(Math.Clamp(take, 1, 200))
                .Select(s => new { id = s.Id, name = s.Name, description = s.Description })));
        }

        private static AuthoringToolOutcome Ok(string text) => new(text, true);
        private static string Error(string message) => JsonSerializer.Serialize(new { error = message });

        private static string Str(JsonNode input, string key) =>
            input?[key] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

        private static int Int(JsonNode input, string key, int fallback) =>
            input?[key] is not JsonValue v ? fallback
            : v.TryGetValue<int>(out var i) ? i
            : v.TryGetValue<double>(out var d) ? (int)d
            : v.TryGetValue<string>(out var s) && int.TryParse(s, out var p) ? p
            : fallback;

        /// <summary>The first 12 hex digits of the SHA-256 of the text's UTF-8 bytes, as the prototype hashed.</summary>
        public static string Hash(string text) =>
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant()[..12];
    }

    /// <summary>
    /// Content blocks to and from the stored form, which follows Converse's own JSON names. Every block of a
    /// reply is kept, reasoning included, so the history sent back is the history received.
    /// </summary>
    public static class AuthoringBlocks
    {
        public static JsonArray ToJson(IEnumerable<ContentBlock> blocks)
        {
            var array = new JsonArray();
            foreach (var b in blocks ?? [])
            {
                if (b.Text != null)
                    array.Add(new JsonObject { ["text"] = b.Text });
                else if (b.ReasoningContent != null)
                    array.Add(new JsonObject
                    {
                        ["reasoningContent"] = b.ReasoningContent.RedactedContent != null
                            ? new JsonObject { ["redactedContent"] = Convert.ToBase64String(b.ReasoningContent.RedactedContent.ToArray()) }
                            : new JsonObject
                            {
                                ["reasoningText"] = new JsonObject
                                {
                                    ["text"] = b.ReasoningContent.ReasoningText?.Text ?? string.Empty,
                                    ["signature"] = b.ReasoningContent.ReasoningText?.Signature
                                }
                            }
                    });
                else if (b.ToolUse != null)
                    array.Add(new JsonObject
                    {
                        ["toolUse"] = new JsonObject
                        {
                            ["toolUseId"] = b.ToolUse.ToolUseId,
                            ["name"] = b.ToolUse.Name,
                            ["input"] = ToJson(b.ToolUse.Input)
                        }
                    });
                else if (b.ToolResult != null)
                    array.Add(new JsonObject
                    {
                        ["toolResult"] = new JsonObject
                        {
                            ["toolUseId"] = b.ToolResult.ToolUseId,
                            ["status"] = b.ToolResult.Status?.Value,
                            ["content"] = new JsonArray(b.ToolResult.Content.Select(c => (JsonNode)new JsonObject { ["text"] = c.Text }).ToArray())
                        }
                    });
                else
                    // A block type this slice does not send back, recorded so the record says it came.
                    array.Add(new JsonObject { ["unsupported"] = true });
            }
            return array;
        }

        public static List<ContentBlock> FromJson(string stored)
        {
            var blocks = new List<ContentBlock>();
            foreach (var node in JsonNode.Parse(stored)?.AsArray() ?? [])
            {
                if (node?["text"] is JsonValue t)
                    blocks.Add(new ContentBlock { Text = t.GetValue<string>() });
                else if (node?["reasoningContent"] is JsonObject r)
                    blocks.Add(new ContentBlock
                    {
                        ReasoningContent = r["redactedContent"] is JsonValue red
                            ? new ReasoningContentBlock { RedactedContent = new MemoryStream(Convert.FromBase64String(red.GetValue<string>())) }
                            : new ReasoningContentBlock
                            {
                                ReasoningText = new ReasoningTextBlock
                                {
                                    Text = r["reasoningText"]?["text"]?.GetValue<string>() ?? string.Empty,
                                    Signature = r["reasoningText"]?["signature"]?.GetValue<string>()
                                }
                            }
                    });
                else if (node?["toolUse"] is JsonObject u)
                    blocks.Add(new ContentBlock
                    {
                        ToolUse = new ToolUseBlock
                        {
                            ToolUseId = u["toolUseId"]?.GetValue<string>(),
                            Name = u["name"]?.GetValue<string>(),
                            Input = ToDocument(u["input"])
                        }
                    });
                else if (node?["toolResult"] is JsonObject res)
                    blocks.Add(new ContentBlock
                    {
                        ToolResult = new ToolResultBlock
                        {
                            ToolUseId = res["toolUseId"]?.GetValue<string>(),
                            Status = res["status"]?.GetValue<string>(),
                            Content = res["content"]?.AsArray()
                                .Select(c => new ToolResultContentBlock { Text = c?["text"]?.GetValue<string>() }).ToList() ?? []
                        }
                    });
            }
            return blocks;
        }

        public static JsonNode ToJson(Document d)
        {
            if (d.IsNull()) return null;
            if (d.IsBool()) return JsonValue.Create(d.AsBool());
            if (d.IsInt()) return JsonValue.Create(d.AsInt());
            if (d.IsLong()) return JsonValue.Create(d.AsLong());
            if (d.IsDouble()) return JsonValue.Create(d.AsDouble());
            if (d.IsString()) return JsonValue.Create(d.AsString());
            if (d.IsList()) return new JsonArray(d.AsList().Select(ToJson).ToArray());
            var obj = new JsonObject();
            foreach (var (k, v) in d.AsDictionary()) obj[k] = ToJson(v);
            return obj;
        }

        public static Document ToDocument(JsonNode node) => node switch
        {
            null => new Document(),
            JsonObject o => new Document(o.ToDictionary(kv => kv.Key, kv => ToDocument(kv.Value))),
            JsonArray a => new Document(a.Select(ToDocument).ToList()),
            JsonValue v when v.TryGetValue<bool>(out var b) => new Document(b),
            JsonValue v when v.TryGetValue<long>(out var l) => new Document(l),
            JsonValue v when v.TryGetValue<double>(out var x) => new Document(x),
            JsonValue v when v.TryGetValue<string>(out var s) => new Document(s),
            _ => new Document(node.ToJsonString())
        };
    }
}
