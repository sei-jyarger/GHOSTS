// Copyright 2017 Carnegie Mellon University. All Rights Reserved. See LICENSE.md file for terms.

using System.Text.Json;
using System.Text.Json.Nodes;
using Amazon.BedrockRuntime;
using Amazon.BedrockRuntime.Model;
using Ghosts.Animator.Models;
using Ghosts.Api.Infrastructure.Data;
using Ghosts.Api.Infrastructure.Models;
using Ghosts.Api.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Ghosts.Api.Tests;

/// <summary>
/// Scenario authoring with a scripted model in place of a real one: the parts that must hold whatever the
/// model does. In-memory database, real services, no mocking library.
/// </summary>
public class ScenarioAuthoringServiceTests
{
    // ───────── a: a tool call, then a reply ─────────

    [Fact]
    public async Task A_tool_call_runs_the_gate_report_lists_it_and_the_history_keeps_both_replies_whole()
    {
        var db = NewDatabase();
        Message[]? sentBack = null;
        var model = new ScriptedModel(
            _ => Reply(Reasoning("looking it up", "sig-1"), Use("t1", "attack_technique_lookup", """{"query":"T1566.002"}""")),
            r =>
            {
                sentBack = r.Messages.ToArray();
                return Reply(Text("Found it."));
            });
        await using var context = db();
        var service = Service(context, model);
        var session = await service.CreateSessionAsync(default);

        var result = await service.RunTurnAsync(session.Id, "Look up spearphishing link.", default);

        Assert.Null(result.Failure);
        Assert.Equal("Found it.", result.Reply);
        Assert.Equal([new AuthoringToolCall("attack_technique_lookup", true)], result.ToolCalls);
        Assert.Contains("Tool calls this turn (1): attack_technique_lookup", result.GateReport);

        // The tool ran: its result went back to the model, beside the reasoning block it came after.
        Assert.NotNull(sentBack);
        Assert.Equal(3, sentBack!.Length);
        Assert.NotNull(sentBack[1].Content[0].ReasoningContent);
        Assert.Equal("sig-1", sentBack[1].Content[0].ReasoningContent.ReasoningText.Signature);
        var toolResult = sentBack[2].Content.Single().ToolResult;
        Assert.Equal("t1", toolResult.ToolUseId);
        Assert.Contains("\"T1566.002\"", toolResult.Content.Single().Text);

        // The history keeps both model replies whole, in order.
        var kept = await context.AuthoringMessages.Where(m => m.InHistory).OrderBy(m => m.Sequence).ToListAsync();
        Assert.Equal(["developer", "model", "tool", "model"], kept.Select(m => m.Role));
        var first = JsonNode.Parse(kept[1].Content)!.AsArray();
        Assert.Equal("sig-1", first[0]!["reasoningContent"]!["reasoningText"]!["signature"]!.GetValue<string>());
        Assert.Equal("attack_technique_lookup", first[1]!["toolUse"]!["name"]!.GetValue<string>());
        Assert.Equal("Found it.", JsonNode.Parse(kept[3].Content)!.AsArray()[0]!["text"]!.GetValue<string>());

        // And they are what the next turn sends.
        var next = new ScriptedModel(r =>
        {
            Assert.Equal(5, r.Messages.Count);
            Assert.NotNull(r.Messages[1].Content[0].ReasoningContent);
            Assert.NotNull(r.Messages[1].Content[1].ToolUse);
            return Reply(Text("Again."));
        });
        Assert.Null((await Service(context, next).RunTurnAsync(session.Id, "And again.", default)).Failure);
    }

    // ───────── b: reasoning first, text second ─────────

    [Fact]
    public async Task The_reply_is_the_first_block_that_holds_text_when_reasoning_comes_first()
    {
        var db = NewDatabase();
        await using var context = db();
        var service = Service(context, new ScriptedModel(_ => Reply(Reasoning("", "sig"), Text("The answer."))));
        var session = await service.CreateSessionAsync(default);

        var result = await service.RunTurnAsync(session.Id, "Question.", default);

        Assert.Null(result.Failure);
        Assert.Equal("The answer.", result.Reply);
    }

    // ───────── c: an empty reply ─────────

    [Fact]
    public async Task An_empty_reply_is_not_saved_to_the_history_and_the_notice_says_so()
    {
        var db = NewDatabase();
        await using var context = db();
        var service = Service(context, new ScriptedModel(_ => Reply(Reasoning("", "sig"))));
        var session = await service.CreateSessionAsync(default);

        var result = await service.RunTurnAsync(session.Id, "Hello.", default);

        Assert.Equal("empty reply", result.Failure?.Cause);
        Assert.Contains("your message was not kept", result.Failure!.Notice);
        Assert.Equal(string.Empty, result.Reply);
        Assert.False(await context.AuthoringMessages.AnyAsync(m => m.InHistory));

        // The session continues: the next turn sends only its own message.
        var next = new ScriptedModel(r =>
        {
            Assert.Single(r.Messages);
            return Reply(Text("Here."));
        });
        var second = await Service(context, next).RunTurnAsync(session.Id, "Hello again.", default);
        Assert.Null(second.Failure);
        Assert.Equal(2, second.Turn);
    }

    // ───────── d: a provider error after a validation ─────────

    [Fact]
    public async Task A_document_validated_before_the_last_call_failed_is_still_kept()
    {
        var db = NewDatabase();
        await using var context = db();
        var document = ValidDocument();
        var model = new ScriptedModel(
            _ => Reply(Use("v1", "scenario_document_validate", Input(document))),
            _ => throw new ServiceUnavailableException("Bedrock is unable to process your request."),
            _ => throw new ServiceUnavailableException("Bedrock is unable to process your request."));
        var service = Service(context, model);
        var session = await service.CreateSessionAsync(default);

        var result = await service.RunTurnAsync(session.Id, "Draft it.", default);

        Assert.Equal("model error", result.Failure?.Cause);
        Assert.Contains("ServiceUnavailableException", result.Failure!.Details);

        // C2: the validated document survived the failure, with its exact bytes and its findings.
        var kept = Assert.Single(await context.AuthoringDocuments.ToListAsync());
        Assert.Equal(ScenarioAuthoringTools.Hash(document), kept.Hash);
        Assert.Equal(document, kept.Document);
        Assert.Equal(0, kept.Errors);
        Assert.False(kept.Shown);
        Assert.Contains(kept.Hash, result.GateReport);

        // F4: the 503 was retried once, and every attempt is on the record; none is in the history.
        var calls = await context.AuthoringMessages.Where(m => m.Role == "model").OrderBy(m => m.Sequence).ToListAsync();
        Assert.Equal(3, calls.Count);
        Assert.Null(calls[0].Error);
        Assert.All(calls.Skip(1), c => Assert.StartsWith("ServiceUnavailableException", c.Error));
        Assert.False(await context.AuthoringMessages.AnyAsync(m => m.InHistory));
    }

    // ───────── e: a turn past its limit ─────────

    [Fact]
    public async Task A_turn_past_its_limit_cancels_the_model_call_and_saves_nothing_to_the_history()
    {
        var db = NewDatabase();
        await using var context = db();
        var cancelled = false;
        var model = new ScriptedModel(async (_, ct) =>
        {
            try
            {
                await Task.Delay(Timeout.Infinite, ct);
            }
            catch (OperationCanceledException)
            {
                cancelled = true;
                throw;
            }
            return Reply(Text("never"));
        });
        var service = Service(context, model);
        service.TurnLimitOverride = TimeSpan.FromMilliseconds(200);
        var session = await service.CreateSessionAsync(default);

        var result = await service.RunTurnAsync(session.Id, "Take your time.", default);

        Assert.Equal("timeout", result.Failure?.Cause);
        Assert.True(cancelled, "the model call the turn was waiting on was not cancelled");
        Assert.False(await context.AuthoringMessages.AnyAsync(m => m.InHistory));
        Assert.Equal("Cancelled: the turn reached its limit.",
            (await context.AuthoringMessages.SingleAsync(m => m.Role == "model")).Error);
    }

    // ───────── f: import refusals ─────────

    [Fact]
    public async Task A_hash_with_errors_is_refused()
    {
        var db = NewDatabase();
        await using var context = db();
        var broken = """{"schemaVersion":"1.1.0"}""";
        var service = Service(context, new ScriptedModel(
            _ => Reply(Use("v1", "scenario_document_validate", Input(broken))),
            _ => Reply(Text("It has errors."))));
        var session = await service.CreateSessionAsync(default);
        var turn = await service.RunTurnAsync(session.Id, "Draft.", default);
        Assert.True(turn.LatestDocument!.Errors > 0);

        var result = await service.ImportAsync(session.Id, turn.LatestDocument.Hash, false, default);

        Assert.False(result.Imported);
        Assert.Contains("did not pass validation", result.Reason);
        Assert.Equal(0, await context.Scenarios.CountAsync());
    }

    [Fact]
    public async Task A_hash_never_shown_is_refused()
    {
        var db = NewDatabase();
        await using var context = db();
        var document = ValidDocument();
        var service = Service(context, new ScriptedModel(
            _ => Reply(Use("v1", "scenario_document_validate", Input(document))),
            _ => Reply(Reasoning("", "sig"))));
        var session = await service.CreateSessionAsync(default);
        var turn = await service.RunTurnAsync(session.Id, "Draft.", default);
        Assert.Equal("empty reply", turn.Failure?.Cause);
        Assert.False(turn.CanImport);

        var result = await service.ImportAsync(session.Id, ScenarioAuthoringTools.Hash(document), false, default);

        Assert.False(result.Imported);
        Assert.Contains("no reply has shown it", result.Reason);
        Assert.Equal(0, await context.Scenarios.CountAsync());
    }

    [Fact]
    public async Task A_hash_that_is_not_the_latest_is_refused()
    {
        var db = NewDatabase();
        await using var context = db();
        var first = ValidDocument();
        var second = JsonNode.Parse(first)!.ToJsonString(); // the same document, other bytes: another hash
        Assert.NotEqual(ScenarioAuthoringTools.Hash(first), ScenarioAuthoringTools.Hash(second));
        var service = Service(context, new ScriptedModel(
            _ => Reply(Use("v1", "scenario_document_validate", Input(first))),
            _ => Reply(Use("v2", "scenario_document_validate", Input(second))),
            _ => Reply(Text("Two versions."))));
        var session = await service.CreateSessionAsync(default);
        var turn = await service.RunTurnAsync(session.Id, "Draft.", default);
        Assert.Equal(ScenarioAuthoringTools.Hash(second), turn.LatestDocument!.Hash);

        var result = await service.ImportAsync(session.Id, ScenarioAuthoringTools.Hash(first), false, default);

        Assert.False(result.Imported);
        Assert.Contains("is not the latest validated document", result.Reason);
        Assert.Equal(0, await context.Scenarios.CountAsync());
    }

    [Fact]
    public async Task A_second_import_of_the_same_hash_needs_again()
    {
        var db = NewDatabase();
        await using var context = db();
        var document = ValidDocument();
        var service = Service(context, new ScriptedModel(
            _ => Reply(Use("v1", "scenario_document_validate", Input(document))),
            _ => Reply(Text("Here is the plan."))));
        var session = await service.CreateSessionAsync(default);
        var turn = await service.RunTurnAsync(session.Id, "Draft.", default);
        Assert.True(turn.CanImport);
        var hash = turn.LatestDocument!.Hash;

        var imported = await service.ImportAsync(session.Id, hash, false, default);
        Assert.True(imported.Imported, imported.Reason);

        var refused = await service.ImportAsync(session.Id, hash, false, default);
        Assert.False(refused.Imported);
        Assert.True(refused.NeedsConfirmation);
        Assert.Contains($"already imported as scenario {imported.ScenarioId}", refused.Reason);
        Assert.Equal(1, await context.Scenarios.CountAsync());

        var again = await service.ImportAsync(session.Id, hash, true, default);
        Assert.True(again.Imported, again.Reason);
        Assert.Equal(2, await context.Scenarios.CountAsync());

        // The model hears of all three at the start of the next message.
        var session2 = await context.AuthoringSessions.SingleAsync();
        Assert.Contains($"Imported: scenario id {imported.ScenarioId}", session2.PendingNote);
        Assert.Contains("Nothing was imported", session2.PendingNote);
    }

    // ───────── g: two sessions at once ─────────

    [Fact]
    public async Task Two_sessions_run_at_the_same_time_keep_their_own_records()
    {
        var db = NewDatabase();
        var document = ValidDocument();
        var started = new TaskCompletionSource();
        var bothIn = new CountdownEvent(2);

        async Task<(Guid Id, AuthoringTurnResult Result)> Run(string name, string text)
        {
            await using var context = db();
            var model = new ScriptedModel(
                async (_, _) =>
                {
                    bothIn.Signal();
                    await started.Task; // both sessions are inside a model call at once
                    return Reply(Use($"{name}-v", "scenario_document_validate", Input(text)));
                },
                (_, _) => Task.FromResult(Reply(Text($"Plan for {name}."))));
            var service = Service(context, model);
            var session = await service.CreateSessionAsync(default);
            return (session.Id, await service.RunTurnAsync(session.Id, $"Intent {name}.", default));
        }

        var a = Run("a", document);
        var b = Run("b", JsonNode.Parse(document)!.ToJsonString());
        Assert.True(bothIn.Wait(TimeSpan.FromSeconds(10)), "the two turns did not overlap");
        started.SetResult();
        var results = await Task.WhenAll(a, b);

        await using var check = db();
        foreach (var (id, result, name) in new[] { (results[0].Id, results[0].Result, "a"), (results[1].Id, results[1].Result, "b") })
        {
            Assert.Null(result.Failure);
            Assert.Equal($"Plan for {name}.", result.Reply);
            var messages = await check.AuthoringMessages.Where(m => m.SessionId == id).ToListAsync();
            Assert.Equal(4, messages.Count);
            Assert.Contains(messages, m => m.Content.Contains($"Intent {name}."));
            var doc = Assert.Single(await check.AuthoringDocuments.Where(d => d.SessionId == id).ToListAsync());
            Assert.Equal(result.LatestDocument!.Hash, doc.Hash);
        }
        Assert.NotEqual(results[0].Result.LatestDocument!.Hash, results[1].Result.LatestDocument!.Hash);
    }

    // ───────── the scripted model and the fixtures ─────────

    private sealed class ScriptedModel : IAuthoringModel
    {
        private readonly Queue<Func<ConverseRequest, CancellationToken, Task<ConverseResponse>>> _steps;

        public ScriptedModel(params Func<ConverseRequest, ConverseResponse>[] steps) =>
            _steps = new(steps.Select(s => (Func<ConverseRequest, CancellationToken, Task<ConverseResponse>>)((r, _) => Task.FromResult(s(r)))));

        public ScriptedModel(params Func<ConverseRequest, CancellationToken, Task<ConverseResponse>>[] steps) =>
            _steps = new(steps);

        public Task<ConverseResponse> ConverseAsync(ConverseRequest request, CancellationToken ct) =>
            _steps.Count == 0 ? throw new InvalidOperationException("The script has no more replies.") : _steps.Dequeue()(request, ct);
    }

    private static ConverseResponse Reply(params ContentBlock[] blocks) => new()
    {
        Output = new ConverseOutput { Message = new Message { Role = ConversationRole.Assistant, Content = blocks.ToList() } },
        StopReason = blocks.Any(b => b.ToolUse != null) ? StopReason.Tool_use : StopReason.End_turn,
        Usage = new TokenUsage { InputTokens = 100, OutputTokens = 10, TotalTokens = 110, CacheReadInputTokens = 5, CacheWriteInputTokens = 0 }
    };

    private static ContentBlock Text(string text) => new() { Text = text };

    private static ContentBlock Reasoning(string text, string signature) => new()
    {
        ReasoningContent = new ReasoningContentBlock { ReasoningText = new ReasoningTextBlock { Text = text, Signature = signature } }
    };

    private static ContentBlock Use(string id, string name, string input) => new()
    {
        ToolUse = new ToolUseBlock { ToolUseId = id, Name = name, Input = AuthoringBlocks.ToDocument(JsonNode.Parse(input)) }
    };

    private static string Input(string document) => new JsonObject { ["document"] = document, ["dryRun"] = false }.ToJsonString();

    /// <summary>The schema's own example that validates clean, which the validator tests already assert.</summary>
    private static string ValidDocument()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
        {
            var path = Path.Combine(dir.FullName, "schemas", "scenario-document", "examples", "phishing-drill.scenario.json");
            if (File.Exists(path)) return File.ReadAllText(path);
        }
        throw new FileNotFoundException("schemas/scenario-document/examples/phishing-drill.scenario.json");
    }

    private static ScenarioAuthoringService Service(ApplicationDbContext context, IAuthoringModel model) => new(
        context,
        new ScenarioService(context),
        model,
        new ServiceCollection().BuildServiceProvider().GetRequiredService<IServiceScopeFactory>(),
        null,
        Options.Create(new ScenarioAuthoringOptions { Model = "scripted", ValidatorTimeoutSeconds = 30 }),
        "Test prompt.");

    /// <summary>One in-memory database; each call gives a new context on it, as each request would.</summary>
    private static Func<ApplicationDbContext> NewDatabase()
    {
        var name = $"authoring-{Guid.NewGuid()}";
        var root = new InMemoryDatabaseRoot();
        return () => new TestDbContext(new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(name, root)
            .ConfigureWarnings(w => w.Ignore(InMemoryEventId.TransactionIgnoredWarning))
            .Options);
    }

    /// <summary>As in ScenarioDocumentStorageTests: NpcProfile is jsonb, which only Npgsql maps.</summary>
    private class TestDbContext(DbContextOptions<ApplicationDbContext> options) : ApplicationDbContext(options)
    {
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            modelBuilder.Entity<NpcRecord>().Property(n => n.NpcProfile).HasConversion(
                profile => JsonSerializer.Serialize(profile, (JsonSerializerOptions?)null),
                text => JsonSerializer.Deserialize<NpcProfile>(text, (JsonSerializerOptions?)null)!);
        }
    }
}
