// Copyright 2017 Carnegie Mellon University. All Rights Reserved. See LICENSE.md file for terms.

using System.Text.Json.Nodes;
using Ghosts.Api.Infrastructure.ScenarioDocuments;

namespace Ghosts.Api.Tests;

/// <summary>
/// What import reports about the paths no column holds. The wording is read by an agent and relayed
/// to a developer, so it must not claim an export drops these: the stored document still returns them.
/// </summary>
public class StorageLossAnalyzerTests
{
    [Fact]
    public void Effects_and_deadline_give_one_finding_per_top_level_path_with_the_right_wording()
    {
        var doc = JsonNode.Parse("""
            {
              "rulesOfPlay": { "deadline": { "at": "T+9h" } },
              "timeline": { "events": [ { "id": "e1", "effects": { "setFlags": ["phish_delivered"] } } ] }
            }
            """)!.AsObject();

        var findings = StorageLossAnalyzer.Analyze(doc);

        Assert.Equal(["/rulesOfPlay", "/timeline"], findings.Select(f => f.Path).Order(StringComparer.Ordinal));
        Assert.All(findings, f =>
        {
            Assert.Equal("STORAGE_LOSSY", f.Code);
            Assert.Equal(ScenarioFinding.Warning, f.Severity);
            Assert.Equal(4, f.Tier);
            Assert.Contains("the stored document does", f.Message);
            Assert.Contains("\"What the columns cannot hold\"", f.Hint);
            Assert.Contains("GET {id}/document returns these", f.Hint);
            Assert.Contains("Nothing in GHOSTS acts on them during play.", f.Hint);
            Assert.Contains("The white cell runs them by hand: an event's flags, the ladder, the deadline.", f.Hint);
            Assert.DoesNotContain("What the API cannot hold", f.Message + f.Hint);
            Assert.DoesNotContain("export", f.Message + f.Hint, StringComparison.OrdinalIgnoreCase);
        });
        Assert.Contains("deadline", findings.Single(f => f.Path == "/rulesOfPlay").Message);
        Assert.Contains("events[].effects", findings.Single(f => f.Path == "/timeline").Message);
    }
}
