// Copyright 2017 Carnegie Mellon University. All Rights Reserved. See LICENSE.md file for terms.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Ghosts.Api.Infrastructure.Services;
using Microsoft.AspNetCore.Mvc;

namespace Ghosts.Api.Controllers.Api;

/// <summary>
/// Scenario authoring: a session, its turns, its record, and the import. No more open than the rest of the
/// API (I1). A turn runs inside the request in this slice; the background turn with live progress is later.
/// </summary>
[ApiController]
[Route("api/scenario-authoring")]
public class ScenarioAuthoringController(IScenarioAuthoringService authoring) : ControllerBase
{
    public class TurnRequest
    {
        public string Message { get; set; }
    }

    public class ImportRequest
    {
        public string Hash { get; set; }
        public bool Again { get; set; }
    }

    // POST: api/scenario-authoring/sessions
    [HttpPost("sessions")]
    public async Task<IActionResult> CreateSession(CancellationToken ct)
    {
        var session = await authoring.CreateSessionAsync(ct);
        return Ok(new { id = session.Id, model = session.Model });
    }

    /// <summary>
    /// Runs one turn. The turn is not tied to the request: a browser that goes away does not cancel it; its
    /// own limit does.
    /// </summary>
    // POST: api/scenario-authoring/sessions/{id}/turns
    [HttpPost("sessions/{id:guid}/turns")]
    public async Task<IActionResult> RunTurn(Guid id, [FromBody] TurnRequest request)
    {
        if (string.IsNullOrWhiteSpace(request?.Message)) return BadRequest(new { error = "A turn needs a message." });
        try
        {
            var result = await authoring.RunTurnAsync(id, request.Message, CancellationToken.None);
            return Ok(new
            {
                result.Turn,
                result.Reply,
                result.GateReport,
                result.ToolCalls,
                result.Validations,
                latestDocument = result.LatestDocument,
                result.CanImport,
                result.Failure
            });
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { error = ex.Message });
        }
        catch (AuthoringSessionBusyException ex)
        {
            return Conflict(new { error = ex.Message });
        }
    }

    /// <summary>The session's messages (reasoning omitted), its documents, and its token totals.</summary>
    // GET: api/scenario-authoring/sessions/{id}
    [HttpGet("sessions/{id:guid}")]
    public async Task<IActionResult> GetSession(Guid id, CancellationToken ct)
    {
        var session = await authoring.GetSessionAsync(id, ct);
        return session == null ? NotFound() : Ok(session);
    }

    /// <summary>
    /// Imports the session's latest document, when it is the one named, validated with 0 errors and shown.
    /// Anything else is refused with the reason. A hash imported before needs "again": true.
    /// </summary>
    // POST: api/scenario-authoring/sessions/{id}/import
    [HttpPost("sessions/{id:guid}/import")]
    public async Task<IActionResult> Import(Guid id, [FromBody] ImportRequest request, CancellationToken ct)
    {
        try
        {
            var result = await authoring.ImportAsync(id, request?.Hash, request?.Again ?? false, ct);
            var body = new
            {
                result.Imported,
                result.ScenarioId,
                result.Hash,
                result.Reason,
                result.NeedsConfirmation,
                result.Report
            };
            return result.Imported ? Ok(body) : Conflict(body);
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(new { error = ex.Message });
        }
        catch (AuthoringSessionBusyException ex)
        {
            return Conflict(new { error = ex.Message });
        }
    }
}
