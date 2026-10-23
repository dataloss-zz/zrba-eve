# All Corp Members (archived feature)

Removed from the active Corp Officers page on 2026-10-23 to avoid fetching the full EVE roster and per-character ESI data.

This file preserves the original markup, browser-side rendering, and Worker roster-fetching logic. It is NOT imported or served by the application. To restore, reinsert these blocks in their original locations and restore the `roster` and `roster_error` response properties. Consider batching or caching ESI lookups before re-enabling.

## HTML section (inside corp-officers card)

```html
    <h4 style="margin-top:1rem;">Corporation Members</h4>
    <p style="color:var(--muted);font-size:0.85rem;">All current EVE corporation members, independently of website applications.</p>
    <details id="officers-roster-details">
      <summary style="cursor:pointer;font-weight:600;">EVE Corporation Roster (<span id="officers-roster-count">0</span>)</summary>
      <div id="officers-roster"></div>
    </details>
    <details id="officers-unknown-details" style="margin-top:1rem;">
      <summary style="cursor:pointer;font-weight:600;">Unknown Status (<span id="officers-unknown-count">0</span>)</summary>
      <div id="officers-unknown"></div>
    </details>
```

## Browser JS (inside loadCorpOfficers, after reading data)

```js
    const roster = data.roster || [];
    const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;
    const lastActivity = member => Math.max(
      member.logon_date ? Date.parse(member.logon_date) || 0 : 0,
      member.logoff_date ? Date.parse(member.logoff_date) || 0 : 0
    );
    const unknown = roster.filter(member => lastActivity(member) < cutoff);
    const known = roster.filter(member => lastActivity(member) >= cutoff);
    const online = member => !!member.logon_date &&
      Date.parse(member.logon_date) > (member.logoff_date ? Date.parse(member.logoff_date) : 0);
    const alphabetical = (a, b) => a.name.localeCompare(b.name);
    known.sort((a,b) => Number(online(b)) - Number(online(a)) || alphabetical(a,b));
    unknown.sort(alphabetical);
    document.getElementById("officers-roster-count").textContent = known.length;
    document.getElementById("officers-unknown-count").textContent = unknown.length;
    const renderRoster = (members, target) => {
      const element = document.getElementById(target);
      element.innerHTML = "";
      if (data.roster_error) {
        element.innerHTML = '<p style="color:#ffb4b4;">' + escapeHtml(data.roster_error) + '</p>';
        return;
      }
      if (!members.length) {
        element.innerHTML = '<p style="color:var(--muted);">No members in this category.</p>';
        return;
      }
      let page = 0;
      const grid = document.createElement("div");
      grid.style.cssText = "display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:0.9rem;margin-top:0.7rem;";
      const controls = document.createElement("div");
      controls.style.cssText = "display:flex;align-items:center;gap:0.6rem;margin-top:0.8rem;";
      const previous = document.createElement("button");
      previous.className = "btn btn-outline";
      previous.textContent = "Previous 10";
      const next = document.createElement("button");
      next.className = "btn btn-outline";
      next.textContent = "Next 10";
      const indicator = document.createElement("span");
      indicator.style.fontSize = "0.85rem";
      const draw = () => {
        grid.innerHTML = members.slice(page * 10, (page + 1) * 10).map(member => {
          const status = target === "officers-unknown" ? "Unknown" : online(member) ? "Online" : "Offline";
          return '<button type="button" class="member-info-card" data-member-id="' + encodeURIComponent(member.character_id) + '" style="width:100%;cursor:pointer;background:transparent;color:inherit;text-align:center;border:1px solid var(--border);border-radius:7px;padding:0.65rem;">' +
            '<img src="https://images.evetech.net/characters/' + encodeURIComponent(member.character_id) + '/portrait?size=128" alt="' + escapeHtml(member.name) + '" loading="lazy" style="width:96px;height:96px;max-width:100%;border-radius:6px;display:block;margin:0 auto 0.45rem;">' +
            '<div style="font-weight:600;font-size:0.9rem;overflow-wrap:anywhere;">' + escapeHtml(member.name) + '</div>' +
            '<div style="font-size:0.75rem;color:var(--muted);">' + status + '</div></button>';
        }).join("");
        grid.querySelectorAll(".member-info-card").forEach(card => card.addEventListener("click", () => showMemberInfo(card.dataset.memberId)));
        previous.disabled = page === 0;
        next.disabled = (page + 1) * 10 >= members.length;
        indicator.textContent = (page * 10 + 1) + "–" + Math.min((page + 1) * 10, members.length) + " of " + members.length;
        controls.style.display = members.length > 10 ? "flex" : "none";
      };
      previous.addEventListener("click", () => { if (page > 0) { page--; draw(); } });
      next.addEventListener("click", () => { if ((page + 1) * 10 < members.length) { page++; draw(); } });
      controls.append(previous, indicator, next);
      element.append(grid, controls);
      draw();
    };
    renderRoster(known, "officers-roster");
    renderRoster(unknown, "officers-unknown");
```

## Worker JS (inside GET /corp-officers, before Response.json)

```js
        // The EVE corporation roster is independent of website applications.
        let roster = [];
        let roster_error = null;
        try {
          const membershipResponse = await fetch("https://esi.evetech.net/latest/corporations/" + corporationId + "/members/?datasource=tranquility", {
            headers: { Authorization: "Bearer " + tokenFrom(request) }
          });
          if (!membershipResponse.ok) {
            roster_error = membershipResponse.status === 403
              ? "EVE denied corporation membership access. Sign in again with a corporation Director character and approve the membership scope."
              : "EVE membership roster unavailable (HTTP " + membershipResponse.status + ").";
          } else {
            const ids = await membershipResponse.json();
            if (!Array.isArray(ids)) throw new Error("Invalid corporation roster response");
            const trackingResponse = await fetch("https://esi.evetech.net/latest/corporations/" + corporationId + "/membertracking/?datasource=tranquility", {
              headers: { Authorization: "Bearer " + tokenFrom(request) }
            });
            if (!trackingResponse.ok) {
              roster_error = "Online status unavailable (HTTP " + trackingResponse.status + "). A Director must authorize corporation member tracking.";
            }
            const tracking = trackingResponse.ok ? await trackingResponse.json() : [];
            const trackingById = new Map(Array.isArray(tracking) ? tracking.map(entry => [entry.character_id, entry]) : []);
            roster = (await Promise.all(ids.map(async id => {
              try {
                const response = await fetch("https://esi.evetech.net/latest/characters/" + id + "/?datasource=tranquility");
                if (!response.ok) return { character_id: id, name: String(id), ...trackingById.get(id) };
                const character = await response.json();
                return { character_id: id, name: character.name || String(id), ...trackingById.get(id) };
              } catch { return { character_id: id, name: String(id) }; }
            }))).sort((a, b) => a.name.localeCompare(b.name));
          }
        } catch (error) { roster_error = "Could not retrieve EVE corporation roster: " + String(error); }

```
