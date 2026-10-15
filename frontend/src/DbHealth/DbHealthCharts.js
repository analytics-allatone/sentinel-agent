import React from "react";

/**
 * The two chart forms this page needs.
 *
 * Both are drawn from the same parts as the meters above them — a track, a
 * fill, a token colour — so a page that is already a column of bars does not
 * suddenly acquire a second visual language halfway down. One hue throughout:
 * these are magnitudes, not identities, and a ranking painted in eight colours
 * invites the reader to look for a meaning the colours do not carry.
 *
 * Values are labelled on the bar itself. The tooltip carries what will not fit
 * — the 400-character SQL text — and never the value, which must stay readable
 * without a mouse.
 */

/** A ranking: label, bar, value at the tip. */
export function RankedBars({ items, caption }) {
  if (!items || items.length === 0) return null;

  return (
    <div className="dbh-rank">
      {caption && <p className="dbh-rank-caption">{caption}</p>}

      <ol className="dbh-rank-list">
        {items.map((item, i) => (
          <li className="dbh-rank-row" key={`${item.label}-${i}`} title={item.title || undefined}>
            <div className="dbh-rank-head">
              <span className="dbh-rank-label">{item.label}</span>
              <span className="dbh-rank-value">{item.display}</span>
            </div>

            <div
              className="dbh-rank-track"
              role="img"
              aria-label={`${item.label}: ${item.display}${item.sub ? `, ${item.sub}` : ""}`}
            >
              {/* the leader keeps its full colour; the tail steps back so the
                  shape of the distribution is the first thing read */}
              <span
                className={`dbh-rank-fill ${i === 0 ? "dbh-rank-fill--lead" : ""}`}
                style={{ width: `${Math.max(1.5, item.share)}%` }}
              />
            </div>

            {item.sub && <span className="dbh-rank-sub">{item.sub}</span>}
          </li>
        ))}
      </ol>
    </div>
  );
}

/**
 * Archive log volume, one column per day that produced any.
 *
 * The days are the days the database actually archived on, so they are labelled
 * individually rather than placed on a continuous axis — spacing them evenly
 * would draw a week that did not happen.
 */
export function DayColumns({ points, caption }) {
  if (!points || points.length === 0) return null;

  return (
    <div className="dbh-days">
      {caption && <p className="dbh-rank-caption">{caption}</p>}

      <ol className="dbh-days-plot">
        {points.map((p) => (
          <li className="dbh-day" key={p.day}>
            <span className="dbh-day-value">{p.mb} MB</span>

            <div
              className="dbh-day-track"
              role="img"
              aria-label={`${p.day}: ${p.mb} megabytes across ${p.archives} archive logs`}
            >
              <span className="dbh-day-fill" style={{ height: `${Math.max(2, p.share)}%` }} />
            </div>

            <span className="dbh-day-label">
              {String(p.day).slice(5)}
              {p.name && <span className="dbh-day-name">{p.name.toLowerCase()}</span>}
            </span>

            <span className="dbh-day-count">
              {p.archives} log{p.archives === 1 ? "" : "s"}
            </span>
          </li>
        ))}
      </ol>
    </div>
  );
}
