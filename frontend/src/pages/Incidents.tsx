import {
  AlertTriangle,
  CheckCircle2,
  ClipboardList,
  FileText,
  RefreshCw,
  Search,
  ShieldAlert,
} from "lucide-react";
import {
  useCallback,
  useEffect,
  useState,
} from "react";
import type {
  FormEvent,
} from "react";

import {
  addIncidentNote,
  createIncident,
  getIncidents,
  updateIncident,
  type Incident,
  type IncidentPriority,
  type IncidentStatus,
} from "../api/incidents";

import "./Incidents.css";

const priorities: IncidentPriority[] = [
  "LOW",
  "MEDIUM",
  "HIGH",
  "CRITICAL",
];

const statuses: IncidentStatus[] = [
  "OPEN",
  "IN_PROGRESS",
  "RESOLVED",
  "CLOSED",
];

function formatDate(value: string | null): string {
  if (!value) {
    return "—";
  }

  return new Date(value).toLocaleString();
}

function readableStatus(value: string): string {
  return value.replaceAll("_", " ");
}

function Incidents() {
  const [incidents, setIncidents] =
    useState<Incident[]>([]);

  const [selectedIncident, setSelectedIncident] =
    useState<Incident | null>(null);

  const [loading, setLoading] =
    useState(true);

  const [saving, setSaving] =
    useState(false);

  const [error, setError] =
    useState<string | null>(null);

  const [success, setSuccess] =
    useState<string | null>(null);

  const [search, setSearch] =
    useState("");

  const [statusFilter, setStatusFilter] =
    useState<IncidentStatus | "">("");

  const [priorityFilter, setPriorityFilter] =
    useState<IncidentPriority | "">("");

  const [title, setTitle] =
    useState("");

  const [description, setDescription] =
    useState("");

  const [priority, setPriority] =
    useState<IncidentPriority>("MEDIUM");

  const [note, setNote] =
    useState("");

  const loadIncidents = useCallback(
    async () => {
      setLoading(true);
      setError(null);

      try {
        const data = await getIncidents({
          limit: 100,
          search: search.trim() || undefined,
          status: statusFilter || undefined,
          priority: priorityFilter || undefined,
        });

        setIncidents(data);

        setSelectedIncident((current) => {
          if (!current) {
            return data[0] ?? null;
          }

          return (
            data.find(
              (item) => item.id === current.id,
            )
            ?? data[0]
            ?? null
          );
        });
      } catch {
        setError(
          "Unable to load incidents.",
        );
      } finally {
        setLoading(false);
      }
    },
    [
      priorityFilter,
      search,
      statusFilter,
    ],
  );

  useEffect(() => {
    const timeoutId = window.setTimeout(() => {
      void loadIncidents();
    }, 0);

    return () => {
      window.clearTimeout(timeoutId);
    };
  }, [loadIncidents]);

  async function handleCreate(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();

    if (
      title.trim().length < 3
      || !description.trim()
    ) {
      setError(
        "Enter a title and description.",
      );
      return;
    }

    setSaving(true);
    setError(null);
    setSuccess(null);

    try {
      const created = await createIncident({
        title: title.trim(),
        description: description.trim(),
        priority,
      });

      setTitle("");
      setDescription("");
      setPriority("MEDIUM");

      setSuccess(
        `Incident #${created.id} created.`,
      );

      await loadIncidents();

      setSelectedIncident(created);
    } catch {
      setError(
        "Unable to create the incident.",
      );
    } finally {
      setSaving(false);
    }
  }

  async function handleStatusChange(
    status: IncidentStatus,
  ) {
    if (!selectedIncident) {
      return;
    }

    setSaving(true);
    setError(null);
    setSuccess(null);

    try {
      const updated = await updateIncident(
        selectedIncident.id,
        {
          status,
        },
      );

      setSelectedIncident(updated);

      setIncidents((current) =>
        current.map((incident) =>
          incident.id === updated.id
            ? updated
            : incident,
        ),
      );

      setSuccess(
        `Incident #${updated.id} status updated.`,
      );
    } catch {
      setError(
        "Unable to update incident status.",
      );
    } finally {
      setSaving(false);
    }
  }

  async function handleAddNote(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();

    if (
      !selectedIncident
      || !note.trim()
    ) {
      return;
    }

    setSaving(true);
    setError(null);
    setSuccess(null);

    try {
      await addIncidentNote(
        selectedIncident.id,
        note.trim(),
      );

      setNote("");

      const refreshed =
        await getIncidents({
          limit: 100,
        });

      setIncidents(refreshed);

      setSelectedIncident(
        refreshed.find(
          (incident) =>
            incident.id
            === selectedIncident.id,
        ) ?? null,
      );

      setSuccess("Incident note added.");
    } catch {
      setError(
        "Unable to add the incident note.",
      );
    } finally {
      setSaving(false);
    }
  }

  const openCount = incidents.filter(
    (incident) =>
      incident.status === "OPEN"
      || incident.status === "IN_PROGRESS",
  ).length;

  const criticalCount = incidents.filter(
    (incident) =>
      incident.priority === "CRITICAL",
  ).length;

  return (
    <div className="incidents-page">
      <section className="incidents-header">
        <div>
          <span className="incidents-kicker">
            RESPONSE
          </span>

          <h1>
            Incident Response
          </h1>

          <p>
            Manage security cases, linked threat
            intelligence, response status, and
            investigation notes.
          </p>
        </div>

        <button
          type="button"
          className="incidents-refresh"
          onClick={() => void loadIncidents()}
          disabled={loading}
        >
          <RefreshCw
            size={17}
            aria-hidden="true"
          />
          Refresh
        </button>
      </section>

      <section className="incident-metrics">
        <article>
          <ClipboardList size={20} />
          <span>Total Cases</span>
          <strong>{incidents.length}</strong>
        </article>

        <article>
          <ShieldAlert size={20} />
          <span>Active</span>
          <strong>{openCount}</strong>
        </article>

        <article>
          <AlertTriangle size={20} />
          <span>Critical</span>
          <strong>{criticalCount}</strong>
        </article>

        <article>
          <CheckCircle2 size={20} />
          <span>Resolved</span>
          <strong>
            {
              incidents.filter(
                (incident) =>
                  incident.status === "RESOLVED"
                  || incident.status === "CLOSED",
              ).length
            }
          </strong>
        </article>
      </section>

      {(error || success) && (
        <div
          className={
            error
              ? "incident-message error"
              : "incident-message success"
          }
          role="status"
        >
          {error ?? success}
        </div>
      )}

      <section className="incident-create-card">
        <div className="incident-section-heading">
          <div>
            <span>NEW CASE</span>
            <h2>Create Incident</h2>
          </div>
        </div>

        <form
          className="incident-create-form"
          onSubmit={handleCreate}
        >
          <input
            type="text"
            minLength={3}
            maxLength={255}
            placeholder="Incident title"
            value={title}
            onChange={(event) =>
              setTitle(event.target.value)
            }
          />

          <select
            value={priority}
            onChange={(event) =>
              setPriority(
                event.target.value as IncidentPriority,
              )
            }
          >
            {priorities.map((item) => (
              <option
                key={item}
                value={item}
              >
                {item}
              </option>
            ))}
          </select>

          <textarea
            placeholder="Describe the security incident..."
            value={description}
            onChange={(event) =>
              setDescription(
                event.target.value,
              )
            }
          />

          <button
            type="submit"
            disabled={saving}
          >
            {saving
              ? "Creating..."
              : "Create Incident"}
          </button>
        </form>
      </section>

      <section className="incident-workspace">
        <div className="incident-list-card">
          <div className="incident-section-heading">
            <div>
              <span>CASES</span>
              <h2>Incident Queue</h2>
            </div>
          </div>

          <div className="incident-filters">
            <div className="incident-search">
              <Search
                size={17}
                aria-hidden="true"
              />

              <input
                type="search"
                placeholder="Search incidents"
                value={search}
                onChange={(event) =>
                  setSearch(
                    event.target.value,
                  )
                }
              />
            </div>

            <select
              value={statusFilter}
              onChange={(event) =>
                setStatusFilter(
                  event.target.value as IncidentStatus | "",
                )
              }
            >
              <option value="">
                All statuses
              </option>

              {statuses.map((item) => (
                <option
                  key={item}
                  value={item}
                >
                  {readableStatus(item)}
                </option>
              ))}
            </select>

            <select
              value={priorityFilter}
              onChange={(event) =>
                setPriorityFilter(
                  event.target.value as IncidentPriority | "",
                )
              }
            >
              <option value="">
                All priorities
              </option>

              {priorities.map((item) => (
                <option
                  key={item}
                  value={item}
                >
                  {item}
                </option>
              ))}
            </select>
          </div>

          {loading ? (
            <div className="incident-empty">
              Loading incidents...
            </div>
          ) : incidents.length === 0 ? (
            <div className="incident-empty">
              No incidents match the current filters.
            </div>
          ) : (
            <div className="incident-list">
              {incidents.map((incident) => (
                <button
                  key={incident.id}
                  type="button"
                  className={
                    selectedIncident?.id
                      === incident.id
                      ? "incident-row selected"
                      : "incident-row"
                  }
                  onClick={() =>
                    setSelectedIncident(
                      incident,
                    )
                  }
                >
                  <div>
                    <span>
                      #{incident.id}
                    </span>

                    <strong>
                      {incident.title}
                    </strong>
                  </div>

                  <div className="incident-row-meta">
                    <span
                      className={`incident-priority priority-${incident.priority.toLowerCase()}`}
                    >
                      {incident.priority}
                    </span>

                    <span>
                      {
                        readableStatus(
                          incident.status,
                        )
                      }
                    </span>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>

        <div className="incident-detail-card">
          {!selectedIncident ? (
            <div className="incident-empty detail">
              <FileText
                size={30}
                aria-hidden="true"
              />

              Select an incident to review
              case details.
            </div>
          ) : (
            <>
              <div className="incident-detail-heading">
                <div>
                  <span>
                    INCIDENT #
                    {selectedIncident.id}
                  </span>

                  <h2>
                    {selectedIncident.title}
                  </h2>
                </div>

                <span
                  className={`incident-priority priority-${selectedIncident.priority.toLowerCase()}`}
                >
                  {selectedIncident.priority}
                </span>
              </div>

              <p className="incident-description">
                {selectedIncident.description}
              </p>

              <div className="incident-detail-grid">
                <div>
                  <span>Status</span>

                  <select
                    value={
                      selectedIncident.status
                    }
                    disabled={saving}
                    onChange={(event) =>
                      void handleStatusChange(
                        event.target.value as IncidentStatus,
                      )
                    }
                  >
                    {statuses.map((item) => (
                      <option
                        key={item}
                        value={item}
                      >
                        {
                          readableStatus(
                            item,
                          )
                        }
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <span>Created</span>
                  <strong>
                    {
                      formatDate(
                        selectedIncident
                          .created_at,
                      )
                    }
                  </strong>
                </div>

                <div>
                  <span>Assigned To</span>
                  <strong>
                    {
                      selectedIncident
                        .assigned_to
                      ?? "Unassigned"
                    }
                  </strong>
                </div>

                <div>
                  <span>Resolved</span>
                  <strong>
                    {
                      formatDate(
                        selectedIncident
                          .resolved_at,
                      )
                    }
                  </strong>
                </div>
              </div>

              <div className="incident-linked-section">
                <h3>Linked Intelligence</h3>

                <div className="incident-linked-grid">
                  <div>
                    <span>Indicators</span>
                    <strong>
                      {
                        selectedIncident
                          .indicators.length
                      }
                    </strong>
                  </div>

                  <div>
                    <span>Alerts</span>
                    <strong>
                      {
                        selectedIncident
                          .alerts.length
                      }
                    </strong>
                  </div>
                </div>

                {
                  selectedIncident
                    .indicators.length > 0
                  && (
                    <div className="incident-linked-items">
                      {
                        selectedIncident
                          .indicators.map(
                            (indicator) => (
                              <span
                                key={
                                  indicator.id
                                }
                              >
                                #
                                {indicator.id}
                                {" "}
                                {indicator.value}
                              </span>
                            ),
                          )
                      }
                    </div>
                  )
                }
              </div>

              <div className="incident-notes-section">
                <h3>Case Notes</h3>

                {selectedIncident.notes.length
                  === 0 ? (
                    <p className="incident-muted">
                      No notes have been added.
                    </p>
                  ) : (
                    <div className="incident-notes">
                      {
                        selectedIncident.notes.map(
                          (item) => (
                            <article
                              key={item.id}
                            >
                              <p>
                                {item.content}
                              </p>

                              <span>
                                User #
                                {item.author_id}
                                {" • "}
                                {
                                  formatDate(
                                    item.created_at,
                                  )
                                }
                              </span>
                            </article>
                          ),
                        )
                      }
                    </div>
                  )}

                <form
                  className="incident-note-form"
                  onSubmit={handleAddNote}
                >
                  <textarea
                    maxLength={5000}
                    placeholder="Add investigation or response note..."
                    value={note}
                    onChange={(event) =>
                      setNote(
                        event.target.value,
                      )
                    }
                  />

                  <button
                    type="submit"
                    disabled={
                      saving
                      || !note.trim()
                    }
                  >
                    Add Note
                  </button>
                </form>
              </div>
            </>
          )}
        </div>
      </section>
    </div>
  );
}

export default Incidents;
